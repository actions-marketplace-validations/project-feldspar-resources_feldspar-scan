"""Configuration review workload counts retained findings per file."""
import contextlib
import copy
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from test_scan import scan


class ConfigReviewByFileTests(unittest.TestCase):
    def test_mixed_categories_repeats_missing_paths_and_order(self):
        findings = [
            {"id": "C1", "category": "config", "file": "z/Dockerfile", "severity": "low"},
            {"id": "C2", "category": "config", "file": "fixtures/Dockerfile", "severity": "high"},
            {"id": "C3", "category": "config", "file": "z/Dockerfile", "severity": "high"},
            {"id": "C4", "category": "config", "file": None},
            {"id": "C5", "category": "config", "file": ""},
            {"id": "C6", "category": "config"},
            {"id": "S1", "category": "secret", "file": "z/Dockerfile", "severity": "high"},
            {"id": "D1", "category": "dependency-vuln", "file": "requirements.txt"},
            {"id": "O1", "category": "other", "file": "other.txt"},
        ]
        original = copy.deepcopy(findings)
        with mock.patch.object(scan, "_secret_false_positive", return_value=(False, None)):
            per_id, summary = scan.triage_findings(findings)
        self.assertEqual(summary["config_review_by_file"],
                         {"fixtures/Dockerfile": 1, "z/Dockerfile": 2})
        self.assertEqual(list(summary["config_review_by_file"]),
                         ["fixtures/Dockerfile", "z/Dockerfile"])
        self.assertEqual(summary["config"], {"needs_review": 6})
        self.assertEqual(summary["config_files_needing_review"], 2)
        self.assertTrue(all(per_id[f"C{i}"] == {"action": "review"} for i in range(1, 7)))
        self.assertEqual(findings, original)

    def report(self, root, *options):
        output, errors = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors), \
                mock.patch.object(scan, "http_json", side_effect=AssertionError("offline only")):
            status = scan.main(["scan.py", str(root), "--no-osv", "--no-commit",
                                "--no-timestamp", *options])
        return status, json.loads(output.getvalue()), errors.getvalue()

    def test_cli_triage_summary_only_and_gates_preserve_raw_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "fixtures").mkdir()
            (root / "fixtures/Dockerfile").write_text(
                "FROM scratch" + chr(10) + "USER root" + chr(10) + "ENV TOKEN=x" + chr(10))
            (root / "Dockerfile").write_text("FROM scratch" + chr(10))
            for threshold, expected_status in (("high", 1), ("critical", 0)):
                with self.subTest(threshold=threshold):
                    baseline = self.report(root, "--fail-on", threshold)
                    result = self.report(root, "--fail-on", threshold, "--triage")
                    self.assertEqual(result[0], expected_status)
                    self.assertEqual(result[0], baseline[0])
                    self.assertEqual(result[2], baseline[2])
                    self.assertEqual(result[1]["triage_summary"]["config_review_by_file"],
                                     {"Dockerfile": 1, "fixtures/Dockerfile": 2})
                    raw = dict(result[1])
                    del raw["triage"]
                    del raw["triage_summary"]
                    self.assertEqual(raw, baseline[1])
                    compact = self.report(root, "--fail-on", threshold, "--triage",
                                          "--summary-only", "--compact", "--sort-keys")
                    expected = dict(result[1])
                    del expected["findings"]
                    del expected["triage"]
                    self.assertEqual(compact, (result[0], expected, result[2]))

    def test_limits_count_retained_findings_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "Dockerfile").write_text(
                "FROM scratch" + chr(10) + "USER root" + chr(10) + "ENV TOKEN=x" + chr(10))
            for limit_name in ("MAX_FINDINGS", "MAX_FINDINGS_PER_FILE"):
                with self.subTest(limit=limit_name), mock.patch.object(scan, limit_name, 1):
                    status, doc, _ = self.report(root, "--triage")
                    self.assertEqual(status, 0)
                    self.assertEqual(len(doc["findings"]), 1)
                    self.assertTrue(doc["summary"]["truncated"]["findings"])
                    self.assertEqual(doc["triage_summary"]["config_review_by_file"], {"Dockerfile": 1})

    def test_empty_and_nonconfig_only_have_empty_mapping(self):
        for findings in ([], [{"id": "D1", "category": "dependency-vuln", "file": "req.txt"}]):
            with self.subTest(findings=findings):
                self.assertEqual(scan.triage_findings(findings)[1]["config_review_by_file"], {})
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(self.report(Path(tmp), "--triage")[1]
                             ["triage_summary"]["config_review_by_file"], {})
