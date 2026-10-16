"""Offline coverage for the distinct-file workload of secret triage."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from test_scan import scan


class SecretReviewFileTests(unittest.TestCase):
    def test_counts_reviewable_secret_files_once(self):
        def finding(fid, category, path, evidence="synthetic"):
            return dict(id=fid, category=category, file=path, evidence=evidence)

        findings = [
            finding("a", "secret", "src/settings.py"),
            finding("b", "secret", "src/settings.py"),
            finding("c", "secret", "service/settings.py"),
            finding("d", "secret", "tests/settings.py"),
            finding("e", "secret", "src/example.py", "value (example-key?)"),
            finding("f", "config", "Dockerfile"),
            finding("g", "dependency-vuln", "requirements.txt"),
        ]
        per_id, summary = scan.triage_findings(findings)
        self.assertEqual(summary["secrets"], {
            "total": 5, "likely_false_positive": 2, "needs_review": 3,
        })
        self.assertEqual(summary["secret_files_needing_review"], 2)
        self.assertEqual(per_id["d"]["action"], "informational")
        self.assertEqual(per_id["e"]["action"], "informational")
        self.assertEqual(per_id["f"]["action"], "review")
        _, reversed_summary = scan.triage_findings(list(reversed(findings)))
        self.assertEqual(summary, reversed_summary)
        for subset in ([], findings[3:]):
            with self.subTest(subset=subset):
                _, summary = scan.triage_findings(subset)
                self.assertEqual(summary["secret_files_needing_review"], 0)

    def report(self, root, *options):
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(io.StringIO()):
            status = scan.main(["scan.py", str(root), "--no-osv", *options])
        return status, json.loads(stdout.getvalue())

    def test_cli_opt_in_preserves_raw_report_and_gate(self):
        with tempfile.TemporaryDirectory() as root:
            # Synthetic generic value only; no credential is used.
            Path(root, "settings.py").write_text('password="A1b2C3d4E5f6G7h8"' + chr(10))
            plain_status, plain = self.report(root, "--fail-on", "medium")
            triage_status, triaged = self.report(root, "--fail-on", "medium", "--triage")
        self.assertEqual(plain_status, 1)
        self.assertEqual(triage_status, plain_status)
        self.assertNotIn("triage_summary", plain)
        self.assertEqual(triaged["triage_summary"]["secret_files_needing_review"], 1)
        for field in ("findings", "manifest_hash", "summary"):
            self.assertEqual(triaged[field], plain[field])

    def test_counts_only_files_represented_after_limits(self):
        with tempfile.TemporaryDirectory() as root:
            for name in ("a.py", "b.py"):
                Path(root, name).write_text(('password="A1b2C3d4E5f6G7h8"' + chr(10)) * 2)
            for limit, flag, expected in (("MAX_FINDINGS", "findings", 1),
                                          ("MAX_FILES", "files", 1),
                                          ("MAX_FINDINGS_PER_FILE", "findings", 2)):
                with self.subTest(limit=limit), mock.patch.object(scan, limit, 1):
                    _, report = self.report(root, "--triage")
                    self.assertTrue(report["summary"]["truncated"][flag])
                    self.assertEqual(
                        report["triage_summary"]["secret_files_needing_review"], expected)
