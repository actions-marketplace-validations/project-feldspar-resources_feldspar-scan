"""Triage counts dependency findings, including when advisories overlap."""
import contextlib
import copy
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from test_scan import scan


class TriageCountLabelTests(unittest.TestCase):
    def test_multiple_and_shared_advisories_count_findings(self):
        findings = [
            {"id": "F-001", "category": "dependency-vuln", "file": "requirements.txt",
             "package": "alpha", "vuln_ids": ["TEST-1", "TEST-2"], "fixed_in": ["2.0"]},
            {"id": "F-002", "category": "dependency-vuln", "file": "requirements.txt",
             "package": "beta", "vuln_ids": ["TEST-1", "TEST-3"], "fixed_in": ["3.0"]},
            {"id": "F-003", "category": "dependency-vuln", "file": "requirements.txt",
             "package": "gamma", "vuln_ids": ["TEST-4", "TEST-5"], "fixed_in": []},
        ]
        original = copy.deepcopy(findings)
        per_id, summary = scan.triage_findings(findings)
        self.assertEqual(findings, original)
        self.assertEqual(summary["dependency"], {
            "upgradeable": 2, "monitor_only": 1, "in_scaffold_lockfiles": 0})
        self.assertEqual(summary["headline"],
                         "2 dependency finding(s) fixable by upgrade; "
                         "1 dependency finding(s) with no patch yet (monitor/mitigate)")
        self.assertEqual([per_id[f["id"]]["action"] for f in findings],
                         ["upgrade", "upgrade", "monitor"])

    def test_empty_headline_is_unchanged(self):
        self.assertEqual(scan.triage_findings([])[1]["headline"],
                         "no actionable findings after triage")

    def test_cli_report_counts_one_finding_for_two_advisories(self):
        with tempfile.TemporaryDirectory() as root:
            Path(root, "requirements.txt").write_text("demo-package==1.0" + chr(10))
            def report(triage):
                output = io.StringIO()
                with mock.patch.object(scan, "query_osv", return_value={
                        ("PyPI", "demo-package", "1.0"): ["TEST-1", "TEST-2"]}), \
                        mock.patch.object(scan, "vuln_details", return_value={
                            "severity": "high", "fixed_in": ["2.0"], "summary": "Synthetic"}), \
                        contextlib.redirect_stdout(output), contextlib.redirect_stderr(io.StringIO()):
                    code = scan.main(["scan.py", root, "--fail-on", "high"] +
                                     (["--triage"] if triage else []))
                self.assertEqual(code, 1)
                return json.loads(output.getvalue())

            plain, triaged = report(False), report(True)
        self.assertEqual(plain["findings"], triaged["findings"])
        self.assertEqual(plain["manifest_hash"], triaged["manifest_hash"])
        self.assertEqual(len(triaged["findings"]), 1)
        self.assertEqual(triaged["findings"][0]["vuln_ids"], ["TEST-1", "TEST-2"])
        self.assertEqual(triaged["triage_summary"]["headline"],
                         "1 dependency finding(s) fixable by upgrade")
