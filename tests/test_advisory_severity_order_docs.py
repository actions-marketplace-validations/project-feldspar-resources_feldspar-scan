"""Offline examples of documented advisory severity precedence and gates."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from test_scan import scan


class AdvisorySeverityOrderDocumentationTests(unittest.TestCase):
    def test_database_severity_precedes_numeric_scores(self):
        for label, expected in (("low", "low"), ("mEdIuM", "medium"),
                                ("MODERATE", "medium"), ("HIGH", "high"),
                                ("critical", "critical")):
            advisory = {"database_specific": {"severity": label},
                        "severity": [{"score": "9.8"}, {"score": "1.0"}]}
            with self.subTest(label=label), mock.patch.object(
                    scan, "http_json", return_value=advisory) as http:
                self.assertEqual(scan.vuln_details("SYNTHETIC-ORDER", {})["severity"],
                                 expected)
                http.assert_called_once_with(scan.OSV_VULN + "SYNTHETIC-ORDER")

    def test_first_supported_numeric_score_wins(self):
        vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        for scores, expected in ((("4.0", "9.8"), "medium"),
                                 (("9.8", "4.0"), "critical"),
                                 ((vector, "bad", "4.0", "9.8"), "medium"),
                                 ((vector, "bad"), "unknown")):
            advisory = {"database_specific": {"severity": "unrecognized"},
                        "severity": [{"score": s} for s in scores]}
            with self.subTest(scores=scores), mock.patch.object(
                    scan, "http_json", return_value=advisory):
                self.assertEqual(scan.vuln_details("SYNTHETIC-ORDER", {})["severity"],
                                 expected)

    def test_report_gate_and_worst_severity_across_advisories(self):
        low_first = {"severity": [{"score": "4.0"}, {"score": "9.8"}]}
        high_first = {"severity": [{"score": "9.8"}, {"score": "4.0"}]}
        cases = (([low_first], "medium", 0), ([high_first], "critical", 1),
                 ([low_first, high_first], "critical", 1),
                 ([high_first, low_first], "critical", 1))
        with tempfile.TemporaryDirectory() as root:
            Path(root, "requirements.txt").write_text("synthetic-package==1.2.3" + chr(10))
            for advisories, expected, exit_code in cases:
                ids = ["SYNTHETIC-ORDER-%d" % i for i in range(len(advisories))]
                output = io.StringIO()
                with self.subTest(expected=expected, advisories=advisories), \
                        mock.patch.object(scan, "query_osv", return_value={
                            ("PyPI", "synthetic-package", "1.2.3"): ids}), \
                        mock.patch.object(scan, "http_json", side_effect=advisories) as http, \
                        mock.patch.object(scan, "git_head", return_value=None), \
                        contextlib.redirect_stdout(output), \
                        contextlib.redirect_stderr(io.StringIO()):
                    status = scan.main(["scan.py", root, "--fail-on", "high"])
                self.assertEqual(status, exit_code)
                self.assertEqual(http.call_count, len(advisories))
                report = json.loads(output.getvalue())
                self.assertNotIn("errors", report)
                self.assertEqual(len(report["findings"]), 1)
                self.assertEqual(report["findings"][0]["severity"], expected)
                self.assertEqual(report["findings"][0]["vuln_ids"], ids)
                self.assertEqual(report["summary"]["by_severity"][expected], 1)
