"""Twilio SID boundary regressions; all token-shaped values are synthetic."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest

from test_scan import scan


SID = "SK" + "aB3dE6f9" * 4
SUMMARY = "Twilio API key SID detected"


class TwilioBoundaryTests(unittest.TestCase):
    def collect(self, text):
        findings = []

        def add(category, severity, file, line, **details):
            findings.append(dict(category=category, severity=severity, file=file,
                                 line=line, **details))

        with tempfile.TemporaryDirectory() as root:
            path = Path(root, "settings.txt")
            path.write_text(text, encoding="utf-8")
            scan.scan_secrets(root, [str(path)], add)
        return findings

    def test_unicode_identifier_neighbors_are_not_standalone_sids(self):
        for neighbor in ("é", "漢", "Ω", "١", "１"):
            for text in (neighbor + SID, SID + neighbor, neighbor + SID + neighbor):
                with self.subTest(neighbor=neighbor, text=text):
                    self.assertEqual(self.collect(text), [])

    def test_ascii_identifier_neighbors_remain_excluded(self):
        for neighbor in ("a", "Z", "0", "_"):
            for text in (neighbor + SID, SID + neighbor):
                with self.subTest(neighbor=neighbor, text=text):
                    self.assertEqual(self.collect(text), [])

    def test_standalone_and_delimited_sids_keep_location_severity_and_redaction(self):
        for left, right in (("", ""), ('"', '"'), ("'", "'"), ("(", ")"),
                            ("=", ","), (" ", "\t"), ("-", "-"),
                            ("«", "»"), ("😀", "😀")):
            with self.subTest(left=left, right=right):
                findings = self.collect(chr(10).join(("heading", left + SID + right)))
                self.assertEqual(len(findings), 1)
                self.assertEqual(findings[0], dict(
                    category="secret", severity="medium", file="settings.txt", line=2,
                    summary=SUMMARY, evidence=SID[:4] + "…"))
                self.assertNotIn(SID, json.dumps(findings))

    def test_body_still_requires_exactly_32_ascii_hex_characters(self):
        for value in (SID[:-1], SID + "a", SID[:-1] + "g", SID[:-1] + "é"):
            with self.subTest(value=value):
                self.assertEqual(self.collect(value), [])
        self.assertEqual(len(self.collect("SK" + "ABCDEF12" * 4)), 1)
        self.assertEqual(len(self.collect("SK" + "abcdef12" * 4)), 1)

    def test_embedded_candidate_does_not_hide_later_standalone_matches(self):
        findings = self.collect("é" + SID + " " + SID + "," + SID)
        self.assertEqual(len(findings), 2)
        self.assertTrue(all(f["summary"] == SUMMARY for f in findings))
        self.assertTrue(all(f["line"] == 1 for f in findings))

    def test_cli_medium_gate_rejects_only_standalone_candidate(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root, "settings.txt")
            for value, expected in (("é" + SID, 0), (SID + "漢", 0), (SID, 1)):
                with self.subTest(value=value):
                    path.write_text(value, encoding="utf-8")
                    stdout, stderr = io.StringIO(), io.StringIO()
                    with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                        result = scan.main(["scan.py", root, "--no-osv", "--fail-on", "medium"])
                    report = json.loads(stdout.getvalue())
                    self.assertEqual(result, expected)
                    self.assertEqual(len(report["findings"]), expected)
                    self.assertEqual(report["summary"]["secret_hits"], expected)
                    self.assertNotIn(SID, stdout.getvalue() + stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
