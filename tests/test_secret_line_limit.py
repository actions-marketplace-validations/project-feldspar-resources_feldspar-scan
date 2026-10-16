"""Pin the documented secret-line coverage limits with synthetic offline input."""
import json
from pathlib import Path
import tempfile
import unittest

from test_scan import scan


class SecretLineLimitTests(unittest.TestCase):
    LF = chr(10)
    CRLF = chr(13) + LF
    TOKEN = "npm_" + "A1b2C3" * 6
    VALUE = "synthetic-value-123456789"

    def collect(self, text):
        findings = []

        def add(category, severity, file, line, **details):
            findings.append(dict(category=category, severity=severity, file=file,
                                 line=line, **details))

        with tempfile.TemporaryDirectory() as root:
            path = Path(root, "settings.txt")
            path.write_bytes(text.encode("utf-8"))
            scan.scan_secrets(root, [str(path)], add)
        return findings

    def test_provider_and_generic_boundary_excludes_line_endings(self):
        cases = [(self.TOKEN, "npm access token detected", "high", "npm_…"),
                 ('password="' + self.VALUE + '"', "Hardcoded password assignment",
                  "medium", "synt…")]
        for content, summary, severity, evidence in cases:
            for ending in ("", self.LF, self.CRLF):
                with self.subTest(content=summary, ending=repr(ending)):
                    line = " " * (4000 - len(content)) + content
                    self.assertEqual(self.collect(line + ending), [dict(
                        category="secret", severity=severity, file="settings.txt",
                        line=1, summary=summary, evidence=evidence)])
                    self.assertEqual(self.collect(" " + line + ending), [])

    def test_limit_counts_unicode_characters_not_utf8_bytes(self):
        line = "界" * (4000 - len(self.TOKEN) - 1) + " " + self.TOKEN
        self.assertGreater(len(line.encode("utf-8")), 4000)
        self.assertEqual(len(self.collect(line)), 1)
        self.assertEqual(self.collect("界" + line), [])

    def test_scanning_resumes_after_skipped_line(self):
        long_line = self.TOKEN + " " * 4001
        findings = self.collect(long_line + self.CRLF * 2 + self.TOKEN)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["line"], 3)
        self.assertEqual(findings[0]["evidence"], "npm_…")
        self.assertNotIn(self.TOKEN, json.dumps(findings))

    def test_multiline_private_key_check_has_separate_line_coverage(self):
        # Synthetic base64-shaped text, not cryptographic key material.
        body = "Ab3D" * 1001
        text = ("-----BEGIN PRIVATE KEY-----" + self.LF
                + (body + self.LF) * 3 + "-----END PRIVATE KEY-----" + self.LF)
        findings = self.collect(text)
        self.assertEqual(findings, [dict(
            category="secret", severity="critical", file="settings.txt", line=1,
            summary="Multiline private key block detected", evidence="----…")])
        self.assertNotIn(body, json.dumps(findings))
