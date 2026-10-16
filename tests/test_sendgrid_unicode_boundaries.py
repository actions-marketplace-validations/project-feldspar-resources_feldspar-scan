"""SendGrid detector boundaries, using synthetic strings only."""
import tempfile
import unittest
from pathlib import Path

from test_scan import _collect, scan


class SendGridUnicodeBoundaryTests(unittest.TestCase):
    first = ("aB3_dE6-fG9" * 2)[:22]
    second = ("hI4_jK7-lM2" * 4)[:43]
    value = "SG." + first + "." + second

    def findings(self, text):
        with tempfile.TemporaryDirectory() as root:
            Path(root, "settings.txt").write_text(text, encoding="utf-8")
            return _collect(root, scan.scan_secrets)

    def test_unicode_identifier_neighbors_exclude_fragments(self):
        for char in ("é", "密", "Ж", "١", "９"):
            for text in (char + self.value, self.value + char):
                with self.subTest(char=char, text=text):
                    self.assertEqual(self.findings(text), [])

    def test_standalone_matches_keep_metadata_and_redaction(self):
        for template in ("{}", 'value="{}"', "Bearer {}", "({})", "{}.",
                         "密: {}", "{} — fin", "\u00a0{}\u00a0"):
            with self.subTest(template=template):
                hits = self.findings("heading" + chr(10) + template.format(self.value))
                self.assertEqual(hits, [dict(
                    category="secret", severity="high", file="settings.txt", line=2,
                    summary="SendGrid API key detected", evidence="SG.a…")])
                self.assertNotIn(self.value, str(hits))

    def test_ascii_boundaries_and_fixed_body_lengths_are_preserved(self):
        for char in ("a", "Z", "0", "_", "-"):
            for text in (char + self.value, self.value + char):
                with self.subTest(char=char, text=text):
                    self.assertEqual(self.findings(text), [])
        for first, second in ((self.first[:-1], self.second),
                              (self.first + "a", self.second),
                              (self.first, self.second[:-1]),
                              (self.first, self.second + "a"),
                              ("é" + self.first[1:], self.second),
                              (self.first, "密" + self.second[1:])):
            with self.subTest(first=first, second=second):
                self.assertEqual(self.findings("SG." + first + "." + second), [])

    def test_later_matches_and_severity_hints_are_preserved(self):
        for embedded in ("密" + self.value, self.value + "é"):
            with self.subTest(embedded=embedded):
                hits = self.findings(embedded + ' value="' + self.value + '"')
                self.assertEqual(len(hits), 1)
                self.assertEqual(hits[0]["severity"], "high")
                self.assertEqual(hits[0]["evidence"], "SG.a…")
        for text, hint in (("SG." + "x" * 22 + "." + "x" * 43, "example-key?"),
                           ('placeholder="' + self.value + '"', "form-placeholder?")):
            with self.subTest(hint=hint):
                hits = self.findings(text)
                self.assertEqual(len(hits), 1)
                self.assertEqual(hits[0]["severity"], "low")
                self.assertIn("(" + hint + ")", hits[0]["evidence"])
