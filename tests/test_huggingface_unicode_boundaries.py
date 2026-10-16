"""Hugging Face detector regressions using synthetic values only."""
import tempfile
import unittest
from pathlib import Path

from test_scan import _collect, scan


class HuggingFaceUnicodeBoundaryTests(unittest.TestCase):
    value = "hf_" + ("aB3dE6fG9" * 4)[:34]

    def findings(self, text):
        with tempfile.TemporaryDirectory() as root:
            Path(root, "settings.txt").write_text(text, encoding="utf-8")
            return _collect(root, scan.scan_secrets)

    def test_unicode_identifier_neighbors_exclude_partial_matches(self):
        for char in ("é", "密", "Ж", "١", "９"):
            for text in (char + self.value, self.value + char):
                with self.subTest(char=char, text=text):
                    self.assertEqual(self.findings(text), [])

    def test_standalone_tokens_preserve_metadata_and_redaction(self):
        for template in ("{}", 'value="{}"', "Bearer {}", "({})", "{}.",
                         "密: {}", "{} — fin", "-{}-", "\u00a0{}\u00a0"):
            with self.subTest(template=template):
                hits = self.findings(("heading" + chr(10)) + template.format(self.value))
                self.assertEqual(hits, [dict(
                    category="secret", severity="medium", file="settings.txt", line=2,
                    summary="Hugging Face token detected", evidence="hf_a…")])
                self.assertNotIn(self.value, str(hits))

    def test_ascii_boundaries_and_variable_length_are_preserved(self):
        for char in ("a", "Z", "0", "_"):
            with self.subTest(prefix=char):
                self.assertEqual(self.findings(char + self.value), [])
        self.assertEqual(self.findings(self.value + "_"), [])
        for size in (33, 34, 35, 68):
            with self.subTest(size=size):
                value = "hf_" + ("aB3dE6fG9" * 8)[:size]
                hits = self.findings(value)
                self.assertEqual(len(hits), int(size >= 34))
                if hits:
                    self.assertEqual(hits[0]["severity"], "medium")

    def test_later_token_and_severity_hints_are_preserved(self):
        for embedded in ("密" + self.value, self.value + "é"):
            with self.subTest(embedded=embedded):
                hits = self.findings(embedded + ' value="' + self.value + '"')
                self.assertEqual(len(hits), 1)
                self.assertEqual(hits[0]["severity"], "medium")
                self.assertEqual(hits[0]["evidence"], "hf_a…")
        for text, hint in (("hf_" + "x" * 34, "example-key?"),
                           ('placeholder="' + self.value + '"', "form-placeholder?")):
            with self.subTest(hint=hint):
                hits = self.findings(text)
                self.assertEqual(len(hits), 1)
                self.assertEqual(hits[0]["severity"], "low")
                self.assertIn("(" + hint + ")", hits[0]["evidence"])
