"""Telegram word-boundary regressions using synthetic, non-live candidates."""
import tempfile
import unittest
from pathlib import Path

from test_scan import _collect, scan


class TelegramUnicodeBoundaryTests(unittest.TestCase):
    value = "123456789:" + "Ab3_De7-Fg9" * 3 + "Hi"

    def findings(self, text):
        with tempfile.TemporaryDirectory() as root:
            Path(root, "settings.txt").write_text(text, encoding="utf-8")
            return _collect(root, scan.scan_secrets)

    def test_unicode_word_neighbors_exclude_partial_tokens(self):
        for char in ("é", "中", "Ω", "١", "９"):
            for text in (char + self.value, self.value + char):
                with self.subTest(char=char, text=text):
                    self.assertEqual(self.findings(text), [])

    def test_delimiters_preserve_metadata_and_redaction(self):
        for left, right in (("", ""), ('"', '"'), (" ", " "),
                            ("（", "）"), ("—", "。"), ("/", "?")):
            with self.subTest(left=left, right=right):
                hits = self.findings("heading" + chr(10) + left + self.value + right)
                self.assertEqual(len(hits), 1)
                hit = hits[0]
                self.assertEqual(hit["summary"], "Telegram bot token detected")
                self.assertEqual(hit["severity"], "high")
                self.assertEqual(hit["category"], "secret")
                self.assertEqual(hit["file"], "settings.txt")
                self.assertEqual(hit["line"], 2)
                self.assertEqual(hit["evidence"], scan.redact(self.value))
                self.assertNotIn(self.value, str(hits))

    def test_embedded_candidates_do_not_hide_later_standalone_token(self):
        hits = self.findings("中" + self.value + " " + self.value + "é " + self.value)
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["evidence"], scan.redact(self.value))

    def test_ascii_body_length_and_masked_hints_are_preserved(self):
        for text in (self.value[:-1], self.value + "A", self.value[:-1] + "９",
                     "١٢٣:" + self.value.split(":")[1]):
            with self.subTest(text=text):
                self.assertEqual(self.findings(text), [])
        hits = self.findings("123456789:" + "x" * 35)
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["severity"], "low")
        self.assertIn("example-key?", hits[0]["evidence"])
