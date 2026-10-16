"""Google detector boundary cases using synthetic, non-live candidates."""
import tempfile
import unittest
from pathlib import Path

from test_scan import _collect, scan


class GoogleUnicodeBoundaryTests(unittest.TestCase):
    value = "AIza" + ("aB3_dE6-fG9" * 4)[:35]

    def findings(self, text):
        with tempfile.TemporaryDirectory() as root:
            Path(root, "settings.txt").write_text(text, encoding="utf-8")
            return _collect(root, scan.scan_secrets)

    def test_unicode_word_neighbors_are_not_partial_keys(self):
        for char in ("é", "中", "Ω", "١", "９"):
            for text in (char + self.value, self.value + char):
                with self.subTest(text=text):
                    self.assertEqual(self.findings(text), [])

    def test_delimiters_preserve_metadata_and_redaction(self):
        for left, right in (("", ""), ('"', '"'), (" ", " "),
                            ("（", "）"), ("—", "。"), ("/", "?")):
            with self.subTest(left=left, right=right):
                hits = self.findings("heading" + chr(10) + left + self.value + right)
                self.assertEqual(len(hits), 1)
                hit = hits[0]
                self.assertEqual(hit["summary"], "Google API key detected")
                self.assertEqual(hit["severity"], "medium")
                self.assertEqual(hit["category"], "secret")
                self.assertEqual(hit["file"], "settings.txt")
                self.assertEqual(hit["line"], 2)
                self.assertEqual(hit["evidence"], scan.redact(self.value))
                self.assertNotIn(self.value, str(hits))

    def test_embedded_candidates_do_not_hide_standalone_keys(self):
        hits = self.findings("中" + self.value + " " + self.value + "é "
                             + self.value + " " + self.value)
        self.assertEqual(len(hits), 2)
        self.assertTrue(all(hit["evidence"] == scan.redact(self.value) for hit in hits))

    def test_body_remains_ascii_and_masked_value_stays_low(self):
        for char in ("é", "中", "١", "９"):
            with self.subTest(char=char):
                self.assertEqual(self.findings(self.value[:-1] + char), [])
        hits = self.findings("AIza" + "x" * 35)
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["severity"], "low")
        self.assertIn("example-key?", hits[0]["evidence"])
