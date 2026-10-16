"""AWS detector boundary regressions with synthetic, non-live candidates."""
import tempfile
import unittest
from pathlib import Path

from test_scan import _collect, scan


class AwsUnicodeBoundaryTests(unittest.TestCase):
    value = "AKIA" + "7B3D9F2H5J8L4N6P"

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
                self.assertEqual(hit["summary"], "AWS access key ID detected")
                self.assertEqual(hit["severity"], "high")
                self.assertEqual(hit["category"], "secret")
                self.assertEqual(hit["file"], "settings.txt")
                self.assertEqual(hit["line"], 2)
                self.assertEqual(hit["evidence"], scan.redact(self.value))
                self.assertNotIn(self.value, str(hits))

    def test_embedded_candidate_does_not_hide_later_standalone_key(self):
        hits = self.findings("中" + self.value + " " + self.value + "é " + self.value)
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["evidence"], scan.redact(self.value))

    def test_body_remains_ascii_and_documented_example_stays_low(self):
        self.assertEqual(self.findings(self.value[:-1] + "９"), [])
        hits = self.findings("AKIAIOSFODNN7EXAMPLE")
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["severity"], "low")
        self.assertIn("example-key?", hits[0]["evidence"])
