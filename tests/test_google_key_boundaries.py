"""Pin Google-key heuristic boundaries using synthetic, non-live values."""
import string
import tempfile
import unittest
from pathlib import Path

from test_scan import _collect, scan


class GoogleKeyBoundaryTests(unittest.TestCase):
    value = "AIza" + ("aB3_dE6-fG9" * 4)[:35]

    def findings(self, text):
        with tempfile.TemporaryDirectory() as root:
            Path(root, "settings.txt").write_text(text, encoding="utf-8")
            return _collect(root, scan.scan_secrets)

    def test_standalone_contexts_preserve_metadata_and_redaction(self):
        for template in ("{}", 'value="{}"', '{{"value":"{}"}}',
                         "Bearer {}", "https://invalid.example/?key={}&next=1",
                         "({})", "[{}]", "{}."):
            with self.subTest(template=template):
                hits = self.findings(("heading" + chr(10)) + template.format(self.value))
                self.assertEqual(len(hits), 1)
                hit = hits[0]
                self.assertEqual(hit["summary"], "Google API key detected")
                self.assertEqual(hit["category"], "secret")
                self.assertEqual(hit["severity"], "medium")
                self.assertEqual(hit["file"], "settings.txt")
                self.assertEqual(hit["line"], 2)
                self.assertEqual(hit["evidence"], scan.redact(self.value))
                self.assertNotIn(self.value, str(hits))

    def test_token_alphabet_prefixes_and_suffixes_are_not_partial_keys(self):
        for char in string.ascii_letters + string.digits + "_-":
            for value in (char + self.value, self.value + char):
                with self.subTest(char=char, value=value):
                    self.assertEqual(self.findings(value), [])

    def test_short_value_and_split_value_are_not_keys(self):
        for value in (self.value[:-1], self.value[:20] + chr(10) + self.value[20:]):
            with self.subTest(value=value):
                self.assertEqual(self.findings(value), [])

    def test_valid_key_after_embedded_candidate_is_still_found(self):
        hits = self.findings("prefix_" + self.value + " " + self.value)
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["evidence"], scan.redact(self.value))
