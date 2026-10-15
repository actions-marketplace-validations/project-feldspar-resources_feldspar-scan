"""Pin GitHub-token heuristic boundaries with synthetic, non-live values."""
import string
import tempfile
import unittest
from pathlib import Path

from test_scan import _collect, scan


class GitHubTokenBoundaryTests(unittest.TestCase):
    suffix = "aB3dE6fG9" * 4

    def findings(self, text):
        with tempfile.TemporaryDirectory() as root:
            Path(root, "settings.txt").write_text(text, encoding="utf-8")
            return _collect(root, scan.scan_secrets)

    def test_supported_prefixes_and_delimiters_preserve_metadata(self):
        for kind in "pousr":
            value = "gh" + kind + "_" + self.suffix
            for template in ("{}", 'value="{}"', "Bearer {}", "({})", "{}."):
                with self.subTest(kind=kind, template=template):
                    hits = self.findings(("heading" + chr(10)) + template.format(value))
                    self.assertEqual(len(hits), 1)
                    hit = hits[0]
                    self.assertEqual(hit["summary"], "GitHub token detected")
                    self.assertEqual(hit["category"], "secret")
                    self.assertEqual(hit["severity"], "high")
                    self.assertEqual(hit["file"], "settings.txt")
                    self.assertEqual(hit["line"], 2)
                    self.assertEqual(hit["evidence"], scan.redact(value))
                    self.assertNotIn(value, str(hits))

    def test_identifier_prefixes_are_not_tokens(self):
        for kind in "pousr":
            value = "gh" + kind + "_" + self.suffix
            for char in string.ascii_letters + string.digits + "_":
                with self.subTest(kind=kind, char=char):
                    self.assertEqual(self.findings(char + value), [])

    def test_underscore_suffixes_are_not_partial_tokens(self):
        for kind in "pousr":
            value = "gh" + kind + "_" + self.suffix
            for suffix in ("_", "_label", "A_label"):
                with self.subTest(kind=kind, suffix=suffix):
                    self.assertEqual(self.findings(value + suffix), [])

    def test_existing_minimum_length_heuristic_is_preserved(self):
        for size in (35, 36, 37, 80):
            with self.subTest(size=size):
                value = "ghp_" + (self.suffix * 3)[:size]
                self.assertEqual(len(self.findings(value)), int(size >= 36))

    def test_later_standalone_token_is_found_after_embedded_candidate(self):
        value = "ghp_" + self.suffix
        for candidate in ("prefix_" + value, value + "_label"):
            with self.subTest(candidate=candidate):
                hits = self.findings(candidate + ' placeholder="' + value + '"')
                self.assertEqual(len(hits), 1)
                self.assertEqual(hits[0]["severity"], "low")
                self.assertIn("(form-placeholder?)", hits[0]["evidence"])

    def test_masked_values_keep_existing_downgrade(self):
        hits = self.findings("ghp_" + "x" * 36)
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["severity"], "low")
        self.assertIn("(example-key?)", hits[0]["evidence"])
