"""Stripe live-key boundaries; all values are synthetic and never authenticated."""
import string
import tempfile
import unittest
from pathlib import Path

from test_scan import _collect, scan


class StripeLiveBoundaryTests(unittest.TestCase):
    value = "sk_live_" + "aB3dE6gH" * 3

    def findings(self, text):
        with tempfile.TemporaryDirectory() as root:
            Path(root, "settings.txt").write_text(text, encoding="utf-8")
            return _collect(root, scan.scan_secrets)

    def test_delimited_values_keep_metadata_and_redaction(self):
        for length in (24, 25, 64, 128):
            value = "sk_live_" + ("aB3dE6gH" * 16)[:length]
            for template in ("{}", 'value="{}"', "'{}'", "({})", "[{}]",
                             "Bearer {}", "https://invalid.example/?key={}&next=1",
                             "prefix-{}-suffix", "{}."):
                with self.subTest(length=length, template=template):
                    hits = self.findings("heading\n" + template.format(value))
                    self.assertEqual(len(hits), 1)
                    hit = hits[0]
                    self.assertEqual(hit["summary"], "Stripe live secret key detected")
                    self.assertEqual(hit["category"], "secret")
                    self.assertEqual(hit["severity"], "critical")
                    self.assertEqual(hit["file"], "settings.txt")
                    self.assertEqual(hit["line"], 2)
                    self.assertEqual(hit["evidence"], "sk_l…")
                    self.assertNotIn(value, str(hits))

    def test_identifier_prefixes_are_not_keys(self):
        for char in string.ascii_letters + string.digits + "_":
            with self.subTest(char=char):
                self.assertEqual(self.findings(char + self.value), [])

    def test_underscore_suffixes_are_not_partial_keys(self):
        for suffix in ("_", "_suffix", "_aB3dE6gH"):
            with self.subTest(suffix=suffix):
                self.assertEqual(self.findings(self.value + suffix), [])

    def test_short_values_remain_excluded(self):
        self.assertEqual(self.findings(self.value[:-1]), [])

    def test_delimited_candidate_after_embedded_candidate_is_found(self):
        hits = self.findings("prefix_" + self.value + " " + self.value)
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["severity"], "critical")
        self.assertEqual(hits[0]["evidence"], "sk_l…")

    def test_existing_placeholder_downgrades_remain(self):
        for text, hint in (("sk_live_" + "x" * 24, "example-key?"),
                           ('<input placeholder="' + self.value + '">',
                            "form-placeholder?")):
            with self.subTest(hint=hint):
                hits = self.findings(text)
                self.assertEqual(len(hits), 1)
                self.assertEqual(hits[0]["severity"], "low")
                self.assertEqual(hits[0]["evidence"], "sk_l… (" + hint + ")")
