"""Boundary refinement for existing OpenAI heuristics; all values are synthetic."""
import tempfile
import unittest
from pathlib import Path

from test_scan import _collect, scan


class OpenAIUnicodeBoundaryTests(unittest.TestCase):
    body = ("aB3_dE6-fG9" * 8)

    def findings(self, text):
        with tempfile.TemporaryDirectory() as root:
            Path(root, "settings.txt").write_text(text, encoding="utf-8")
            return _collect(root, scan.scan_secrets)

    def test_unicode_word_neighbors_are_not_partial_keys(self):
        for prefix in ("sk-", "sk-proj-"):
            value = prefix + self.body[:40]
            for char in ("é", "中", "Ω", "١", "９"):
                for text in (char + value, value + char):
                    with self.subTest(prefix=prefix, char=char, text=text):
                        self.assertEqual(self.findings(text), [])

    def test_delimited_keys_preserve_metadata_and_redaction(self):
        for prefix in ("sk-", "sk-proj-"):
            value = prefix + self.body[:40]
            for left, right in (("", ""), ('"', '"'), (" ", " "),
                                ("（", "）"), ("—", "。"), ("/", "?")):
                with self.subTest(prefix=prefix, left=left, right=right):
                    hits = self.findings("heading" + chr(10) + left + value + right)
                    self.assertEqual(len(hits), 1)
                    hit = hits[0]
                    self.assertEqual(hit["summary"], "OpenAI API key detected")
                    self.assertEqual(hit["severity"], "high")
                    self.assertEqual(hit["category"], "secret")
                    self.assertEqual(hit["file"], "settings.txt")
                    self.assertEqual(hit["line"], 2)
                    self.assertEqual(hit["evidence"], scan.redact(value))
                    self.assertNotIn(value, str(hits))

    def test_body_and_minimum_length_are_unchanged(self):
        for prefix in ("sk-", "sk-proj-"):
            for size in (39, 40, 41, 80):
                with self.subTest(prefix=prefix, size=size):
                    self.assertEqual(len(self.findings(prefix + self.body[:size])),
                                     int(size >= 40))
            for char in ("é", "中", "١", "９"):
                with self.subTest(prefix=prefix, char=char):
                    self.assertEqual(self.findings(prefix + self.body[:39] + char), [])

    def test_embedded_candidates_do_not_hide_multiple_standalone_hits(self):
        for prefix in ("sk-", "sk-proj-"):
            value = prefix + self.body[:40]
            with self.subTest(prefix=prefix):
                hits = self.findings("中" + value + " " + value + "é "
                                     + value + " " + value)
                self.assertEqual(len(hits), 2)
                self.assertTrue(all(hit["evidence"] == scan.redact(value) for hit in hits))

    def test_masked_values_and_anthropic_exclusion_are_preserved(self):
        for prefix in ("sk-", "sk-proj-"):
            with self.subTest(prefix=prefix):
                hits = self.findings(prefix + "x" * 40)
                self.assertEqual(len(hits), 1)
                self.assertEqual(hits[0]["severity"], "low")
                self.assertIn("example-key?", hits[0]["evidence"])
        hits = self.findings("sk-ant-" + self.body[:40])
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["summary"], "Anthropic API key detected")
