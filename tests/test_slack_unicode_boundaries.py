"""Slack boundary regressions using synthetic, non-live values."""
import re
import tempfile
import unittest
from pathlib import Path

from test_scan import _collect, scan


class SlackUnicodeBoundaryTests(unittest.TestCase):
    prefixes = ("xoxb-", "xoxa-", "xoxp-", "xoxr-", "xoxs-")
    body = "1234567890-AbCdEf123456"
    word_chars = ("é", "中", "Ж", "١", "９", "²", "K")

    def findings(self, text):
        with tempfile.TemporaryDirectory() as root:
            Path(root, "settings.txt").write_text(text, encoding="utf-8")
            return _collect(root, scan.scan_secrets)

    def test_unicode_word_adjacency_is_not_a_standalone_token(self):
        for prefix in self.prefixes:
            value = prefix + self.body
            for char in self.word_chars:
                self.assertIsNotNone(re.fullmatch(r"\w", char))
                for text in (char + value, value + char,
                             prefix + self.body[:10] + char + self.body[10:]):
                    with self.subTest(prefix=prefix, text=text):
                        self.assertEqual(self.findings(text), [])

    def test_unicode_punctuation_preserves_metadata_and_redaction(self):
        for prefix in self.prefixes:
            value = prefix + self.body
            for left, right in (("“", "”"), ("（", "）"), ("—", "。")):
                with self.subTest(prefix=prefix, left=left):
                    hits = self.findings("heading" + chr(10) + left + value + right)
                    self.assertEqual(len(hits), 1)
                    self.assertEqual(hits[0], {
                        "category": "secret", "severity": "high",
                        "file": "settings.txt", "line": 2,
                        "summary": "Slack token detected",
                        "evidence": scan.redact(value),
                    })
                    self.assertNotIn(value, str(hits))

    def test_later_standalone_token_survives_excluded_candidates(self):
        for prefix in self.prefixes:
            value = prefix + self.body
            with self.subTest(prefix=prefix):
                hits = self.findings("é" + value + " " + value + "中 " + value)
                self.assertEqual(len(hits), 1)
                self.assertEqual(hits[0]["evidence"], scan.redact(value))
