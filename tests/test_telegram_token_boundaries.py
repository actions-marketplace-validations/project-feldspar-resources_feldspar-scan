"""Telegram heuristic boundaries using synthetic, non-live values."""
import string
import tempfile
import unittest
from pathlib import Path

from test_scan import _collect, scan


class TelegramTokenBoundaryTests(unittest.TestCase):
    body = 'aB3_dE6-fG9' * 3 + 'h7'
    value = '123456789:' + body

    def findings(self, text):
        with tempfile.TemporaryDirectory() as root:
            Path(root, 'settings.txt').write_text(text, encoding='utf-8')
            return _collect(root, scan.scan_secrets)

    def test_standalone_contexts_preserve_metadata_and_redaction(self):
        for template in ('{}', 'value="{}"', 'Bearer {}', '({})', '{}.',
                         'https://invalid.example/?value={}&next=1'):
            with self.subTest(template=template):
                hits = self.findings('heading' + chr(10) + template.format(self.value))
                self.assertEqual(len(hits), 1)
                self.assertEqual(hits[0]['summary'], 'Telegram bot token detected')
                self.assertEqual(hits[0]['category'], 'secret')
                self.assertEqual(hits[0]['severity'], 'high')
                self.assertEqual(hits[0]['file'], 'settings.txt')
                self.assertEqual(hits[0]['line'], 2)
                self.assertEqual(hits[0]['evidence'], scan.redact(self.value))
                self.assertNotIn(self.value, str(hits))

    def test_identifier_prefixes_do_not_produce_partial_matches(self):
        # Digits extend the existing variable-length numeric prefix.
        for prefix in (*string.ascii_letters, '_', '-', 'service-', 'service-42-'):
            with self.subTest(prefix=prefix):
                self.assertEqual(self.findings(prefix + self.value), [])

    def test_body_suffixes_do_not_produce_partial_matches(self):
        for suffix in string.ascii_letters + string.digits + '_-':
            with self.subTest(suffix=suffix):
                self.assertEqual(self.findings(self.value + suffix), [])

    def test_existing_numeric_prefix_and_body_length_are_preserved(self):
        for prefix in ('1', '123456789', '123456789012345'):
            for body in (self.body[:-1], self.body, self.body + 'A'):
                with self.subTest(prefix=prefix, size=len(body)):
                    hits = self.findings(prefix + ':' + body)
                    self.assertEqual(len(hits), int(len(body) == 35))

    def test_later_standalone_match_survives_rejected_candidate(self):
        hits = self.findings('service-' + self.value + ' value="' + self.value + '"')
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]['severity'], 'high')
        self.assertEqual(hits[0]['evidence'], scan.redact(self.value))

    def test_existing_masked_and_placeholder_hints_are_preserved(self):
        for text, hint in (('123456789:' + 'x' * 35, 'example-key?'),
                           ('placeholder="' + self.value + '"', 'form-placeholder?')):
            with self.subTest(hint=hint):
                hits = self.findings(text)
                self.assertEqual(len(hits), 1)
                self.assertEqual(hits[0]['severity'], 'low')
                self.assertIn('(' + hint + ')', hits[0]['evidence'])
