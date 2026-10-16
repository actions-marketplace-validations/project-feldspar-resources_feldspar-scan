"""Generic assignments require paired value quotes; all values are synthetic."""
import json
from pathlib import Path
import tempfile
import unittest

from test_scan import scan


class GenericValueQuoteTests(unittest.TestCase):
    value = 'A1b2C3d4E5f6G7h8'

    def findings(self, text):
        hits = []

        def add(category, severity, file, line, **details):
            hits.append(dict(category=category, severity=severity, file=file,
                             line=line, **details))

        with tempfile.TemporaryDirectory() as root:
            path = Path(root, 'settings.txt')
            path.write_text(text, encoding='utf-8')
            scan.scan_secrets(root, [str(path)], add)
        self.assertNotIn(self.value, json.dumps(hits))
        return hits

    def test_mismatched_value_quotes_are_not_assignments(self):
        for opening, closing in (("'", '"'), ('"', "'")):
            with self.subTest(opening=opening):
                self.assertEqual(self.findings(
                    'password = ' + opening + self.value + closing), [])

    def test_matching_quotes_preserve_keys_location_severity_and_redaction(self):
        for quote in ("'", '"'):
            for key in ('password', "'api_key'", '"token"'):
                for separator in ('=', ':'):
                    with self.subTest(quote=quote, key=key, separator=separator):
                        hits = self.findings(chr(10) + key + separator + quote + self.value + quote)
                        self.assertEqual(len(hits), 1)
                        self.assertEqual(hits[0], dict(
                            category='secret', severity='medium', file='settings.txt',
                            line=2, summary='Hardcoded %s assignment' % key.strip("'\""),
                            evidence='A1b2…'))

    def test_bad_quotes_do_not_hide_later_valid_assignment(self):
        for bad in ("'" + self.value + '"', '"' + self.value + "'"):
            hits = self.findings('password=' + bad + '; token="' + self.value + '"')
            self.assertEqual(len(hits), 1)
            self.assertEqual(hits[0]['summary'], 'Hardcoded token assignment')

    def test_provider_pattern_still_detects_value_with_mismatched_quotes(self):
        token = 'ghp_' + 'A1b2C3d4E5f6' * 3
        hits = self.findings('password="' + token + "'")
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]['summary'], 'GitHub token detected')
        self.assertEqual(hits[0]['severity'], 'high')
        self.assertNotIn(token, json.dumps(hits))

    def test_existing_length_and_placeholder_rules_remain(self):
        for quote in ("'", '"'):
            self.assertEqual(self.findings('password=' + quote + self.value[:-1] + quote), [])
            hits = self.findings('password=' + quote + 'x' * 16 + quote)
            self.assertEqual(len(hits), 1)
            self.assertEqual(hits[0]['severity'], 'low')
            self.assertIn('(placeholder?)', hits[0]['evidence'])
