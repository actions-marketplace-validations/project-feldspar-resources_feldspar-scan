"""Stripe restricted-key detection using synthetic strings only; no API calls."""
import json
from pathlib import Path
import tempfile
import unittest

from test_scan import scan


class StripeRestrictedKeyTests(unittest.TestCase):
    def findings(self, text):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root, 'settings.txt')
            path.write_text(text, encoding='utf-8')
            findings = []

            def add(category, severity, file, line, **details):
                findings.append(dict(category=category, severity=severity,
                                     file=file, line=line, **details))

            scan.scan_secrets(root, [str(path)], add)
            return findings

    def test_live_restricted_keys_are_detected_and_redacted(self):
        for size in (24, 100):
            value = 'rk_live_' + ('A1b2C3d4' * 13)[:size]
            for text in (value, 'Authorization: Bearer ' + value,
                         json.dumps({'stripe': value})):
                with self.subTest(size=size, text=text):
                    findings = self.findings('heading' + chr(10) + text)
                    self.assertEqual(len(findings), 1)
                    hit = findings[0]
                    self.assertEqual(hit['summary'], 'Stripe live restricted key detected')
                    self.assertEqual(hit['category'], 'secret')
                    self.assertEqual(hit['severity'], 'high')
                    self.assertEqual(hit['file'], 'settings.txt')
                    self.assertEqual(hit['line'], 2)
                    self.assertEqual(hit['evidence'], 'rk_l…')
                    self.assertNotIn(value, json.dumps(findings))

    def test_non_live_short_and_embedded_values_are_not_provider_hits(self):
        suffix = 'A1b2C3d4' * 3
        values = ['rk_test_' + suffix, 'pk_live_' + suffix,
                  'rk_live_' + suffix[:-1], 'rk_live_${STRIPE_VALUE}',
                  'prefix_rk_live_' + suffix, 'Ark_live_' + suffix,
                  'rk_live_' + suffix + '_suffix']
        for value in values:
            with self.subTest(value=value):
                self.assertEqual(self.findings(value), [])

    def test_masked_key_still_has_low_severity_hint(self):
        findings = self.findings('rk_live_' + 'x' * 24)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]['severity'], 'low')
        self.assertEqual(findings[0]['evidence'], 'rk_l… (example-key?)')

    def test_existing_live_secret_key_detection_is_preserved(self):
        findings = self.findings('sk_live_' + 'A1b2C3d4' * 3)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]['summary'], 'Stripe live secret key detected')
        self.assertEqual(findings[0]['severity'], 'critical')
