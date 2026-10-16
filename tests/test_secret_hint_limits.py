"""Documented hint limitations, using synthetic values and offline scans."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest

from test_scan import scan


class SecretHintLimitTests(unittest.TestCase):
    def report(self, text, gate):
        with tempfile.TemporaryDirectory() as root:
            Path(root, 'settings.txt').write_text(text, encoding='utf-8')
            output = io.StringIO()
            with contextlib.redirect_stdout(output), contextlib.redirect_stderr(io.StringIO()):
                status = scan.main(['scan.py', root, '--no-osv', '--triage',
                                    '--fail-on', gate])
            return status, json.loads(output.getvalue())

    def test_generic_shape_hints_keep_hits_but_lower_priority_and_gate(self):
        cases = (
            ('AbCdEfGhJkLmNpQrStUv', 'word-like?'),
            ('AbCdEfGhJkLmNpQrStUv9é', 'non-ascii?'),
        )
        for value, hint in cases:
            for gate, expected_status in (('medium', 0), ('low', 1)):
                with self.subTest(hint=hint, gate=gate):
                    status, report = self.report('password="%s"' % value, gate)
                    self.assertEqual(status, expected_status)
                    self.assertEqual(len(report['findings']), 1)
                    finding = report['findings'][0]
                    self.assertEqual(finding['severity'], 'low')
                    self.assertEqual(finding['evidence'], value[:4] + '… (' + hint + ')')
                    self.assertNotIn(value, json.dumps(report, ensure_ascii=False))
                    self.assertTrue(report['triage'][finding['id']]['likely_false_positive'])
                    self.assertEqual(report['triage'][finding['id']]['action'], 'informational')

    def test_generic_mixed_case_with_digit_without_hint_remains_review(self):
        value = 'AbCdEfGhJkLmNpQrStUv9'
        status, report = self.report('password="%s"' % value, 'medium')
        self.assertEqual(status, 1)
        self.assertEqual(len(report['findings']), 1)
        finding = report['findings'][0]
        self.assertEqual(finding['severity'], 'medium')
        self.assertEqual(finding['evidence'], value[:4] + '…')
        self.assertFalse(report['triage'][finding['id']]['likely_false_positive'])
        self.assertEqual(report['triage'][finding['id']]['action'], 'review')

    def test_provider_pattern_without_digits_does_not_use_word_like_hint(self):
        # Deliberately synthetic letters-only payload; never a real credential.
        value = 'ghp_' + 'AbCdEfGhJkLm' * 3
        status, report = self.report('credential: %s' % value, 'high')
        self.assertEqual(status, 1)
        self.assertEqual(len(report['findings']), 1)
        finding = report['findings'][0]
        self.assertEqual(finding['summary'], 'GitHub token detected')
        self.assertEqual(finding['severity'], 'high')
        self.assertEqual(finding['evidence'], 'ghp_…')
        self.assertNotIn(value, json.dumps(report))
        self.assertEqual(report['triage'][finding['id']]['action'], 'review')
