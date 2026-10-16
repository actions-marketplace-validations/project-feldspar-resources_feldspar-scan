"""Placeholder-name hint boundaries, using only synthetic offline fixtures."""
import json
from pathlib import Path
import tempfile
import unittest

from test_scan import _run


class PlaceholderNameBoundaryTests(unittest.TestCase):
    PROVIDER = 'npm_' + 'A1b2C3' * 6
    GENERIC = 'A1b2C3d4E5f6G7h8'

    def report(self, text, severity):
        with tempfile.TemporaryDirectory() as root:
            Path(root, 'settings.html').write_text(text, encoding='utf-8')
            code, stdout, stderr = _run(
                root, '--no-osv', '--triage', '--fail-on', severity)
        report = json.loads(stdout)
        self.assertEqual(len(report['findings']), 1, stderr)
        self.assertNotIn(self.PROVIDER, stdout)
        self.assertNotIn(self.GENERIC, stdout)
        return code, report['findings'][0]

    def test_longer_names_do_not_downgrade_provider_hits(self):
        for name in ('notplaceholder', 'data-placeholder', 'custom_placeholder',
                     '9placeholder', 'éplaceholder', 'placeholderSuffix'):
            with self.subTest(name=name):
                code, hit = self.report(
                    '<input ' + name + '="' + self.PROVIDER + '">', 'high')
                self.assertEqual(code, 1)
                self.assertEqual(hit['severity'], 'high')
                self.assertEqual(hit['evidence'], 'npm_…')
                self.assertEqual(hit['line'], 1)

    def test_longer_names_do_not_downgrade_generic_hits(self):
        for name in ('notplaceholder', 'data-placeholder', 'custom_placeholder',
                     'éplaceholder'):
            with self.subTest(name=name):
                code, hit = self.report(
                    name + '={token: "' + self.GENERIC + '"}', 'medium')
                self.assertEqual(code, 1)
                self.assertEqual(hit['severity'], 'medium')
                self.assertEqual(hit['evidence'], 'A1b2…')

    def test_exact_placeholder_still_downgrades_provider_hits(self):
        for prefix, suffix in (('placeholder="', '"'),
                               ("<input PLACEHOLDER = '", "'>"),
                               ("{placeholder: '", "'}"),
                               ('placeholder={"', '"}')):
            with self.subTest(prefix=prefix):
                code, hit = self.report(prefix + self.PROVIDER + suffix, 'high')
                self.assertEqual(code, 0)
                self.assertEqual(hit['severity'], 'low')
                self.assertEqual(hit['evidence'], 'npm_… (form-placeholder?)')

    def test_exact_placeholder_still_downgrades_generic_hits(self):
        code, hit = self.report(
            'placeholder={token: "' + self.GENERIC + '"}', 'medium')
        self.assertEqual(code, 0)
        self.assertEqual(hit['severity'], 'low')
        self.assertEqual(hit['evidence'], 'A1b2… (form-placeholder?)')
