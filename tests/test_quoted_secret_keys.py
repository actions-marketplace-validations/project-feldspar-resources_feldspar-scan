"""Quoted generic assignment keys, using synthetic values and offline scans."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest

from test_scan import scan


class QuotedSecretKeyTests(unittest.TestCase):
    value = 'A1b2C3d4E5f6G7h8'

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

    def test_quoted_and_unquoted_keys_keep_metadata_and_redaction(self):
        for key in ('api_key', 'api-key', 'apikey', 'secret', 'password',
                    'passwd', 'token', 'PASSWORD'):
            for quote in ('', "'", '"'):
                for separator in (':', '='):
                    with self.subTest(key=key, quote=quote, separator=separator):
                        text = f'{quote}{key}{quote} {separator} "{self.value}"'
                        hits = self.findings('\n' + text)
                        self.assertEqual(len(hits), 1)
                        self.assertEqual(hits[0], dict(
                            category='secret', severity='medium', file='settings.txt',
                            line=2, summary=f'Hardcoded {key.lower()} assignment',
                            evidence='A1b2…'))
                        self.assertNotIn(self.value, json.dumps(hits))

    def test_quoted_keys_preserve_value_exclusions_and_hints(self):
        for value in ('https://example.invalid/path', 'wss://example.invalid/socket',
                      self.value[:-1], 'two words with spaces'):
            with self.subTest(value=value):
                self.assertEqual(self.findings(json.dumps({'password': value})), [])
        text = json.dumps({'password': '${SYNTHETIC_PASSWORD}'})
        hits = self.findings(text)
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]['severity'], 'low')
        self.assertEqual(hits[0]['evidence'], '${SY… (placeholder?)')

    def test_unquoted_prefixed_names_and_single_quoted_values_still_work(self):
        for name in ('DB_PASSWORD', 'service_token'):
            with self.subTest(name=name):
                hits = self.findings(f"{name} = '{self.value}'")
                self.assertEqual(len(hits), 1)
                self.assertEqual(hits[0]['severity'], 'medium')
                self.assertEqual(hits[0]['evidence'], 'A1b2…')

    def test_quoted_keys_require_paired_quotes_and_assignment(self):
        for key in ('"password\'', '\'password"',
                    '"password_hint"', '"description"'):
            with self.subTest(key=key):
                self.assertEqual(self.findings(f'{key}: "{self.value}"'), [])
        self.assertEqual(self.findings('"password" is a configuration field'), [])

    def test_json_file_reaches_summary_gate_and_triage(self):
        with tempfile.TemporaryDirectory() as root:
            Path(root, 'settings.json').write_text(
                json.dumps({'password': self.value}), encoding='utf-8')
            output = io.StringIO()
            with contextlib.redirect_stdout(output), contextlib.redirect_stderr(io.StringIO()):
                code = scan.main(['scan.py', root, '--no-osv', '--triage',
                                  '--fail-on', 'medium'])
            report = json.loads(output.getvalue())
        self.assertEqual(code, 1)
        self.assertEqual(report['summary']['secret_hits'], 1)
        self.assertEqual(report['summary']['by_severity']['medium'], 1)
        self.assertEqual(report['findings'][0]['file'], 'settings.json')
        self.assertEqual(report['triage_summary']['secrets']['total'], 1)
        self.assertNotIn(self.value, output.getvalue())
