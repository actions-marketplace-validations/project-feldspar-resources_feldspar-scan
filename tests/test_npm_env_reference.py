"""Npm config reference filtering with synthetic, non-live values."""
import json
from pathlib import Path
import tempfile
import unittest

from test_scan import scan


class NpmEnvReferenceTests(unittest.TestCase):
    def collect(self, text, name='.npmrc'):
        findings = []

        def add(category, severity, file, line, **details):
            findings.append(dict(category=category, severity=severity,
                                 file=file, line=line, **details))

        with tempfile.TemporaryDirectory() as root:
            path = Path(root, name)
            path.write_text(text, encoding='utf-8')
            scan.scan_config(root, [str(path)], add)
        return findings

    def test_exact_auth_token_references_are_excluded(self):
        for key in ('_authToken', '//registry.invalid/:_authToken',
                    '//registry.invalid/team/:_authToken'):
            for name in ('NPM_TOKEN', '_TOKEN2', 'token'):
                with self.subTest(key=key, name=name):
                    self.assertEqual(self.collect('  ' + key + '=  ${' + name + '}  '), [])

    def test_later_literal_token_preserves_metadata_and_redaction(self):
        literal = 'synthetic-credential-123456789'
        entry = '//registry.invalid/:_authToken=' + literal
        text = chr(10).join(('# comment', '_authToken=${NPM_TOKEN}', entry))
        hits = self.collect(text)
        self.assertEqual(len(hits), 1)
        hit = hits[0]
        self.assertEqual(hit['category'], 'config')
        self.assertEqual(hit['severity'], 'high')
        self.assertEqual(hit['file'], '.npmrc')
        self.assertEqual(hit['line'], 3)
        self.assertEqual(hit['summary'], 'Credential committed in .npmrc')
        self.assertEqual(hit['evidence'], scan.redact(entry))
        self.assertNotIn(literal, json.dumps(hits))

    def test_non_exact_values_remain_findings(self):
        for value in ('synthetic-credential-123456789', '', '${}', '${1TOKEN}',
                      '${TOKEN', '$TOKEN', '${TOKEN:-literal}',
                      'prefix${TOKEN}', '${TOKEN}suffix', '${A}${B}',
                      '"${TOKEN}"', '${TOKEN} # comment'):
            with self.subTest(value=value):
                hits = self.collect('_authToken=' + value)
                self.assertEqual(len(hits), 1)
                self.assertEqual(hits[0]['severity'], 'high')

    def test_other_config_rules_remain_unchanged(self):
        for name, entry in (('.pypirc', '_authToken=${NPM_TOKEN}'),
                            ('.pypirc', 'password=${PASSWORD}'),
                            ('.npmrc', 'password=${PASSWORD}'),
                            ('.npmrc', 'other_authToken=${NPM_TOKEN}'),
                            ('.npmrc', 'message=_authToken=${NPM_TOKEN}')):
            with self.subTest(name=name, entry=entry):
                self.assertEqual(len(self.collect(entry, name)), 1)
