"""Package-config assignment context; all credential values are synthetic."""
import json
import tempfile
import unittest
from pathlib import Path

from test_scan import _collect, scan


class NpmAuthKeyContextTests(unittest.TestCase):
    value = 'synthetic-value-123456789'

    def findings(self, text, name='.npmrc', scanner=None):
        with tempfile.TemporaryDirectory() as root:
            Path(root, name).write_text(text, encoding='utf-8')
            return _collect(root, scanner or scan.scan_config)

    def test_token_marker_inside_other_fields_is_not_an_assignment(self):
        for name in ('.npmrc',):
            for prefix in ('other_authToken=', 'prefix_authToken=',
                           'message=_authToken=', 'message="_authToken=',
                           'registry=https://registry.invalid/?_authToken=',
                           'registry=https://registry.invalid/ # _authToken=',
                           'registry=https://registry.invalid/ ; _authToken='):
                with self.subTest(name=name, prefix=prefix):
                    self.assertEqual(self.findings(prefix + self.value, name), [])

    def test_actual_assignments_keep_metadata_and_redaction(self):
        for name in ('.npmrc', '.pypirc'):
            for key in ('_authToken', '//registry.invalid/:_authToken',
                        '//registry.invalid:4873/team/:_authToken'):
                for indent in ('', '  ', '\t'):
                    with self.subTest(name=name, key=key, indent=indent):
                        entry = key + '=' + self.value
                        hits = self.findings('# comment' + chr(10) + indent + entry, name)
                        self.assertEqual(hits, [dict(
                            category='config', severity='high', file=name, line=2,
                            summary='Credential committed in ' + name,
                            evidence=scan.redact(entry))])
                        self.assertNotIn(self.value, json.dumps(hits))

    def test_ignored_marker_does_not_hide_later_assignment(self):
        for entry in ('_authToken=' + self.value,
                      'password = ' + self.value, 'password: ' + self.value):
            with self.subTest(entry=entry):
                hits = self.findings('message=_authToken=example' + chr(10) + entry)
                self.assertEqual(len(hits), 1)
                self.assertEqual(hits[0]['line'], 2)
                self.assertEqual(hits[0]['severity'], 'high')

    def test_comments_and_one_config_finding_per_file_are_preserved(self):
        entry = '//registry.invalid/:_authToken=' + self.value
        for marker in ('#', ';', '  #', '\t;'):
            with self.subTest(marker=marker):
                self.assertEqual(self.findings(marker + ' ' + entry), [])
        hits = self.findings(entry + chr(10) + entry)
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]['line'], 1)

    def test_provider_token_in_unrelated_value_still_has_secret_finding(self):
        token = 'npm_' + 'aB3dE6gH9jK2' * 3
        text = 'message=_authToken=' + token
        self.assertEqual(self.findings(text), [])
        hits = self.findings(text, scanner=scan.scan_secrets)
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]['summary'], 'npm access token detected')
        self.assertEqual(hits[0]['severity'], 'high')
        self.assertNotIn(token, json.dumps(hits))
