"""Pin the documented package-config key case and delimiter selection."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from test_scan import scan


class PackageConfigKeyCaseDocsTests(unittest.TestCase):
    def report(self, filename, lines):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            # Deliberately short synthetic values; no credential material.
            (root / filename).write_text(chr(10).join(lines) + chr(10), encoding='utf-8')
            with mock.patch.object(scan, 'query_osv') as query, \
                    contextlib.redirect_stdout(io.StringIO()) as output, \
                    contextlib.redirect_stderr(io.StringIO()):
                status = scan.main(['scan.py', str(root), '--no-osv', '--no-commit',
                                    '--fail-on', 'high'])
            query.assert_not_called()
        report = json.loads(output.getvalue())
        self.assertEqual(report['summary']['secret_hits'], 0)
        return status, report

    def assert_config_hit(self, filename, lines, line):
        status, report = self.report(filename, lines)
        self.assertEqual(status, 1)
        self.assertFalse(report['summary']['gate']['passed'])
        self.assertEqual(report['summary']['config_issues'], 1)
        self.assertEqual([(f['category'], f['severity'], f['file'], f['line'], f['summary'])
                          for f in report['findings']],
                         [('config', 'high', filename, line,
                           'Credential committed in ' + filename)])

    def test_password_case_and_both_delimiters(self):
        for filename in ('.npmrc', '.pypirc'):
            for key in ('password', 'PASSWORD', 'PassWord'):
                for delimiter in ('=', ':'):
                    with self.subTest(filename=filename, key=key, delimiter=delimiter):
                        self.assert_config_hit(filename,
                                               ['# synthetic fixture',
                                                '  ' + key + ' ' + delimiter + ' x'], 2)

    def test_token_key_requires_exact_case_and_equals(self):
        for filename in ('.npmrc', '.pypirc'):
            for prefix in ('', '//registry.invalid/:'):
                for spacing in ('', ' ', chr(9)):
                    with self.subTest(filename=filename, prefix=prefix, spacing=spacing):
                        self.assert_config_hit(filename,
                                               ['  ' + prefix + '_authToken' + spacing + '=x'], 1)

    def test_near_misses_are_skipped_and_later_password_still_reports(self):
        for filename in ('.npmrc', '.pypirc'):
            for ignored in ('_authtoken=x', '_AUTHTOKEN=x', '_AuthToken=x',
                            '//registry.invalid/:_AUTHTOKEN=x',
                            '_authToken: x', '//registry.invalid/:_authToken: x',
                            'password_extra=x', 'db_password=x', 'otherpassword=x'):
                with self.subTest(filename=filename, ignored=ignored):
                    status, report = self.report(filename, [ignored])
                    self.assertEqual(status, 0)
                    self.assertEqual(report['findings'], [])
                    self.assertTrue(report['summary']['gate']['passed'])
                    self.assert_config_hit(filename, [ignored, 'PaSsWoRd: x'], 2)
