"""Offline examples of what lockfiles_parsed does and does not establish."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from test_scan import scan


class ManifestCoverageDocsTests(unittest.TestCase):
    def report(self, root):
        output = io.StringIO()
        # OSV is enabled: an empty inventory must still make no advisory requests.
        with mock.patch.object(scan, 'http_json', side_effect=AssertionError(
                'Unexpected network request')) as network, \
                contextlib.redirect_stdout(output), \
                contextlib.redirect_stderr(io.StringIO()):
            status = scan.main(['scan.py', str(root)])
        network.assert_not_called()
        self.assertEqual(status, 0)
        report = json.loads(output.getvalue())
        self.assertTrue(report['summary']['osv_enabled'])
        self.assertEqual(report['summary']['packages_found'], 0)
        self.assertEqual(report['summary']['vulnerable_packages'], 0)
        self.assertEqual(report['findings'], [])
        self.assertNotIn('errors', report)
        return report['summary']

    def test_empty_and_malformed_supported_manifests_are_listed(self):
        for filename, content in (
                ('package-lock.json', '{"packages": {}}'),
                ('package-lock.json', '{not valid json'),
                ('requirements.txt', ''),
                ('requirements.txt', 'synthetic-package>=1.0')):
            with self.subTest(filename=filename, content=content), \
                    tempfile.TemporaryDirectory() as root:
                Path(root, filename).write_text(content, encoding='utf-8')
                summary = self.report(root)
                self.assertEqual(summary['lockfiles_parsed'], [filename])
                self.assertNotIn('notes', summary)

    def test_unsupported_manifest_is_not_listed(self):
        with tempfile.TemporaryDirectory() as root:
            Path(root, 'composer.lock').write_text('{"packages": []}')
            summary = self.report(root)
        self.assertEqual(summary['lockfiles_parsed'], [])
        self.assertTrue(any('No supported dependency manifest was parsed' in note
                            for note in summary['notes']))

    def test_manifest_over_read_limit_is_not_listed(self):
        with tempfile.TemporaryDirectory() as root:
            # Sparse file exercises the actual 8 MiB manifest read limit.
            with Path(root, 'package-lock.json').open('wb') as manifest:
                manifest.truncate(8 * 1024 * 1024 + 1)
            summary = self.report(root)
        self.assertEqual(summary['lockfiles_parsed'], [])
        self.assertTrue(any('No supported dependency manifest was parsed' in note
                            for note in summary['notes']))
