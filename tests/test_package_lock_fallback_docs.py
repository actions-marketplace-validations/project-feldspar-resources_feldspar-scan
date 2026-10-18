"""Offline examples of packages-map precedence and legacy-tree fallback."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from test_scan import scan


LEGACY = {
    'synthetic-parent': {
        'version': '1.0.0',
        'dependencies': {'synthetic-child': {'version': '2.0.0'}},
    },
}
LEGACY_PACKAGES = [('npm', 'synthetic-parent', '1.0.0'),
                   ('npm', 'synthetic-child', '2.0.0')]


class PackageLockFallbackDocsTests(unittest.TestCase):
    def check_inventory(self, lock, expected):
        self.assertEqual(scan.parse_package_lock(json.dumps(lock)), expected)
        with tempfile.TemporaryDirectory() as root:
            Path(root, 'package-lock.json').write_text(
                json.dumps(lock), encoding='utf-8')
            for offline in (False, True):
                with self.subTest(offline=offline):
                    output = io.StringIO()
                    with mock.patch.object(scan, 'http_json', return_value={
                            'results': [{} for _ in expected]}) as network, \
                            contextlib.redirect_stdout(output), \
                            contextlib.redirect_stderr(io.StringIO()):
                        status = scan.main(['scan.py', root, '--no-commit',
                                            '--fail-on', 'low'] +
                                           (['--no-osv'] if offline else []))
                    self.assertEqual(status, 0)
                    report = json.loads(output.getvalue())
                    self.assertEqual(report['summary']['packages_found'], len(expected))
                    self.assertEqual(report['summary']['lockfiles_parsed'],
                                     ['package-lock.json'])
                    self.assertEqual(report['summary']['osv_enabled'], not offline)
                    self.assertEqual(report['findings'], [])
                    self.assertNotIn('errors', report)
                    if offline or not expected:
                        network.assert_not_called()
                    else:
                        network.assert_called_once_with(scan.OSV_BATCH, {
                            'queries': [
                                {'package': {'name': name, 'ecosystem': ecosystem},
                                 'version': version}
                                for ecosystem, name, version in expected],
                        })

    def test_productive_map_does_not_merge_legacy_only_packages(self):
        for lock_version in (2, 3):
            with self.subTest(lock_version=lock_version):
                self.check_inventory({
                    'lockfileVersion': lock_version,
                    'packages': {
                        '': {'name': 'synthetic-root', 'version': '9.0.0'},
                        'node_modules/synthetic-parent': {'version': '3.0.0'},
                        'node_modules/synthetic-child': {},
                    },
                    'dependencies': LEGACY,
                }, [('npm', 'synthetic-parent', '3.0.0')])

    def test_fallback_depends_on_map_output_not_map_presence(self):
        for map_fields in (
                {},
                {'packages': {}},
                {'packages': {'': {'name': 'synthetic-root', 'version': '9.0.0'}}},
                {'packages': {'node_modules/synthetic-parent': {}}}):
            with self.subTest(map_fields=map_fields):
                self.check_inventory({'lockfileVersion': 2,
                                      'dependencies': LEGACY, **map_fields},
                                     LEGACY_PACKAGES)

    def test_no_packages_in_either_section_makes_no_advisory_request(self):
        self.check_inventory({
            'lockfileVersion': 3,
            'packages': {'': {'name': 'synthetic-root', 'version': '9.0.0'}},
            'dependencies': {},
        }, [])
