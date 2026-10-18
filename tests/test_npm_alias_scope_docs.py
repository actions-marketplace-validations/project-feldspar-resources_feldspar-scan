"""Offline examples of package-lock identities without npm alias resolution."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from test_scan import scan


MODERN = {
    'lockfileVersion': 3,
    'packages': {
        '': {'name': 'synthetic-root', 'version': '9.0.0'},
        'node_modules/synthetic-normal': {'version': '1.0.0'},
        'node_modules/synthetic-alias': {
            'name': 'synthetic-original', 'version': '2.0.0'},
        'node_modules/parent/node_modules/@synthetic/alias': {
            'name': '@synthetic/original', 'version': '3.0.0'},
    },
}
MODERN_IDENTITIES = [
    ('synthetic-normal', '1.0.0'),
    ('synthetic-alias', '2.0.0'),
    ('@synthetic/alias', '3.0.0'),
]
LEGACY = {
    'lockfileVersion': 1,
    'dependencies': {
        'synthetic-normal': {'version': '1.0.0'},
        'synthetic-alias': {
            'version': 'npm:synthetic-original@2.0.0',
            'dependencies': {
                '@synthetic/alias': {
                    'version': 'npm:@synthetic/original@3.0.0'},
            },
        },
    },
}
LEGACY_IDENTITIES = [
    ('synthetic-normal', '1.0.0'),
    ('synthetic-alias', 'npm:synthetic-original@2.0.0'),
    ('@synthetic/alias', 'npm:@synthetic/original@3.0.0'),
]


class NpmAliasScopeDocsTests(unittest.TestCase):
    def report(self, lock, identities, offline=False):
        text = json.dumps(lock)
        self.assertEqual(scan.parse_package_lock(text), [
            ('npm', name, version) for name, version in identities
        ])
        output = io.StringIO()
        with tempfile.TemporaryDirectory() as root:
            Path(root, 'package-lock.json').write_text(text, encoding='utf-8')
            with mock.patch.object(scan, 'http_json', return_value={
                    'results': [{} for _ in identities]}) as network, \
                    contextlib.redirect_stdout(output), \
                    contextlib.redirect_stderr(io.StringIO()):
                status = scan.main(['scan.py', root, '--fail-on', 'low',
                                    *(['--no-osv'] if offline else [])])
        self.assertEqual(status, 0)
        report = json.loads(output.getvalue())
        self.assertEqual(report['summary']['packages_found'], len(identities))
        self.assertEqual(report['summary']['packages_by_ecosystem'],
                         {'npm': len(identities)})
        self.assertEqual(report['summary']['lockfiles_parsed'], ['package-lock.json'])
        self.assertEqual(report['findings'], [])
        self.assertNotIn('errors', report)
        if offline:
            network.assert_not_called()
            self.assertFalse(report['summary']['osv_enabled'])
        else:
            network.assert_called_once_with(scan.OSV_BATCH, {'queries': [
                {'package': {'name': name, 'ecosystem': 'npm'}, 'version': version}
                for name, version in identities
            ]})

    def test_modern_uses_installed_names_including_nested_scoped_alias(self):
        for version in (2, 3):
            with self.subTest(lockfileVersion=version):
                self.report(dict(MODERN, lockfileVersion=version), MODERN_IDENTITIES)

    def test_legacy_keeps_alias_keys_and_literal_versions(self):
        self.report(LEGACY, LEGACY_IDENTITIES)

    def test_offline_inventory_keeps_the_same_alias_identities(self):
        for lock, identities in ((MODERN, MODERN_IDENTITIES),
                                 (LEGACY, LEGACY_IDENTITIES)):
            with self.subTest(lockfileVersion=lock['lockfileVersion']):
                self.report(lock, identities, offline=True)
