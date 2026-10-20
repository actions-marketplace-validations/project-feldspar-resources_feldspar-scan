"""Lockfile inventory describes recorded packages, not an installation profile."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from test_scan import scan


class NpmInstallScopeDocsTests(unittest.TestCase):
    def entries(self):
        return {
            'production': {'version': '1.0.0'},
            'development': {'version': '2.0.0', 'dev': True},
            'optional': {'version': '3.0.0', 'optional': True},
            'dev-optional': {'version': '4.0.0', 'devOptional': True},
            'platform-specific': {
                'version': '5.0.0', 'os': ['synthetic-os'], 'cpu': ['synthetic-cpu']},
        }

    def lockfile(self, layout):
        entries = self.entries()
        if layout == 'packages':
            return {'lockfileVersion': 3, 'packages': {
                '': {'name': 'root-project', 'version': '9.0.0'},
                **{'node_modules/' + name: meta for name, meta in entries.items()},
            }}
        # Include a nested dependency to pin traversal beneath a dev-only parent.
        nested = entries.pop('platform-specific')
        entries['development']['dependencies'] = {'platform-specific': nested}
        return {'lockfileVersion': 1, 'dependencies': entries}

    def expected(self):
        return {('npm', name, meta['version']) for name, meta in self.entries().items()}

    def report(self, root, *options):
        with contextlib.redirect_stdout(io.StringIO()) as output, \
                contextlib.redirect_stderr(io.StringIO()):
            status = scan.main(['scan.py', str(root), *options])
        return status, json.loads(output.getvalue())

    def test_both_layouts_keep_install_profile_metadata_entries(self):
        for layout in ('packages', 'dependencies'):
            with self.subTest(layout=layout):
                parsed = scan.parse_package_lock(json.dumps(self.lockfile(layout)))
                self.assertEqual(set(parsed), self.expected())
                self.assertEqual(len(parsed), 5)

    def test_advisory_queries_include_all_recorded_profiles(self):
        for layout in ('packages', 'dependencies'):
            with self.subTest(layout=layout), tempfile.TemporaryDirectory() as root:
                Path(root, 'package-lock.json').write_text(
                    json.dumps(self.lockfile(layout)), encoding='utf-8')
                with mock.patch.object(scan, 'query_osv', return_value={}) as query, \
                        mock.patch.object(scan, 'http_json', side_effect=AssertionError('offline')):
                    status, report = self.report(root)
                query.assert_called_once()
                self.assertEqual(set(query.call_args.args[0]), self.expected())
                self.assertEqual(status, 0)
                self.assertEqual(report['summary']['packages_found'], 5)
                self.assertEqual(report['summary']['lockfiles_parsed'], ['package-lock.json'])

    def test_no_osv_keeps_inventory_but_skips_queries(self):
        for layout in ('packages', 'dependencies'):
            with self.subTest(layout=layout), tempfile.TemporaryDirectory() as root:
                Path(root, 'package-lock.json').write_text(
                    json.dumps(self.lockfile(layout)), encoding='utf-8')
                with mock.patch.object(scan, 'query_osv') as query, \
                        mock.patch.object(scan, 'http_json', side_effect=AssertionError('offline')):
                    status, report = self.report(root, '--no-osv')
                query.assert_not_called()
                self.assertEqual(status, 0)
                self.assertEqual(report['summary']['packages_by_ecosystem'], {'npm': 5})
                self.assertEqual(report['summary']['packages_by_manifest'], {'package-lock.json': 5})
                self.assertFalse(report['summary']['osv_enabled'])


if __name__ == '__main__':
    unittest.main()
