"""Pin the documented distinction between pnpm inventory and graph resolution."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from test_scan import scan


LOCKFILE = """lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      importer-only:
        specifier: 1.0.0
        version: 1.0.0
packages:
  unused@2.0.0:
    dev: true
    optional: true
    os: [synthetic-os]
    cpu: [synthetic-cpu]
  '@scope/shared@3.0.0(peer@1.0.0)':
    resolution: {integrity: synthetic}
  '@scope/shared@3.0.0(peer@2.0.0)':
    resolution: {integrity: synthetic}
snapshots:
  snapshot-only@4.0.0:
    dependencies:
      peer: 2.0.0
"""
EXPECTED = {('npm', 'unused', '2.0.0'), ('npm', '@scope/shared', '3.0.0')}


class PnpmInventoryScopeDocsTests(unittest.TestCase):
    def report(self, root, *options):
        with contextlib.redirect_stdout(io.StringIO()) as output:
            status = scan.main(['scan.py', str(root), *options])
        self.assertEqual(status, 0)
        return json.loads(output.getvalue())

    def test_only_packages_keys_supply_names_and_peer_suffixes_are_removed(self):
        parsed = scan.parse_pnpm_lock(LOCKFILE)
        self.assertEqual(parsed, [
            ('npm', 'unused', '2.0.0'),
            ('npm', '@scope/shared', '3.0.0'),
            ('npm', '@scope/shared', '3.0.0'),
        ])

    def test_queries_use_deduplicated_inventory_without_graph_or_profile_filter(self):
        with tempfile.TemporaryDirectory() as root:
            Path(root, 'pnpm-lock.yaml').write_text(LOCKFILE, encoding='utf-8')
            with mock.patch.object(scan, 'query_osv', return_value={}) as query, \
                    mock.patch.object(scan, 'http_json', side_effect=AssertionError('offline')):
                report = self.report(root)
            query.assert_called_once()
            self.assertEqual(set(query.call_args.args[0]), EXPECTED)
            self.assertEqual(len(query.call_args.args[0]), 2)
            self.assertEqual(report['summary']['packages_found'], 2)
            self.assertEqual(report['summary']['packages_by_manifest'], {'pnpm-lock.yaml': 2})

    def test_no_osv_preserves_inventory_and_importer_snapshot_only_files_are_empty(self):
        graph_only = LOCKFILE.split('packages:', 1)[0] + 'snapshots:' + LOCKFILE.split('snapshots:', 1)[1]
        for text, count in ((LOCKFILE, 2), (graph_only, 0)):
            with self.subTest(count=count), tempfile.TemporaryDirectory() as root:
                Path(root, 'pnpm-lock.yaml').write_text(text, encoding='utf-8')
                with mock.patch.object(scan, 'query_osv') as query, \
                        mock.patch.object(scan, 'http_json', side_effect=AssertionError('offline')):
                    report = self.report(root, '--no-osv')
                query.assert_not_called()
                self.assertEqual(report['summary']['packages_found'], count)
                self.assertEqual(report['summary']['lockfiles_parsed'], ['pnpm-lock.yaml'])
                self.assertEqual(report['summary']['packages_by_manifest'], {'pnpm-lock.yaml': count})
                self.assertFalse(report['summary']['osv_enabled'])


if __name__ == '__main__':
    unittest.main()
