"""Counts of retained dependency findings, with synthetic offline advisories."""
import contextlib
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from test_scan import scan


class DependencyFindingsByEcosystemTests(unittest.TestCase):
    def report(self, root, *options):
        output = io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(io.StringIO()):
            status = scan.main(['scan.py', str(root), *options])
        return status, json.loads(output.getvalue())

    def assert_counts(self, report, expected):
        counts = report['summary']['dependency_findings_by_ecosystem']
        self.assertEqual(counts, expected)
        self.assertEqual(list(counts), sorted(counts))
        self.assertEqual(sum(counts.values()), report['summary']['by_category']['dependency-vuln'])
        canon = json.dumps({key: report[key] for key in ('findings', 'target', 'commit')},
                           sort_keys=True, separators=(',', ':'))
        self.assertEqual(report['manifest_hash'], hashlib.sha256(canon.encode()).hexdigest())

    def fixtures(self, root):
        for name in ('requirements.txt', 'requirements-dev.txt'):
            Path(root, name).write_text(chr(10).join(('shared==1.0', 'shared==2.0', 'clean==3.0', '')))
        Path(root, 'package-lock.json').write_text(json.dumps({
            'packages': {'node_modules/shared': {'version': '1.0'}}}))
        Path(root, 'compose.yaml').write_text(chr(10).join((
            'services:', '  app:', '    privileged: true', '')))
        return {
            ('npm', 'shared', '1.0'): ['TEST-1'],
            ('PyPI', 'shared', '2.0'): ['TEST-1', 'TEST-2'],
            ('PyPI', 'shared', '1.0'): ['TEST-3'],
        }

    def test_empty_and_non_dependency_reports(self):
        with tempfile.TemporaryDirectory() as root:
            _, empty = self.report(root, '--no-osv')
            Path(root, 'compose.yaml').write_text(chr(10).join((
                'services:', '  app:', '    privileged: true', '')))
            # Synthetic generic assignment; no real credential is used.
            Path(root, 'settings.txt').write_text('api_key = "' + 'Ab7xQ9mZ2vK4sN6p' + '"')
            status, other = self.report(root, '--no-osv', '--triage', '--fail-on', 'low')
        self.assertEqual(status, 1)
        self.assertEqual({f['category'] for f in other['findings']}, {'config', 'secret'})
        for report in (empty, other):
            self.assert_counts(report, {})

    def test_inventory_without_hits_or_without_lookup(self):
        with tempfile.TemporaryDirectory() as root:
            self.fixtures(root)
            with mock.patch.object(scan, 'query_osv', return_value={}) as query:
                _, offline = self.report(root, '--no-osv')
                query.assert_not_called()
                _, checked = self.report(root)
                query.assert_called_once()
        for report in (offline, checked):
            self.assertEqual(report['summary']['packages_found'], 4)
            self.assert_counts(report, {})

    def test_counts_findings_not_advisories_or_duplicate_manifests(self):
        with tempfile.TemporaryDirectory() as root:
            hits = self.fixtures(root)
            detail = {'severity': 'high', 'fixed_in': ['4.0'], 'summary': 'Synthetic'}
            with mock.patch.object(scan, 'query_osv', return_value=hits), \
                    mock.patch.object(scan, 'vuln_details', return_value=detail):
                status, plain = self.report(root)
                failed, triaged = self.report(root, '--triage', '--fail-on', 'high')
                passed, gated = self.report(root, '--fail-on', 'critical')
        self.assertEqual((status, failed, passed), (0, 1, 0))
        self.assertEqual(plain['summary']['packages_found'], 4)
        self.assertEqual(plain['summary']['by_category']['config'], 1)
        for report in (plain, triaged, gated):
            self.assert_counts(report, {'PyPI': 2, 'npm': 1})
            self.assertEqual(report['findings'], plain['findings'])
            self.assertEqual(report['manifest_hash'], plain['manifest_hash'])
        self.assertEqual(triaged['summary']['gate']['matching_findings'], 3)
        self.assertTrue(gated['summary']['gate']['passed'])

    def test_global_and_per_file_caps_count_only_retained_findings(self):
        with tempfile.TemporaryDirectory() as root:
            hits = self.fixtures(root)
            detail = {'severity': 'high', 'fixed_in': [], 'summary': 'Synthetic'}
            with mock.patch.object(scan, 'query_osv', return_value=hits), \
                    mock.patch.object(scan, 'vuln_details', return_value=detail):
                with mock.patch.object(scan, 'MAX_FINDINGS', 1):
                    _, global_cap = self.report(root)
                with mock.patch.object(scan, 'MAX_FINDINGS_PER_FILE', 1):
                    _, file_cap = self.report(root)
        self.assert_counts(global_cap, {'PyPI': 1})
        self.assert_counts(file_cap, {'PyPI': 1, 'npm': 1})
        for report in (global_cap, file_cap):
            self.assertTrue(report['summary']['truncated']['findings'])
            self.assertEqual(report['summary']['vulnerable_packages_by_ecosystem'], {'PyPI': 2, 'npm': 1})


if __name__ == '__main__':
    unittest.main()
