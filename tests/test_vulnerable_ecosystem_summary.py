"""Vulnerable package version counts, using synthetic offline advisories."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from test_scan import scan


class VulnerableEcosystemSummaryTests(unittest.TestCase):
    def report(self, root, *options):
        output = io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(io.StringIO()):
            status = scan.main(['scan.py', str(root), *options])
        return status, json.loads(output.getvalue())

    def assert_counts(self, report, expected):
        counts = report['summary']['vulnerable_packages_by_ecosystem']
        self.assertEqual(counts, expected)
        self.assertEqual(list(counts), sorted(counts))
        self.assertEqual(sum(counts.values()), report['summary']['vulnerable_packages'])

    def test_empty_scan(self):
        with tempfile.TemporaryDirectory() as root:
            status, report = self.report(root, '--no-osv')
        self.assertEqual(status, 0)
        self.assert_counts(report, {})

    def test_inventory_without_advisories(self):
        with tempfile.TemporaryDirectory() as root:
            Path(root, 'requirements.txt').write_text('sample-package==1.0' + chr(10))
            with mock.patch.object(scan, 'query_osv', return_value={}) as query:
                status, offline = self.report(root, '--no-osv')
                query.assert_not_called()
                checked_status, checked = self.report(root)
                query.assert_called_once()
        self.assertEqual((status, checked_status), (0, 0))
        for report in (offline, checked):
            self.assertEqual(report['summary']['packages_by_ecosystem'], {'PyPI': 1})
            self.assert_counts(report, {})

    def test_counts_versions_not_advisories_or_manifest_occurrences(self):
        with tempfile.TemporaryDirectory() as root:
            for name in ('requirements.txt', 'requirements-dev.txt'):
                Path(root, name).write_text(chr(10).join(('shared==1.0', 'shared==2.0', 'clean==3.0', '')))
            Path(root, 'package-lock.json').write_text(json.dumps({
                'packages': {'node_modules/shared': {'version': '1.0'}}}))
            hits = {
                ('npm', 'shared', '1.0'): ['TEST-1'],
                ('PyPI', 'shared', '2.0'): ['TEST-1', 'TEST-2'],
                ('PyPI', 'shared', '1.0'): ['TEST-3'],
            }
            detail = {'severity': 'high', 'fixed_in': ['4.0'], 'summary': 'Synthetic'}
            with mock.patch.object(scan, 'query_osv', return_value=hits), \
                    mock.patch.object(scan, 'vuln_details', return_value=detail):
                status, plain = self.report(root)
                gated_status, triaged = self.report(root, '--triage', '--fail-on', 'high')
                with mock.patch.object(scan, 'MAX_FINDINGS', 1):
                    _, capped = self.report(root)
        self.assertEqual((status, gated_status), (0, 1))
        self.assertEqual(plain['summary']['packages_found'], 4)
        self.assertEqual(len(plain['findings']), 3)
        self.assertEqual(plain['findings'], triaged['findings'])
        self.assertEqual(plain['manifest_hash'], triaged['manifest_hash'])
        self.assertEqual(len(capped['findings']), 1)
        self.assertTrue(capped['summary']['truncated']['findings'])
        for report in (plain, triaged, capped):
            self.assert_counts(report, {'PyPI': 2, 'npm': 1})


if __name__ == '__main__':
    unittest.main()
