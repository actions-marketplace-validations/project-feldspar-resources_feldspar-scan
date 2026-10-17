"""Retained dependency findings count distinct representative manifest paths."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from test_scan import scan


class DependencyFilesByEcosystemTests(unittest.TestCase):
    def report(self, root, *options):
        output = io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(io.StringIO()):
            status = scan.main(['scan.py', str(root), *options])
        return status, json.loads(output.getvalue())

    def assert_counts(self, report, expected):
        counts = report['summary']['dependency_files_by_ecosystem']
        self.assertEqual(counts, expected)
        self.assertEqual(list(counts), sorted(counts))

    def test_empty_offline_and_no_advisory_reports(self):
        with tempfile.TemporaryDirectory() as root:
            _, empty = self.report(root, '--no-osv')
            Path(root, 'requirements.txt').write_text('sample==1.0' + chr(10))
            Path(root, 'Dockerfile').write_text('FROM scratch' + chr(10))
            with mock.patch.object(scan, 'query_osv', return_value={}) as query:
                _, offline = self.report(root, '--no-osv')
                query.assert_not_called()
                _, checked = self.report(root)
                query.assert_called_once()
        for report in (empty, offline, checked):
            self.assert_counts(report, {})
        self.assertEqual(offline['summary']['packages_found'], 1)
        self.assertGreater(offline['summary']['config_issues'], 0)

    def test_distinct_paths_not_packages_advisories_or_duplicate_manifests(self):
        with tempfile.TemporaryDirectory() as root:
            Path(root, 'requirements.txt').write_text(
                chr(10).join(('alpha==1.0', 'beta==1.0', '')))
            # These duplicated packages still have just one representative each.
            Path(root, 'requirements-dev.txt').write_text(
                chr(10).join(('alpha==1.0', 'beta==1.0', '')))
            nested = Path(root, 'service')
            nested.mkdir()
            (nested / 'requirements.txt').write_text('gamma==1.0' + chr(10))
            Path(root, 'package-lock.json').write_text(json.dumps({
                'packages': {'node_modules/alpha': {'version': '1.0'}}}))
            hits = {('PyPI', name, '1.0'): ['TEST-1', 'TEST-2']
                    for name in ('alpha', 'beta', 'gamma')}
            hits[('npm', 'alpha', '1.0')] = ['TEST-1']
            detail = {'severity': 'high', 'fixed_in': ['2.0'], 'summary': 'Synthetic'}
            with mock.patch.object(scan, 'query_osv', return_value=hits), \
                    mock.patch.object(scan, 'vuln_details', return_value=detail):
                status, plain = self.report(root)
                gate_status, triaged = self.report(root, '--triage', '--fail-on', 'high')
                with mock.patch.object(scan, 'MAX_FINDINGS', 1):
                    _, capped = self.report(root)
                with mock.patch.object(scan, 'MAX_FINDINGS_PER_FILE', 1):
                    _, per_file = self.report(root)
                with mock.patch.object(scan, 'MAX_FINDINGS', 0):
                    _, zero = self.report(root)
        self.assertEqual((status, gate_status), (0, 1))
        self.assertEqual(len(plain['findings']), 4)
        for report in (plain, triaged, per_file):
            self.assert_counts(report, {'PyPI': 2, 'npm': 1})
        self.assertEqual(plain['findings'], triaged['findings'])
        self.assertEqual(plain['manifest_hash'], triaged['manifest_hash'])
        self.assertEqual(triaged['summary']['gate']['matching_findings'], 4)
        self.assertEqual(len(per_file['findings']), 3)
        self.assertTrue(per_file['summary']['truncated']['findings'])
        self.assertEqual(len(capped['findings']), 1)
        self.assert_counts(capped, {capped['findings'][0]['ecosystem']: 1})
        self.assertTrue(capped['summary']['truncated']['findings'])
        self.assert_counts(zero, {})
        self.assertTrue(zero['summary']['truncated']['findings'])


if __name__ == '__main__':
    unittest.main()
