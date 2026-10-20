"""Retained dependency finding counts per representative manifest, offline."""
import contextlib
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from test_scan import scan


class DependencyFindingsByManifestTests(unittest.TestCase):
    def report(self, root, *options, output=None):
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(io.StringIO()):
            status = scan.main(['scan.py', str(root), *options])
        return status, json.loads(output.read_text() if output else stdout.getvalue())

    def fixtures(self, root):
        for name in ('requirements.txt', 'requirements-dev.txt'):
            Path(root, name).write_text(chr(10).join(('shared==1.0', 'shared==2.0', 'clean==3.0', '')))
        Path(root, 'package-lock.json').write_text(json.dumps({
            'packages': {'node_modules/shared': {'version': '1.0'}}}))
        Path(root, 'compose.yaml').write_text(chr(10).join(('services:', '  app:', '    privileged: true', '')))
        return {('PyPI', 'shared', '1.0'): ['TEST-1', 'TEST-1', 'TEST-2'],
                ('PyPI', 'shared', '2.0'): ['TEST-2'],
                ('npm', 'shared', '1.0'): ['TEST-3']}

    def assert_counts(self, report, expected):
        counts = report['summary']['dependency_findings_by_manifest']
        self.assertEqual(counts, expected)
        self.assertEqual(list(counts), sorted(counts))
        self.assertEqual(sum(counts.values()), report['summary']['by_category']['dependency-vuln'])
        canon = json.dumps({k: report[k] for k in ('findings', 'target', 'commit')},
                           sort_keys=True, separators=(',', ':'))
        self.assertEqual(report['manifest_hash'], hashlib.sha256(canon.encode()).hexdigest())

    def test_empty_offline_clean_inventory_and_other_categories(self):
        with tempfile.TemporaryDirectory() as root:
            _, empty = self.report(root, '--no-osv')
            self.fixtures(root)
            with mock.patch.object(scan, 'query_osv', return_value={}) as query:
                _, offline = self.report(root, '--no-osv')
                query.assert_not_called()
                _, clean = self.report(root)
                query.assert_called_once()
            self.assertEqual(offline['summary']['packages_found'], 4)
            self.assertEqual(clean['summary']['config_issues'], 1)
        for report in (empty, offline, clean):
            self.assert_counts(report, {})

    def test_shared_paths_versions_duplicate_ids_and_output_modes(self):
        with tempfile.TemporaryDirectory() as root, tempfile.TemporaryDirectory() as outputs:
            hits = self.fixtures(root)
            detail = {'severity': 'high', 'fixed_in': ['4.0'], 'summary': 'Synthetic advisory'}
            destination = Path(outputs, 'report.json')
            with mock.patch.object(scan, 'query_osv', return_value=hits), \
                    mock.patch.object(scan, 'vuln_details', return_value=detail):
                plain_status, plain = self.report(root)
                failed, triaged = self.report(root, '--triage', '--fail-on', 'high')
                passed, saved = self.report(root, '--triage', '--fail-on', 'critical',
                                            '--compact', '--sort-keys', '--json', str(destination),
                                            output=destination)
            self.assertEqual((plain_status, failed, passed), (0, 1, 0))
        for report in (plain, triaged, saved):
            self.assert_counts(report, {'package-lock.json': 1, 'requirements-dev.txt': 2})
            self.assertEqual(report['findings'], plain['findings'])
            self.assertEqual(report['manifest_hash'], plain['manifest_hash'])
        self.assertEqual(triaged['triage'], saved['triage'])
        self.assertEqual(triaged['triage_summary'], saved['triage_summary'])
        self.assertEqual(triaged['summary']['gate']['matching_findings'], 3)
        self.assertTrue(saved['summary']['gate']['passed'])

    def test_global_and_per_file_caps_count_only_retained_findings(self):
        with tempfile.TemporaryDirectory() as root:
            hits = self.fixtures(root)
            detail = {'severity': 'unknown', 'fixed_in': [], 'summary': 'Synthetic advisory'}
            with mock.patch.object(scan, 'query_osv', return_value=hits), \
                    mock.patch.object(scan, 'vuln_details', return_value=detail):
                with mock.patch.object(scan, 'MAX_FINDINGS', 1):
                    _, capped = self.report(root, '--fail-on', 'low')
                with mock.patch.object(scan, 'MAX_FINDINGS_PER_FILE', 1):
                    _, per_file = self.report(root)
        self.assert_counts(capped, {'requirements-dev.txt': 1})
        self.assert_counts(per_file, {'package-lock.json': 1, 'requirements-dev.txt': 1})
        self.assertTrue(capped['summary']['gate']['passed'])
        for report in (capped, per_file):
            self.assertTrue(report['summary']['truncated']['findings'])
            self.assertEqual(report['summary']['vulnerable_packages'], 3)

    def test_config_in_manifest_does_not_inflate_dependency_count(self):
        with tempfile.TemporaryDirectory() as root:
            Path(root, 'requirements.txt').write_text('sample==1.0' + chr(10))
            def config(_root, _files, add):
                add('config', 'low', 'requirements.txt', 1, 'Synthetic config', 'fixture')
            with mock.patch.object(scan, 'query_osv', return_value={('PyPI', 'sample', '1.0'): ['TEST-1']}), \
                    mock.patch.object(scan, 'vuln_details', return_value={
                        'severity': 'medium', 'fixed_in': [], 'summary': 'Synthetic advisory'}), \
                    mock.patch.object(scan, 'scan_config', side_effect=config):
                _, report = self.report(root)
        self.assertEqual(report['summary']['findings_by_file'], {'requirements.txt': 2})
        self.assert_counts(report, {'requirements.txt': 1})


if __name__ == '__main__':
    unittest.main()
