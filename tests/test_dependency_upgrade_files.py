"""Upgrade-file triage counts use retained findings and synthetic advisories."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from test_scan import scan


class DependencyUpgradeFilesTests(unittest.TestCase):
    def report(self, root, *flags):
        with contextlib.redirect_stdout(io.StringIO()) as output, \
                contextlib.redirect_stderr(io.StringIO()):
            status = scan.main(['scan.py', str(root), *flags])
        return status, json.loads(output.getvalue())

    def test_unique_paths_scaffolds_missing_paths_and_mixed_categories(self):
        paths = ['app/requirements.txt', 'app/requirements.txt',
                 'tests/requirements.txt', None, '']
        findings = [dict(id=str(i), category='dependency-vuln', file=path,
                         package='sample', fixed_in=['2.0', '3.0'])
                    for i, path in enumerate(paths)]
        findings += [dict(id='M', category='dependency-vuln', file='go.mod'),
                     dict(id='C', category='config', file='compose.yaml'),
                     dict(id='S', category='secret', file='settings.txt', evidence='omitted')]
        before = json.dumps(findings, sort_keys=True)
        actions, summary = scan.triage_findings(findings)
        self.assertEqual(summary['dependency_files_needing_upgrade'], 2)
        self.assertEqual(summary['dependency'], {
            'upgradeable': 5, 'monitor_only': 1, 'in_scaffold_lockfiles': 1})
        self.assertEqual(actions['2']['action'], 'upgrade')
        self.assertTrue(actions['2']['scaffold'])
        self.assertEqual(actions['M']['action'], 'monitor')
        self.assertEqual(json.dumps(findings, sort_keys=True), before)

    def test_empty_offline_and_monitor_only_reports(self):
        self.assertEqual(scan.triage_findings([])[1]['dependency_files_needing_upgrade'], 0)
        with tempfile.TemporaryDirectory() as root:
            Path(root, 'requirements.txt').write_text('sample==1.0' + chr(10))
            with mock.patch.object(scan, 'query_osv', side_effect=AssertionError('offline')):
                _, plain = self.report(root, '--no-osv')
                _, triaged = self.report(root, '--no-osv', '--triage')
            self.assertNotIn('triage_summary', plain)
            self.assertEqual(triaged['triage_summary']['dependency_files_needing_upgrade'], 0)
            with mock.patch.object(scan, 'query_osv', return_value={
                    ('PyPI', 'sample', '1.0'): ['TEST-1']}), \
                    mock.patch.object(scan, 'vuln_details', return_value={
                        'severity': 'unknown', 'summary': 'Synthetic', 'fixed_in': []}):
                _, report = self.report(root, '--triage')
            self.assertEqual(report['triage_summary']['dependency_files_needing_upgrade'], 0)
            self.assertEqual(report['triage_summary']['dependency']['monitor_only'], 1)

    def test_cli_representative_paths_limits_and_unchanged_raw_report(self):
        hits = {('PyPI', name, '1.0'): ['TEST-1'] for name in ('sample-a', 'sample-b', 'sample-c')}
        with tempfile.TemporaryDirectory() as root:
            Path(root, 'requirements.txt').write_text(chr(10).join(['sample-a==1.0', 'sample-b==1.0', '']))
            Path(root, 'tests').mkdir()
            # sample-a is deduplicated; sample-c keeps this scaffold represented.
            Path(root, 'tests/requirements.txt').write_text(chr(10).join(['sample-a==1.0', 'sample-c==1.0', '']))
            with mock.patch.object(scan, 'query_osv', return_value=hits), \
                    mock.patch.object(scan, 'vuln_details', return_value={
                        'severity': 'high', 'summary': 'Synthetic', 'fixed_in': ['2.0']}):
                status, plain = self.report(root, '--fail-on', 'high')
                triage_status, triaged = self.report(root, '--fail-on', 'high', '--triage')
                self.assertEqual((status, triage_status), (1, 1))
                self.assertEqual(triaged['triage_summary']['dependency_files_needing_upgrade'], 2)
                self.assertEqual(triaged['triage_summary']['dependency']['upgradeable'], 3)
                for field in ('findings', 'summary', 'manifest_hash'):
                    self.assertEqual(plain[field], triaged[field])
                for limit, value, expected in [('MAX_FINDINGS', 1, 1),
                                               ('MAX_FINDINGS_PER_FILE', 1, 2),
                                               ('MAX_FINDINGS', 0, 0)]:
                    with self.subTest(limit=limit, value=value), mock.patch.object(scan, limit, value):
                        _, limited = self.report(root, '--triage')
                    self.assertTrue(limited['summary']['truncated']['findings'])
                    self.assertEqual(limited['triage_summary']['dependency_files_needing_upgrade'], expected)
