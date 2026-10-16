"""Dependency triage scope counts use synthetic findings and offline advisories."""
import contextlib
import copy
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from test_scan import scan


class DependencyTriageScopeTests(unittest.TestCase):
    def test_action_counts_exclude_only_existing_scaffold_paths(self):
        findings = []
        for path in ('requirements.txt', 'service/requirements.txt',
                     'tests/requirements.txt', 'examples/requirements.txt',
                     'fixtures/requirements.txt'):
            for fixed in ([], ['2.0', '3.0']):
                findings.append(dict(id=str(len(findings)), category='dependency-vuln',
                                     file=path, package='synthetic-package', fixed_in=fixed))
        findings.extend([
            dict(id='config', category='config', file='Dockerfile'),
            dict(id='secret', category='secret', file='app.py'),
        ])
        before = copy.deepcopy(findings)
        per_id, summary = scan.triage_findings(findings)
        self.assertEqual(findings, before)
        self.assertEqual(summary['dependency'], {
            'upgradeable': 5, 'monitor_only': 5, 'in_scaffold_lockfiles': 6,
        })
        for action, field in (('upgrade', 'upgradeable'), ('monitor', 'monitor_only')):
            expected = sum(t['action'] == action and not t.get('scaffold', False)
                           for t in per_id.values())
            self.assertEqual(summary['dependency_outside_scaffold_lockfiles'][field], expected)

    def test_empty_and_scaffold_only_keep_zero_buckets(self):
        for findings in ([], [dict(id='1', category='dependency-vuln',
                                  file='tests/requirements.txt', fixed_in=['2.0'])]):
            with self.subTest(findings=findings):
                _, summary = scan.triage_findings(findings)
                self.assertEqual(summary['dependency_outside_scaffold_lockfiles'],
                                 {'upgradeable': 0, 'monitor_only': 0})

    def report(self, root, *options):
        output = io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(io.StringIO()):
            status = scan.main(['scan.py', root, *options])
        return status, json.loads(output.getvalue())

    def test_cli_opt_in_preserves_findings_hash_and_gate(self):
        with tempfile.TemporaryDirectory() as root:
            Path(root, 'requirements.txt').write_text("""synthetic-package==1.0
""")
            with mock.patch.object(scan, 'query_osv', return_value={
                    ('PyPI', 'synthetic-package', '1.0'): ['TEST-1']}), \
                    mock.patch.object(scan, 'vuln_details', return_value={
                        'severity': 'high', 'summary': 'Synthetic', 'fixed_in': ['2.0']}):
                plain_status, plain = self.report(root, '--fail-on', 'high')
                triage_status, triaged = self.report(root, '--fail-on', 'high', '--triage')
        self.assertEqual((plain_status, triage_status), (1, 1))
        self.assertNotIn('triage_summary', plain)
        for field in ('findings', 'manifest_hash', 'summary'):
            self.assertEqual(plain[field], triaged[field])
        self.assertEqual(triaged['triage_summary']['dependency_outside_scaffold_lockfiles'],
                         {'upgradeable': 1, 'monitor_only': 0})

    def test_caps_count_only_emitted_dependency_findings(self):
        for limit in ('MAX_FINDINGS', 'MAX_FINDINGS_PER_FILE'):
            with self.subTest(limit=limit), tempfile.TemporaryDirectory() as root:
                Path(root, 'requirements.txt').write_text("""synthetic-a==1.0
synthetic-b==1.0
""")
                with mock.patch.object(scan, 'query_osv', return_value={
                        ('PyPI', name, '1.0'): ['TEST-1']
                        for name in ('synthetic-a', 'synthetic-b')}), \
                        mock.patch.object(scan, 'vuln_details', return_value={
                            'severity': 'high', 'summary': 'Synthetic', 'fixed_in': ['2.0']}), \
                        mock.patch.object(scan, limit, 1):
                    _, report = self.report(root, '--triage')
                self.assertTrue(report['summary']['truncated']['findings'])
                self.assertEqual(len(report['findings']), 1)
                self.assertEqual(report['triage_summary']['dependency_outside_scaffold_lockfiles'],
                                 {'upgradeable': 1, 'monitor_only': 0})
