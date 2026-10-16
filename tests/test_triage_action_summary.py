"""Triage action totals using offline scans and synthetic findings."""
import contextlib
import copy
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from test_scan import scan


class TriageActionSummaryTests(unittest.TestCase):
    def report(self, root, *options):
        output = io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(io.StringIO()):
            status = scan.main(['scan.py', str(root), '--no-osv', *options])
        return status, json.loads(output.getvalue())

    def test_empty_scan_has_all_zero_buckets(self):
        with tempfile.TemporaryDirectory() as root:
            status, report = self.report(root, '--triage')
        self.assertEqual(status, 0)
        self.assertEqual(report['triage_summary']['by_action'], {
            'upgrade': 0, 'monitor': 0, 'review': 0, 'informational': 0})

    def test_mixed_actions_count_findings_not_advisories_or_files(self):
        findings = [
            dict(id='F-001', category='dependency-vuln', file='requirements.txt',
                 package='sample', fixed_in=['2.0'], vuln_ids=['TEST-1', 'TEST-2']),
            dict(id='F-002', category='dependency-vuln', file='requirements.txt',
                 package='other', fixed_in=[]),
            dict(id='F-003', category='secret', file='app.py', evidence='abcd…'),
            dict(id='F-004', category='secret', file='tests/data.py', evidence='abcd…'),
            dict(id='F-005', category='secret', file='app.py', evidence='xxxx… (example-key?)'),
            dict(id='F-006', category='config', file='Dockerfile'),
            dict(id='F-007', category='dependency-vuln', file='tests/requirements.txt',
                 package='scaffold', fixed_in=['2.0']),
        ]
        original = copy.deepcopy(findings)
        per_id, summary = scan.triage_findings(findings)
        self.assertEqual(summary['by_action'], {
            'upgrade': 2, 'monitor': 1, 'review': 2, 'informational': 2})
        self.assertEqual(sum(summary['by_action'].values()), len(findings))
        self.assertEqual([per_id[f['id']]['action'] for f in findings],
                         ['upgrade', 'monitor', 'review', 'informational',
                          'informational', 'review', 'upgrade'])
        self.assertTrue(per_id['F-007']['scaffold'])
        self.assertEqual(findings, original)

    def test_opt_in_preserves_findings_hash_and_gate(self):
        with tempfile.TemporaryDirectory() as root:
            Path(root, '.env').write_text('password="A1b2C3d4E5f6G7h8"')
            plain_status, plain = self.report(root, '--fail-on', 'high')
            triage_status, triaged = self.report(root, '--triage', '--fail-on', 'high')
        self.assertEqual((plain_status, triage_status), (1, 1))
        self.assertNotIn('triage_summary', plain)
        self.assertNotIn('triage', plain)
        self.assertEqual(triaged['triage_summary']['by_action'], {
            'upgrade': 0, 'monitor': 0, 'review': 2, 'informational': 0})
        for key in ('findings', 'manifest_hash', 'summary'):
            self.assertEqual(plain[key], triaged[key])

    def test_truncated_reports_count_only_emitted_findings(self):
        for limit in ('MAX_FINDINGS', 'MAX_FINDINGS_PER_FILE'):
            with self.subTest(limit=limit), tempfile.TemporaryDirectory() as root:
                Path(root, '.env').write_text('password="A1b2C3d4E5f6G7h8"')
                with mock.patch.object(scan, limit, 1):
                    _, report = self.report(root, '--triage')
                self.assertTrue(report['summary']['truncated']['findings'])
                self.assertEqual(len(report['findings']), 1)
                self.assertEqual(report['triage_summary']['by_action'], {
                    'upgrade': 0, 'monitor': 0, 'review': 1, 'informational': 0})
