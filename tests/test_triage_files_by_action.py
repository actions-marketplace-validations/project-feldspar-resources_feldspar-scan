"""Distinct-file action counts; all fixtures and scans are offline."""
import contextlib
import copy
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from test_scan import scan


class TriageFilesByActionTests(unittest.TestCase):
    def report(self, root, *options):
        output = io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(io.StringIO()):
            status = scan.main(['scan.py', str(root), '--no-osv', *options])
        return status, json.loads(output.getvalue())

    def test_empty_scan_has_zero_file_counts(self):
        with tempfile.TemporaryDirectory() as root:
            status, report = self.report(root, '--triage')
        self.assertEqual(status, 0)
        self.assertEqual(report['triage_summary']['files_by_action'], {
            'upgrade': 0, 'monitor': 0, 'review': 0, 'informational': 0})

    def test_deduplicates_within_actions_but_not_across_actions(self):
        findings = [
            dict(id='1', category='dependency-vuln', file='requirements.txt',
                 package='one', fixed_in=['2', '3'], vuln_ids=['TEST-1', 'TEST-2']),
            dict(id='2', category='dependency-vuln', file='requirements.txt',
                 package='two', fixed_in=['4']),
            dict(id='3', category='dependency-vuln', file='requirements.txt',
                 package='three', fixed_in=[]),
            dict(id='4', category='dependency-vuln', file='tests/requirements.txt',
                 package='four', fixed_in=['5']),
            dict(id='5', category='secret', file='app.py', evidence='redacted'),
            dict(id='6', category='config', file='app.py'),
            dict(id='7', category='secret', file='app.py', evidence='(example-key?)'),
            dict(id='8', category='secret', file='tests/data.py', evidence='redacted'),
            dict(id='9', category='secret', file='tests/data.py', evidence='redacted'),
            dict(id='10', category='config', file='Dockerfile'),
        ]
        original = copy.deepcopy(findings)
        per_id, summary = scan.triage_findings(findings)
        self.assertEqual(summary['files_by_action'], {
            'upgrade': 2, 'monitor': 1, 'review': 2, 'informational': 2})
        self.assertEqual(summary['by_action'], {
            'upgrade': 3, 'monitor': 1, 'review': 3, 'informational': 3})
        self.assertTrue(per_id['4']['scaffold'])
        self.assertEqual(findings, original)
        self.assertEqual(scan.triage_findings(list(reversed(findings)))[1]['files_by_action'],
                         summary['files_by_action'])

    def test_opt_in_preserves_raw_report_and_gate(self):
        with tempfile.TemporaryDirectory() as root:
            Path(root, '.env').write_text('password="A1b2C3d4E5f6G7h8"')
            plain_status, plain = self.report(root, '--fail-on', 'high')
            status, report = self.report(root, '--triage', '--fail-on', 'high')
        self.assertEqual((plain_status, status), (1, 1))
        self.assertNotIn('triage_summary', plain)
        self.assertEqual(report['triage_summary']['by_action']['review'], 2)
        self.assertEqual(report['triage_summary']['files_by_action'], {
            'upgrade': 0, 'monitor': 0, 'review': 1, 'informational': 0})
        for key in ('findings', 'manifest_hash', 'summary'):
            self.assertEqual(report[key], plain[key])

    def test_pathless_findings_keep_actions_without_inventing_a_file(self):
        findings = [dict(id='1', category='config'),
                    dict(id='2', category='config', file=None),
                    dict(id='3', category='config', file='')]
        per_id, summary = scan.triage_findings(findings)
        self.assertEqual(summary['by_action']['review'], 3)
        self.assertEqual(summary['files_by_action']['review'], 0)
        self.assertTrue(all(t['action'] == 'review' for t in per_id.values()))

    def test_truncation_counts_only_emitted_files(self):
        with tempfile.TemporaryDirectory() as root:
            for directory in ('first', 'second'):
                Path(root, directory).mkdir()
                Path(root, directory, 'Dockerfile').write_text('FROM ubuntu:22.04' + chr(10))
            with mock.patch.object(scan, 'MAX_FINDINGS', 1):
                _, report = self.report(root, '--triage')
        self.assertTrue(report['summary']['truncated']['findings'])
        self.assertEqual(len(report['findings']), 1)
        self.assertEqual(report['triage_summary']['files_by_action'], {
            'upgrade': 0, 'monitor': 0, 'review': 1, 'informational': 0})
