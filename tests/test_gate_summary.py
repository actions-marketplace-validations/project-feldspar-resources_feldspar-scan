"""Offline report/exit-code agreement for the optional severity gate."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from test_scan import scan


class GateSummaryTests(unittest.TestCase):
    def report(self, root, *options):
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            status = scan.main(['scan.py', str(root), '--no-osv', *options])
        return status, json.loads(stdout.getvalue()), stderr.getvalue()

    @staticmethod
    def emit(severities):
        def detector(root, files, add):
            for line, severity in enumerate(severities, 1):
                add('secret', severity, 'settings.txt', line,
                    summary='Synthetic finding', evidence='omitted')
        return detector

    def test_every_threshold_counts_raw_findings_and_preserves_identity(self):
        with tempfile.TemporaryDirectory() as root, mock.patch.object(
                scan, 'scan_secrets', side_effect=self.emit(
                    ['unknown', 'low', 'medium', 'high', 'critical', 'high'])):
            _, plain, _ = self.report(root)
            self.assertNotIn('gate', plain['summary'])
            for threshold, count in [('CRITICAL', 1), ('high', 3), ('medium', 4), ('low', 5)]:
                with self.subTest(threshold=threshold):
                    status, report, stderr = self.report(root, '--fail-on', threshold, '--triage')
                    self.assertEqual(status, 1)
                    self.assertEqual(report['summary']['gate'], {
                        'threshold': threshold.lower(), 'matching_findings': count, 'passed': False})
                    self.assertEqual(stderr.splitlines(),
                                     ['gate: findings at or above %s severity' % threshold.lower()])
                    self.assertEqual(report['findings'], plain['findings'])
                    self.assertEqual(report['manifest_hash'], plain['manifest_hash'])

    def test_empty_unknown_and_below_threshold_reports_pass(self):
        for severities in ([], ['unknown'], ['low', 'medium']):
            with self.subTest(severities=severities), tempfile.TemporaryDirectory() as root:
                with mock.patch.object(scan, 'scan_secrets', side_effect=self.emit(severities)):
                    status, report, stderr = self.report(root, '--fail-on', 'high')
                self.assertEqual(status, 0)
                self.assertEqual(stderr, '')
                self.assertEqual(report['summary']['gate'], {
                    'threshold': 'high', 'matching_findings': 0, 'passed': True})

    def test_limits_count_only_retained_findings(self):
        for limit in ('MAX_FINDINGS', 'MAX_FINDINGS_PER_FILE'):
            with self.subTest(limit=limit), tempfile.TemporaryDirectory() as root:
                with mock.patch.object(scan, limit, 1), mock.patch.object(
                        scan, 'scan_secrets', side_effect=self.emit(['low', 'critical'])):
                    status, report, _ = self.report(root, '--fail-on', 'high')
                self.assertEqual(status, 0)
                self.assertTrue(report['summary']['truncated']['findings'])
                self.assertEqual(report['summary']['gate']['matching_findings'], 0)
                self.assertTrue(report['summary']['gate']['passed'])

    def test_named_output_records_gate_for_real_detector(self):
        with tempfile.TemporaryDirectory() as root, tempfile.TemporaryDirectory() as output:
            Path(root, 'settings.txt').write_text('password="A1b2C3d4E5f6G7h8"')
            report_path = Path(output, 'report.json')
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(io.StringIO()):
                status = scan.main(['scan.py', root, '--no-osv', '--fail-on', 'medium',
                                    '--json', str(report_path)])
            report = json.loads(report_path.read_text())
        self.assertEqual(stdout.getvalue(), '')
        self.assertEqual(status, 1)
        self.assertEqual(len(report['findings']), 1)
        self.assertEqual(report['summary']['gate'], {
            'threshold': 'medium', 'matching_findings': 1, 'passed': False})
