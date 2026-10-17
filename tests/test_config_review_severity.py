"""Offline checks for configuration review counts by severity."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from test_scan import scan


class ConfigReviewSeverityTests(unittest.TestCase):
    def test_mixed_categories_and_fixture_configs(self):
        findings = [dict(id=severity, category='config', severity=severity,
                         file='tests/Dockerfile', evidence='synthetic')
                    for severity in ('critical', 'high', 'medium', 'low', 'unknown')]
        findings += [dict(id='missing', category='config', file='.env'),
                     dict(id='secret', category='secret', severity='high',
                          file='settings.txt', evidence='synthetic'),
                     dict(id='dep', category='dependency-vuln', severity='high',
                          file='requirements.txt', fixed_in=['2.0'], package='sample'),
                     dict(id='other', category='other', severity='high')]
        per_id, summary = scan.triage_findings(findings)
        self.assertEqual(summary['config_review_by_severity'],
                         dict(critical=1, high=1, medium=1, low=1, unknown=2))
        self.assertEqual(summary['config'], {'needs_review': 6})
        self.assertEqual(summary['by_action'],
                         dict(upgrade=1, monitor=0, review=8, informational=0))
        for finding in findings[:6]:
            self.assertEqual(per_id[finding['id']], {'action': 'review'})

    def report(self, root, *args):
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(io.StringIO()):
            status = scan.main(['scan.py', str(root), '--no-osv', *args])
        return status, json.loads(stdout.getvalue())

    def test_empty_report_zero_buckets(self):
        with tempfile.TemporaryDirectory() as root:
            status, report = self.report(root, '--triage')
        self.assertEqual(status, 0)
        self.assertEqual(report['triage_summary']['config_review_by_severity'],
                         dict(critical=0, high=0, medium=0, low=0, unknown=0))

    def test_cli_preserves_raw_findings_hash_gate_and_fixture_review(self):
        with tempfile.TemporaryDirectory() as root:
            Path(root, 'tests').mkdir()
            Path(root, 'tests', 'Dockerfile').write_text('FROM scratch' + chr(10))
            Path(root, 'compose.yml').write_text('services:' + chr(10) +
                '  app:' + chr(10) + '    privileged: true' + chr(10))
            plain_status, plain = self.report(root, '--fail-on', 'low')
            status, report = self.report(root, '--triage', '--fail-on', 'low')
        self.assertEqual((plain_status, status), (1, 1))
        self.assertNotIn('triage_summary', plain)
        self.assertEqual(report['findings'], plain['findings'])
        self.assertEqual(report['manifest_hash'], plain['manifest_hash'])
        self.assertEqual(report['summary'], plain['summary'])
        self.assertEqual(report['triage_summary']['config_review_by_severity'],
                         dict(critical=0, high=0, medium=1, low=1, unknown=0))
        self.assertEqual(report['triage_summary']['config'], {'needs_review': 2})
        self.assertTrue(all(t['action'] == 'review' for t in report['triage'].values()))

    def test_limits_count_only_retained_config_findings(self):
        with tempfile.TemporaryDirectory() as root:
            Path(root, 'Dockerfile').write_text('FROM alpine:latest' + chr(10))
            for limit, value in (('MAX_FINDINGS', 1), ('MAX_FINDINGS_PER_FILE', 1),
                                 ('MAX_FINDINGS', 0)):
                with self.subTest(limit=limit, value=value), mock.patch.object(scan, limit, value):
                    _, report = self.report(root, '--triage')
                self.assertTrue(report['summary']['truncated']['findings'])
                self.assertEqual(len(report['findings']), value)
                counts = report['triage_summary']['config_review_by_severity']
                self.assertEqual(sum(counts.values()), value)
                self.assertEqual(counts['low'], value)
                self.assertEqual(report['triage_summary']['config']['needs_review'], value)
