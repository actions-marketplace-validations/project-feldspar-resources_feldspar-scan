"""Offline checks for the severity breakdown of secrets needing review."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from test_scan import scan


class SecretReviewSeverityTests(unittest.TestCase):
    def test_mixed_review_severities_exclude_informational_and_other_categories(self):
        findings = []
        for severity in ('critical', 'high', 'medium', 'low', 'unknown'):
            findings.append(dict(id=severity, category='secret', severity=severity,
                                 file='settings.txt', evidence='synthetic'))
        for ident, category, path, evidence in (
            ('fixture', 'secret', 'tests/settings.txt', 'synthetic'),
            ('hint', 'secret', 'settings.txt', 'synthetic (example-key?)'),
            ('config', 'config', '.env', 'PORT=…'),
            ('dependency', 'dependency-vuln', 'requirements.txt', ''),
        ):
            findings.append(dict(id=ident, category=category, severity='critical',
                                 file=path, evidence=evidence))
        per_id, summary = scan.triage_findings(findings)
        self.assertEqual(summary['secret_review_by_severity'],
                         dict(critical=1, high=1, medium=1, low=1, unknown=1))
        self.assertEqual(summary['secrets']['needs_review'], 5)
        self.assertEqual(summary['secrets']['likely_false_positive'], 2)
        self.assertEqual(per_id['fixture']['action'], 'informational')
        self.assertEqual(per_id['hint']['action'], 'informational')
        self.assertEqual(per_id['config']['action'], 'review')

    def report(self, root, *args):
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(io.StringIO()):
            status = scan.main(['scan.py', str(root), '--no-osv', *args])
        return status, json.loads(stdout.getvalue())

    def test_empty_report_has_zero_buckets(self):
        with tempfile.TemporaryDirectory() as root:
            status, report = self.report(root, '--triage')
        self.assertEqual(status, 0)
        self.assertEqual(report['triage_summary']['secret_review_by_severity'],
                         dict(critical=0, high=0, medium=0, low=0, unknown=0))

    def test_cli_opt_in_preserves_findings_hash_and_gate(self):
        with tempfile.TemporaryDirectory() as root:
            Path(root, 'settings.txt').write_text(('password="A1b2C3d4E5f6G7h8"' + chr(10)))
            Path(root, 'tests').mkdir()
            Path(root, 'tests', 'settings.txt').write_text(('password="A1b2C3d4E5f6G7h8"' + chr(10)))
            plain_status, plain = self.report(root, '--fail-on', 'medium')
            status, report = self.report(root, '--triage', '--fail-on', 'medium')
        self.assertEqual((plain_status, status), (1, 1))
        self.assertNotIn('triage_summary', plain)
        self.assertEqual(report['findings'], plain['findings'])
        self.assertEqual(report['manifest_hash'], plain['manifest_hash'])
        self.assertEqual(report['triage_summary']['secret_review_by_severity'],
                         dict(critical=0, high=0, medium=1, low=0, unknown=0))

    def test_truncation_counts_only_emitted_secrets(self):
        with tempfile.TemporaryDirectory() as root:
            Path(root, 'settings.txt').write_text(('password="A1b2C3d4E5f6G7h8"' + chr(10)) * 3)
            with mock.patch.object(scan, 'MAX_FINDINGS', 1):
                _, report = self.report(root, '--triage')
        self.assertTrue(report['summary']['truncated']['findings'])
        self.assertEqual(len(report['findings']), 1)
        counts = report['triage_summary']['secret_review_by_severity']
        self.assertEqual(sum(counts.values()), 1)
        self.assertEqual(counts['medium'], 1)
