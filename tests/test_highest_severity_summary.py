"""Highest emitted severity, tested offline with synthetic findings and values."""
import contextlib
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from test_scan import scan


class HighestSeveritySummaryTests(unittest.TestCase):
    def report(self, root, *options):
        output = io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(io.StringIO()):
            status = scan.main(['scan.py', str(root), '--no-osv', *options])
        return status, json.loads(output.getvalue())

    def test_empty_report_has_null_severity(self):
        with tempfile.TemporaryDirectory() as root:
            status, report = self.report(root, '--fail-on', 'low')
        self.assertEqual(status, 0)
        self.assertIsNone(report['summary']['highest_severity'])
        self.assertEqual(report['findings'], [])

    def test_all_severity_levels_and_unknown_gate_behavior(self):
        # Inject detector output to cover every rating without provider requests.
        for severity in ('critical', 'high', 'medium', 'low', 'unknown'):
            with self.subTest(severity=severity), tempfile.TemporaryDirectory() as root:
                def emit(root, files, add):
                    add('secret', severity, 'settings.txt', 1,
                        summary='Synthetic finding', evidence='omitted')
                with mock.patch.object(scan, 'scan_secrets', side_effect=emit):
                    status, report = self.report(root, '--fail-on', 'low')
            self.assertEqual(report['summary']['highest_severity'], severity)
            self.assertEqual(status, 0 if severity == 'unknown' else 1)

    def test_mixed_real_detectors_preserve_triage_hash_and_gates(self):
        with tempfile.TemporaryDirectory() as root:
            Path(root, '.env').write_text('password="A1b2C3d4E5f6G7h8"\n')
            Path(root, 'Dockerfile').write_text('FROM scratch\n')
            status, plain = self.report(root, '--fail-on', 'critical')
            gated_status, triaged = self.report(root, '--triage', '--fail-on', 'high')
        self.assertEqual({f['severity'] for f in plain['findings']}, {'high', 'medium', 'low'})
        self.assertEqual(plain['summary']['highest_severity'], 'high')
        self.assertEqual(triaged['summary']['highest_severity'], 'high')
        self.assertEqual((status, gated_status), (0, 1))
        self.assertEqual(plain['findings'], triaged['findings'])
        self.assertEqual(plain['manifest_hash'], triaged['manifest_hash'])
        canonical = json.dumps({k: plain[k] for k in ('findings', 'target', 'commit')},
                               sort_keys=True, separators=(',', ':'))
        self.assertEqual(plain['manifest_hash'], hashlib.sha256(canonical.encode()).hexdigest())

    def test_unknown_does_not_hide_a_rated_finding(self):
        with tempfile.TemporaryDirectory() as root:
            def emit(root, files, add):
                for line, severity in enumerate(('unknown', 'low'), 1):
                    add('secret', severity, 'settings.txt', line,
                        summary='Synthetic finding', evidence='omitted')
            with mock.patch.object(scan, 'scan_secrets', side_effect=emit):
                status, report = self.report(root, '--fail-on', 'low')
        self.assertEqual(report['summary']['highest_severity'], 'low')
        self.assertEqual(report['summary']['by_severity']['unknown'], 1)
        self.assertEqual(status, 1)

    def test_truncation_reports_only_emitted_findings(self):
        # Generic medium hit is emitted before the .env high config finding.
        for limit in ('MAX_FINDINGS', 'MAX_FINDINGS_PER_FILE'):
            with self.subTest(limit=limit), tempfile.TemporaryDirectory() as root:
                Path(root, '.env').write_text('password="A1b2C3d4E5f6G7h8"\n')
                with mock.patch.object(scan, limit, 1):
                    status, report = self.report(root, '--fail-on', 'high')
            self.assertTrue(report['summary']['truncated']['findings'])
            self.assertEqual(len(report['findings']), 1)
            self.assertEqual(report['summary']['highest_severity'], 'medium')
            self.assertEqual(status, 0)
