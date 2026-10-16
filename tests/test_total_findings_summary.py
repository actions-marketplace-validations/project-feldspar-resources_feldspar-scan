"""Offline report-contract coverage for the emitted finding total."""
import contextlib
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from test_scan import scan


class TotalFindingsSummaryTests(unittest.TestCase):
    def report(self, root, *options):
        output = io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(io.StringIO()):
            status = scan.main(['scan.py', str(root), '--no-osv', *options])
        return status, json.loads(output.getvalue())

    def assert_total(self, report, expected):
        self.assertEqual(report['summary']['total_findings'], expected)
        self.assertEqual(len(report['findings']), expected)
        self.assertEqual(sum(report['summary']['by_category'].values()), expected)
        self.assertEqual(sum(report['summary']['by_severity'].values()), expected)
        canonical = json.dumps({key: report[key] for key in ('findings', 'target', 'commit')},
                               sort_keys=True, separators=(',', ':'))
        self.assertEqual(report['manifest_hash'], hashlib.sha256(canonical.encode()).hexdigest())

    def test_empty_report(self):
        with tempfile.TemporaryDirectory() as root:
            status, report = self.report(root)
        self.assertEqual(status, 0)
        self.assert_total(report, 0)
        self.assertTrue(report['summary']['notes'])

    def test_all_categories_and_severities(self):
        def synthetic_findings(root, files, add):
            for category in ('secret', 'config', 'dependency-vuln'):
                for severity in ('critical', 'high', 'medium', 'low', 'unknown'):
                    add(category, severity, 'fixture.txt', 1,
                        summary='Synthetic finding', evidence='fixture')
        with tempfile.TemporaryDirectory() as root, mock.patch.object(
                scan, 'scan_secrets', synthetic_findings):
            status, report = self.report(root, '--fail-on', 'critical')
        self.assertEqual(status, 1)
        self.assert_total(report, 15)
        self.assertEqual(report['summary']['gate']['matching_findings'], 3)
        self.assertEqual(report['summary']['files_with_findings'], 1)

    def test_real_config_findings_with_triage_and_gate(self):
        with tempfile.TemporaryDirectory() as root:
            Path(root, '.env').write_text('PORT=8080' + chr(10))
            Path(root, 'compose.yml').write_text(chr(10).join(['services:', '  app:', '    privileged: true', '']))
            status, plain = self.report(root)
            gated, triaged = self.report(root, '--triage', '--compact', '--fail-on', 'high')
        self.assertEqual(status, 0)
        self.assertEqual(gated, 1)
        self.assert_total(plain, 2)
        self.assert_total(triaged, 2)
        self.assertEqual(plain['findings'], triaged['findings'])
        self.assertEqual(plain['manifest_hash'], triaged['manifest_hash'])
        self.assertEqual(triaged['summary']['gate'],
                         {'threshold': 'high', 'matching_findings': 1, 'passed': False})

    def test_caps_count_only_emitted_findings(self):
        def synthetic_findings(root, files, add):
            for name in ('one.txt', 'one.txt', 'two.txt', 'two.txt'):
                add('config', 'low', name, 1, summary='Synthetic finding', evidence='fixture')
        with tempfile.TemporaryDirectory() as root, mock.patch.object(
                scan, 'scan_secrets', synthetic_findings):
            for limit, expected in (('MAX_FINDINGS', 1), ('MAX_FINDINGS_PER_FILE', 2)):
                with self.subTest(limit=limit), mock.patch.object(scan, limit, 1):
                    _, report = self.report(root)
                    self.assert_total(report, expected)
                    self.assertTrue(report['summary']['truncated']['findings'])
