"""Distinct line-addressable configuration locations in offline reports."""
import contextlib
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from test_scan import scan

NL = chr(10)


class ConfigLineSummaryTests(unittest.TestCase):
    def report(self, root, *options):
        output = io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(io.StringIO()):
            status = scan.main(['scan.py', str(root), '--no-osv', *options])
        return status, json.loads(output.getvalue())

    def test_empty_and_file_wide_findings_have_zero_lines(self):
        with tempfile.TemporaryDirectory() as root:
            status, empty = self.report(root)
            self.assertEqual(status, 0)
            self.assertEqual(empty['summary']['config_lines'], 0)
            Path(root, 'Dockerfile').write_text('FROM scratch' + NL)
            status, report = self.report(root, '--fail-on', 'low')
        self.assertEqual(status, 1)
        self.assertEqual(report['summary']['config_issues'], 1)
        self.assertIsNone(report['findings'][0]['line'])
        self.assertEqual(report['summary']['config_lines'], 0)

    def test_shared_lines_multiple_files_and_triage(self):
        with tempfile.TemporaryDirectory() as root:
            for directory in ('one', 'two'):
                path = Path(root, directory)
                path.mkdir()
                # Two config findings share line 2; root USER is another line.
                (path / 'Dockerfile').write_text(
                    'FROM scratch' + NL + 'ENV PASSWORD=short TOKEN=short' + NL + 'USER root' + NL)
            status, plain = self.report(root, '--fail-on', 'high')
            triage_status, triaged = self.report(root, '--fail-on', 'high', '--triage')
        self.assertEqual((status, triage_status), (1, 1))
        self.assertEqual(plain['summary']['config_issues'], 6)
        self.assertEqual(plain['summary']['config_lines'], 4)
        self.assertEqual(plain['summary']['gate'], {
            'threshold': 'high', 'matching_findings': 4, 'passed': False})
        self.assertEqual(plain['summary'], triaged['summary'])
        self.assertEqual(plain['findings'], triaged['findings'])
        self.assertEqual(plain['manifest_hash'], triaged['manifest_hash'])
        canonical = json.dumps({k: plain[k] for k in ('findings', 'target', 'commit')},
                               sort_keys=True, separators=(',', ':'))
        self.assertEqual(plain['manifest_hash'], hashlib.sha256(canonical.encode()).hexdigest())

    def test_secret_only_report_does_not_count_as_config(self):
        with tempfile.TemporaryDirectory() as root:
            Path(root, 'settings.txt').write_text('password="your_placeholder_value"' + NL)
            status, report = self.report(root)
        self.assertEqual(status, 0)
        self.assertEqual(report['summary']['secret_hits'], 1)
        self.assertEqual(report['summary']['config_lines'], 0)

    def test_caps_count_only_retained_config_locations(self):
        for limit in ('MAX_FINDINGS', 'MAX_FINDINGS_PER_FILE'):
            with self.subTest(limit=limit), tempfile.TemporaryDirectory() as root:
                Path(root, 'Dockerfile').write_text(
                    'FROM scratch' + NL + 'ENV PASSWORD=short TOKEN=short' + NL + 'USER root' + NL)
                with mock.patch.object(scan, limit, 2):
                    status, report = self.report(root, '--fail-on', 'high')
            self.assertEqual(status, 1)
            self.assertTrue(report['summary']['truncated']['findings'])
            self.assertEqual(report['summary']['config_issues'], 2)
            self.assertEqual({f['line'] for f in report['findings']}, {2})
            self.assertEqual(report['summary']['config_lines'], 1)
