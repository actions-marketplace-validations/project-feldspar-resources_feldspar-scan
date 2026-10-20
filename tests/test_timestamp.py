"""Explicit timestamp restoration supports layered CLI options, offline."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from test_scan import scan


class TimestampTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name) / 'repo'
        self.root.mkdir()
        (self.root / 'compose.yml').write_text('privileged: true' + chr(10), encoding='utf-8')

    def run_scan(self, *options):
        with mock.patch.object(scan, 'datetime') as clock, \
                mock.patch.object(scan, 'http_json', side_effect=AssertionError('network')), \
                mock.patch.object(scan, 'git_head', return_value=None), \
                contextlib.redirect_stdout(io.StringIO()) as stdout, \
                contextlib.redirect_stderr(io.StringIO()) as stderr:
            clock.now.return_value.strftime.return_value = '2026-01-02T03:04:05Z'
            status = scan.main(['scan.py', str(self.root), '--no-osv', *options])
        return status, stdout.getvalue(), stderr.getvalue()

    def test_last_timestamp_flag_wins_and_calls_are_isolated(self):
        baseline = self.run_scan()
        omitted = self.run_scan('--no-timestamp')
        self.assertEqual(baseline[0], 0)
        self.assertEqual(json.loads(baseline[1])['scanned_at'], '2026-01-02T03:04:05Z')
        self.assertNotIn('scanned_at', json.loads(omitted[1]))
        for flags in (('--timestamp',), ('--timestamp', '--timestamp'),
                      ('--no-timestamp', '--timestamp')):
            with self.subTest(flags=flags):
                self.assertEqual(self.run_scan(*flags), baseline)
        self.assertEqual(self.run_scan('--timestamp', '--no-timestamp'), omitted)
        self.assertEqual(self.run_scan('--no-timestamp', '--timestamp', '--no-timestamp'), omitted)
        self.assertEqual(self.run_scan(), baseline)

    def test_preserves_report_bytes_triage_and_gates(self):
        for formatting in ((), ('--compact', '--sort-keys'), ('--indent', '4')):
            for gate, expected_status in (('none', 0), ('medium', 1), ('high', 0)):
                with self.subTest(formatting=formatting, gate=gate):
                    args = (*formatting, '--triage', '--fail-on', gate)
                    baseline = self.run_scan(*args)
                    self.assertEqual(baseline[0], expected_status)
                    report = json.loads(baseline[1])
                    self.assertTrue(report['findings'])
                    self.assertIn('triage', report)
                    self.assertEqual(self.run_scan(*args, '--no-timestamp', '--timestamp'), baseline)

    def test_file_stdout_and_summary_only(self):
        destination = self.root.parent / 'report.json'
        args = ('--no-timestamp', '--timestamp', '--summary-only', '--triage',
                '--compact', '--fail-on=medium')
        baseline = self.run_scan(*args, '--json=-')
        self.assertEqual(baseline[0], 1)
        report = json.loads(baseline[1])
        self.assertIn('scanned_at', report)
        self.assertNotIn('findings', report)
        self.assertNotIn('triage', report)
        self.assertIn('triage_summary', report)
        actual = self.run_scan(*args, '--quiet', '--json', str(destination))
        self.assertEqual(actual, (baseline[0], '', baseline[2]))
        self.assertEqual(destination.read_text(encoding='utf-8'), baseline[1])

    def test_empty_report_and_help(self):
        (self.root / 'compose.yml').unlink()
        baseline = self.run_scan()
        self.assertEqual(json.loads(baseline[1])['findings'], [])
        self.assertEqual(self.run_scan('--no-timestamp', '--timestamp'), baseline)
        status, output, error = self.run_scan('--help')
        self.assertEqual((status, error), (0, ''))
        self.assertIn('--timestamp', output)
        self.assertIn('last timestamp flag wins', output)
