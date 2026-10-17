"""Timestamp omission is opt-in and leaves report meaning intact, offline."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from test_scan import scan


class NoTimestampTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name) / 'repo'
        self.root.mkdir()
        (self.root / 'compose.yml').write_text('privileged: true' + chr(10), encoding='utf-8')

    def run_scan(self, *options, timestamp='2026-01-01T00:00:00Z'):
        with mock.patch.object(scan, 'datetime') as clock, \
                mock.patch.object(scan, 'query_osv', side_effect=AssertionError('network')), \
                contextlib.redirect_stdout(io.StringIO()) as stdout, \
                contextlib.redirect_stderr(io.StringIO()) as stderr:
            clock.now.return_value.strftime.return_value = timestamp
            status = scan.main(['scan.py', str(self.root), '--no-osv', *options])
        return status, stdout.getvalue(), stderr.getvalue()

    def test_omits_only_timestamp_with_triage_and_gates(self):
        for gate, status in (('none', 0), ('medium', 1), ('high', 0)):
            with self.subTest(gate=gate):
                args = ('--triage', '--fail-on', gate)
                baseline = self.run_scan(*args)
                expected = json.loads(baseline[1])
                self.assertEqual(expected.pop('scanned_at'), '2026-01-01T00:00:00Z')
                actual = self.run_scan(*args, '--no-timestamp')
                self.assertEqual(actual[0], status)
                self.assertEqual(actual[2], baseline[2])
                self.assertEqual(json.loads(actual[1]), expected)
                self.assertTrue(expected['findings'])
                self.assertIn('triage', expected)
                self.assertIn('manifest_hash', expected)

    def test_repetition_and_invocation_isolation(self):
        baseline = self.run_scan()
        once = self.run_scan('--no-timestamp')
        self.assertEqual(once[0], 0)
        self.assertNotIn('scanned_at', json.loads(once[1]))
        self.assertEqual(self.run_scan('--no-timestamp', '--no-timestamp'), once)
        self.assertEqual(self.run_scan(), baseline)

    def test_output_stays_identical_across_clock_changes(self):
        for formatting in ((), ('--compact', '--sort-keys')):
            with self.subTest(formatting=formatting):
                first = self.run_scan('--no-timestamp', *formatting)
                later = self.run_scan('--no-timestamp', *formatting,
                                      timestamp='2027-02-03T04:05:06Z')
                self.assertEqual(first[0], 0)
                self.assertEqual(first, later)
                self.assertNotIn('scanned_at', json.loads(first[1]))
                if formatting:
                    self.assertEqual(len(first[1].splitlines()), 1)
                self.assertNotEqual(self.run_scan(*formatting)[1],
                                    self.run_scan(*formatting, timestamp='later')[1])

    def test_named_file_and_explicit_stdout(self):
        destination = self.root.parent / 'report.json'
        args = ('--no-timestamp', '--compact', '--sort-keys', '--fail-on=medium')
        expected = self.run_scan(*args, '--json=-')
        self.assertEqual(expected[0], 1)
        self.assertNotIn('scanned_at', json.loads(expected[1]))
        actual = self.run_scan(*args, '--json', str(destination))
        self.assertEqual(actual[0], 1)
        self.assertEqual(actual[1], '')
        self.assertEqual(destination.read_text(encoding='utf-8'), expected[1])

    def test_empty_report_and_help(self):
        (self.root / 'compose.yml').unlink()
        status, output, _ = self.run_scan('--no-timestamp')
        self.assertEqual(status, 0)
        report = json.loads(output)
        self.assertEqual(report['findings'], [])
        self.assertNotIn('scanned_at', report)
        status, output, error = self.run_scan('--help')
        self.assertEqual((status, error), (0, ''))
        self.assertIn('--no-timestamp', output)
