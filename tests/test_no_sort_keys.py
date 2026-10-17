"""Callers can restore default JSON key order after wrapper-provided flags."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from test_scan import scan


class NoSortKeysTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='fds-no-sort-keys-')
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.root = self.directory / 'repo'
        self.root.mkdir()
        (self.root / 'Dockerfile').write_text('FROM scratch' + chr(10))

    def run_scan(self, *options):
        with mock.patch.object(scan, 'datetime') as clock, \
                mock.patch.object(scan, 'http_json', side_effect=AssertionError('offline')), \
                contextlib.redirect_stdout(io.StringIO()) as stdout, \
                contextlib.redirect_stderr(io.StringIO()) as stderr:
            clock.now.return_value.strftime.return_value = '2026-01-01T00:00:00Z'
            status = scan.main(['scan.py', str(self.root), '--no-osv', *options])
        return status, stdout.getvalue(), stderr.getvalue()

    def test_restores_exact_output_in_both_formats_with_triage_and_gates(self):
        for formatting in ('--pretty', '--compact'):
            for threshold in ('low', 'critical'):
                with self.subTest(formatting=formatting, threshold=threshold):
                    options = (formatting, '--triage', '--fail-on', threshold)
                    baseline = self.run_scan(*options)
                    restored = self.run_scan(*options, '--sort-keys', '--no-sort-keys')
                    self.assertEqual(baseline[0], 1 if threshold == 'low' else 0)
                    self.assertEqual(restored, baseline)
                    self.assertEqual(next(iter(json.loads(restored[1]))), 'scanner')

    def test_last_key_order_flag_wins_and_state_does_not_leak(self):
        baseline = self.run_scan()
        sorted_output = self.run_scan('--sort-keys')
        self.assertNotEqual(baseline[1], sorted_output[1])
        for options, expected in (
                (('--no-sort-keys',), baseline),
                (('--sort-keys', '--no-sort-keys', '--no-sort-keys'), baseline),
                (('--no-sort-keys', '--sort-keys'), sorted_output),
                (('--sort-keys', '--no-sort-keys', '--sort-keys'), sorted_output)):
            with self.subTest(options=options):
                self.assertEqual(self.run_scan(*options), expected)
        self.assertEqual(self.run_scan(), baseline)

    def test_named_file_and_explicit_stdout_restore_same_bytes(self):
        output = self.directory / 'report.json'
        for formatting in ('--pretty', '--compact'):
            with self.subTest(formatting=formatting):
                options = (formatting, '--triage')
                baseline = self.run_scan(*options)
                restored = (*options, '--sort-keys', '--no-sort-keys')
                self.assertEqual(self.run_scan(*restored, '--json', '-'), baseline)
                status, stdout, stderr = self.run_scan(*restored, '--json', str(output))
                self.assertEqual(status, 0)
                self.assertEqual(stdout, '')
                self.assertEqual(output.read_text(), baseline[1])
                self.assertIn('wrote ' + str(output), stderr)

    def test_empty_scan_and_help(self):
        (self.root / 'Dockerfile').unlink()
        baseline = self.run_scan()
        self.assertEqual(json.loads(baseline[1])['findings'], [])
        self.assertEqual(self.run_scan('--sort-keys', '--no-sort-keys'), baseline)
        status, help_text, _ = self.run_scan('--help')
        self.assertEqual(status, 0)
        self.assertIn('--no-sort-keys', help_text)
        self.assertIn('last key-order flag wins', help_text)
