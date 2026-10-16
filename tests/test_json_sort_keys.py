"""Sorted JSON output is opt-in and preserves report data and gate behavior."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from test_scan import scan


class SortedJsonTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='fds-sort-keys-')
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.root = self.directory / 'repo'
        self.root.mkdir()
        (self.root / 'Dockerfile').write_text('FROM scratch' + chr(10))

    def run_scan(self, *options):
        with mock.patch.object(scan, 'datetime') as clock, \
                contextlib.redirect_stdout(io.StringIO()) as stdout, \
                contextlib.redirect_stderr(io.StringIO()) as stderr:
            clock.now.return_value.strftime.return_value = '2026-01-01T00:00:00Z'
            status = scan.main(['scan.py', str(self.root), '--no-osv', *options])
        return status, stdout.getvalue(), stderr.getvalue()

    def assert_sorted_objects(self, value):
        if isinstance(value, dict):
            self.assertEqual(list(value), sorted(value))
            for child in value.values():
                self.assert_sorted_objects(child)
        elif isinstance(value, list):
            for child in value:
                self.assert_sorted_objects(child)

    def test_stdout_preserves_report_and_gate_in_both_formats(self):
        for compact in (False, True):
            for threshold in ('low', 'critical'):
                with self.subTest(compact=compact, threshold=threshold):
                    options = ['--triage', '--fail-on', threshold]
                    if compact:
                        options.append('--compact')
                    status, original, errors = self.run_scan(*options)
                    result, ordered, diagnostics = self.run_scan(*options, '--sort-keys')
                    self.assertEqual(status, 1 if threshold == 'low' else 0)
                    self.assertEqual(result, status)
                    self.assertEqual(diagnostics, errors)
                    self.assertEqual(json.loads(ordered), json.loads(original))
                    self.assertNotEqual(ordered, original)
                    self.assert_sorted_objects(json.loads(ordered))
                    self.assertEqual(len(ordered.splitlines()), len(original.splitlines()))
                    self.assertTrue(ordered.endswith(chr(10)))

    def test_named_file_and_explicit_stdout_match(self):
        output = self.directory / 'sorted.json'
        for compact in (False, True):
            with self.subTest(compact=compact):
                options = ['--sort-keys', '--triage', '--fail-on', 'low']
                if compact:
                    options.append('--compact')
                expected, text, _ = self.run_scan(*options, '--json', '-')
                status, stdout, stderr = self.run_scan(*options, '--json', str(output))
                self.assertEqual(status, expected)
                self.assertEqual(status, 1)
                self.assertEqual(stdout, '')
                self.assertEqual(output.read_text(), text)
                self.assertIn('wrote ' + str(output), stderr)
                self.assertIn('gate: findings at or above low severity', stderr)
                self.assert_sorted_objects(json.loads(text))

    def test_repeated_flag_is_idempotent_and_does_not_affect_later_invocations(self):
        _, baseline, _ = self.run_scan()
        status, once, _ = self.run_scan('--sort-keys')
        repeated, twice, _ = self.run_scan('--sort-keys', '--sort-keys')
        _, later, _ = self.run_scan()
        self.assertEqual((status, repeated), (0, 0))
        self.assertEqual(once, twice)
        self.assertEqual(later, baseline)
        self.assertEqual(baseline, json.dumps(json.loads(baseline), indent=2) + chr(10))
        self.assertEqual(next(iter(json.loads(baseline))), 'scanner')

    def test_help_describes_sorting(self):
        status, text, _ = self.run_scan('--help')
        self.assertEqual(status, 0)
        self.assertIn('--sort-keys', text)
