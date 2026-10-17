"""Quiet mode suppresses file-write confirmations, never reports or failures."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from test_scan import scan


class QuietOutputTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='fds-quiet-')
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.root = self.directory / 'repo'
        self.root.mkdir()
        (self.root / 'Dockerfile').write_text('FROM scratch\n')

    def run_scan(self, *options, target=None):
        with mock.patch.object(scan, 'datetime') as clock, \
                contextlib.redirect_stdout(io.StringIO()) as stdout, \
                contextlib.redirect_stderr(io.StringIO()) as stderr:
            clock.now.return_value.strftime.return_value = '2026-01-01T00:00:00Z'
            status = scan.main(['scan.py', str(target or self.root), '--no-osv', *options])
        return status, stdout.getvalue(), stderr.getvalue()

    def test_file_confirmation_only_is_suppressed(self):
        output = self.directory / 'report.json'
        for formatting in ('--pretty', '--compact'):
            for threshold in ('low', 'critical'):
                for destination in (('--json', str(output)), ('--json=' + str(output),)):
                    with self.subTest(formatting=formatting, threshold=threshold,
                                      destination=destination):
                        options = (formatting, '--sort-keys', '--triage',
                                   '--fail-on', threshold, *destination)
                        status, stdout, stderr = self.run_scan(*options)
                        original = output.read_bytes()
                        count = len(json.loads(original)['findings'])
                        self.assertGreater(count, 0)
                        confirmation = 'wrote %s (%d findings)\n' % (output, count)
                        gate = 'gate: findings at or above low severity\n' if threshold == 'low' else ''
                        self.assertEqual((status, stdout, stderr),
                                         (1 if threshold == 'low' else 0, '', confirmation + gate))
                        quiet = self.run_scan(*options, '--quiet')
                        self.assertEqual(quiet, (status, '', gate))
                        self.assertEqual(output.read_bytes(), original)

    def test_stdout_reports_and_gate_diagnostics_are_preserved(self):
        for destination in ((), ('--json', '-'), ('--json=-',)):
            with self.subTest(destination=destination):
                options = ('--triage', '--fail-on', 'low', *destination)
                normal = self.run_scan(*options)
                quiet = self.run_scan('--quiet', *options)
                self.assertEqual(quiet, normal)
                self.assertEqual(quiet[0], 1)
                self.assertTrue(json.loads(quiet[1])['findings'])
                self.assertIn('gate:', quiet[2])

    def test_errors_and_help_are_not_silenced(self):
        for options in (('--unknown',), ('--fail-on=invalid',), ('--json=',), ('--json',)):
            with self.subTest(options=options):
                normal = self.run_scan(*options)
                self.assertEqual(normal[0], 2)
                self.assertTrue(normal[2])
                self.assertEqual(self.run_scan('--quiet', *options), normal)
        missing = self.directory / 'missing'
        normal = self.run_scan(target=missing)
        self.assertEqual(normal[0], 2)
        self.assertIn('not a directory:', normal[2])
        self.assertEqual(self.run_scan('--quiet', target=missing), normal)
        normal = self.run_scan('--help')
        self.assertEqual(self.run_scan('--quiet', '--help'), normal)
        self.assertEqual(normal[0], 0)
        self.assertIn('--quiet', normal[1])

    def test_repetition_invocation_isolation_and_empty_report(self):
        (self.root / 'Dockerfile').unlink()
        output = self.directory / 'empty.json'
        options = ('--json', str(output))
        normal = self.run_scan(*options)
        self.assertIn('(0 findings)', normal[2])
        once = self.run_scan(*options, '--quiet')
        self.assertEqual(once, (0, '', ''))
        self.assertEqual(self.run_scan('--quiet', *options, '--quiet'), once)
        self.assertEqual(json.loads(output.read_text())['findings'], [])
        self.assertEqual(self.run_scan(*options), normal)
