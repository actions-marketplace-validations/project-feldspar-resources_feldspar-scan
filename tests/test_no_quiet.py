"""The last confirmation flag wins without changing reports or diagnostics."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from test_scan import scan


class NoQuietTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='fds-no-quiet-')
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.root = self.directory / 'repo'
        self.root.mkdir()
        (self.root / 'Dockerfile').write_text('FROM scratch' + chr(10))

    def run_scan(self, *options, target=None):
        with mock.patch.object(scan, 'datetime') as clock, \
                mock.patch.object(scan, 'query_osv') as query, \
                contextlib.redirect_stdout(io.StringIO()) as stdout, \
                contextlib.redirect_stderr(io.StringIO()) as stderr:
            clock.now.return_value.strftime.return_value = '2026-01-01T00:00:00Z'
            status = scan.main(['scan.py', str(target or self.root), '--no-osv', *options])
            query.assert_not_called()
        return status, stdout.getvalue(), stderr.getvalue()

    def test_last_flag_controls_only_file_confirmation(self):
        output = self.directory / 'report.json'
        for formatting in ('--pretty', '--compact'):
            for threshold in ('low', 'critical'):
                for destination in (('--json', str(output)), ('--json=' + str(output),)):
                    options = (formatting, '--sort-keys', '--triage',
                               '--fail-on', threshold, *destination)
                    normal = self.run_scan(*options)
                    original = output.read_bytes()
                    count = len(json.loads(original)['findings'])
                    self.assertGreater(count, 0)
                    confirmation = ('wrote %s (%d findings)' % (output, count)) + chr(10)
                    gate = 'gate: findings at or above low severity' + chr(10) if threshold == 'low' else ''
                    self.assertEqual(normal, (1 if threshold == 'low' else 0, '', confirmation + gate))
                    for flags, quiet in (
                            (('--no-quiet',), False),
                            (('--quiet', '--no-quiet'), False),
                            (('--quiet', '--no-quiet', '--no-quiet'), False),
                            (('--no-quiet', '--quiet'), True),
                            (('--quiet', '--no-quiet', '--quiet'), True)):
                        with self.subTest(options=options, flags=flags):
                            actual = self.run_scan(*options, *flags)
                            self.assertEqual(actual, (normal[0], '', gate) if quiet else normal)
                            self.assertEqual(output.read_bytes(), original)

    def test_stdout_reports_and_gate_are_unchanged(self):
        for destination in ((), ('--json', '-'), ('--json=-',)):
            with self.subTest(destination=destination):
                options = ('--triage', '--fail-on', 'low', *destination)
                normal = self.run_scan(*options)
                self.assertEqual(normal[0], 1)
                self.assertTrue(json.loads(normal[1])['findings'])
                self.assertEqual(self.run_scan('--quiet', *options, '--no-quiet'), normal)
                self.assertNotIn('wrote ', normal[2])

    def test_errors_and_help_are_preserved(self):
        for options in (('--unknown',), ('--fail-on=invalid',), ('--json=',)):
            with self.subTest(options=options):
                normal = self.run_scan(*options)
                self.assertEqual(normal[0], 2)
                self.assertTrue(normal[2])
                self.assertEqual(self.run_scan('--quiet', '--no-quiet', *options), normal)
        missing = self.directory / 'missing'
        normal = self.run_scan(target=missing)
        self.assertEqual(normal[0], 2)
        self.assertEqual(self.run_scan('--quiet', '--no-quiet', target=missing), normal)
        help_result = self.run_scan('--help')
        self.assertEqual(self.run_scan('--quiet', '--no-quiet', '--help'), help_result)
        self.assertIn('--no-quiet', help_result[1])
        self.assertIn('last confirmation flag wins', help_result[1])

    def test_empty_report_and_invocation_isolation(self):
        (self.root / 'Dockerfile').unlink()
        output = self.directory / 'empty.json'
        options = ('--json', str(output))
        normal = self.run_scan(*options)
        self.assertIn('(0 findings)', normal[2])
        self.assertEqual(self.run_scan(*options, '--quiet'), (0, '', ''))
        self.assertEqual(self.run_scan(*options, '--quiet', '--no-quiet'), normal)
        self.assertEqual(json.loads(output.read_text())['findings'], [])
        self.assertEqual(self.run_scan(*options, '--no-quiet', '--quiet'), (0, '', ''))
        self.assertEqual(self.run_scan(*options), normal)
