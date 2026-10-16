"""Explicit pretty formatting preserves report content and gates, offline."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from test_scan import scan


class PrettyJsonTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name) / 'repo'
        self.root.mkdir()
        (self.root / 'docker-compose.yml').write_text(
            chr(10).join(('services:', '  app:', '    privileged: true', '')),
            encoding='utf-8')

    def run_scan(self, *options):
        with mock.patch.object(scan, 'datetime') as clock, \
                contextlib.redirect_stdout(io.StringIO()) as stdout, \
                contextlib.redirect_stderr(io.StringIO()) as stderr:
            clock.now.return_value.strftime.return_value = '2026-01-01T00:00:00Z'
            status = scan.main(['scan.py', str(self.root), '--no-osv', *options])
        return status, stdout.getvalue(), stderr.getvalue()

    def test_pretty_matches_default_with_triage_and_gates(self):
        for gate, expected_status in (('none', 0), ('medium', 1), ('high', 0)):
            with self.subTest(gate=gate):
                expected = self.run_scan('--triage', '--fail-on', gate)
                self.assertEqual(expected[0], expected_status)
                report = json.loads(expected[1])
                self.assertTrue(report['findings'])
                self.assertIn('triage', report)
                self.assertEqual(expected[1], json.dumps(report, indent=2) + chr(10))
                for flags in (('--pretty',), ('--compact', '--pretty'),
                              ('--pretty', '--pretty')):
                    with self.subTest(flags=flags):
                        self.assertEqual(self.run_scan('--triage', '--fail-on', gate,
                                                       *flags), expected)

    def test_last_format_flag_wins_without_state_leakage(self):
        expected = self.run_scan('--compact')
        self.assertEqual(expected[0], 0)
        self.assertEqual(len(expected[1].splitlines()), 1)
        for flags in (('--pretty', '--compact'),
                      ('--compact', '--pretty', '--compact')):
            with self.subTest(flags=flags):
                self.assertEqual(self.run_scan(*flags), expected)
        default = self.run_scan()
        self.assertGreater(len(default[1].splitlines()), 1)
        self.assertEqual(json.loads(default[1]), json.loads(expected[1]))

    def test_pretty_file_and_explicit_stdout(self):
        destination = self.root.parent / 'report.json'
        expected = self.run_scan('--triage', '--fail-on=medium')
        actual = self.run_scan('--compact', '--json', str(destination),
                               '--pretty', '--triage', '--fail-on=medium')
        self.assertEqual(actual[0], 1)
        self.assertEqual(actual[1], '')
        self.assertIn('wrote ' + str(destination), actual[2])
        self.assertEqual(destination.read_text(encoding='utf-8'), expected[1])
        self.assertEqual(self.run_scan('--compact', '--json=-', '--pretty',
                                       '--triage', '--fail-on=medium'), expected)

    def test_help_documents_option_and_order(self):
        status, stdout, stderr = self.run_scan('--help')
        self.assertEqual((status, stderr), (0, ''))
        self.assertIn('--pretty', stdout)
        self.assertIn('last formatting flag wins', stdout)
