"""Explicit triage disabling preserves raw reports and gates, offline."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from test_scan import scan


class NoTriageTests(unittest.TestCase):
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

    def test_disabling_matches_default_report_and_gate(self):
        for gate, expected_status in (('none', 0), ('medium', 1), ('high', 0)):
            with self.subTest(gate=gate):
                expected = self.run_scan('--fail-on', gate)
                self.assertEqual(expected[0], expected_status)
                self.assertTrue(json.loads(expected[1])['findings'])
                for flags in (('--no-triage',), ('--triage', '--no-triage'),
                              ('--no-triage', '--no-triage')):
                    with self.subTest(flags=flags):
                        self.assertEqual(self.run_scan('--fail-on', gate, *flags), expected)

    def test_last_triage_flag_wins_and_does_not_leak_between_calls(self):
        expected = self.run_scan('--triage')
        self.assertEqual(expected[0], 0)
        triaged = json.loads(expected[1])
        self.assertIn('triage', triaged)
        self.assertIn('triage_summary', triaged)
        for flags in (('--no-triage', '--triage'),
                      ('--triage', '--no-triage', '--triage')):
            with self.subTest(flags=flags):
                self.assertEqual(self.run_scan(*flags), expected)
        raw = json.loads(self.run_scan()[1])
        self.assertNotIn('triage', raw)
        self.assertNotIn('triage_summary', raw)
        self.assertEqual(raw['findings'], triaged['findings'])
        self.assertEqual(raw['manifest_hash'], triaged['manifest_hash'])

    def test_compact_file_output_matches_raw_stdout(self):
        destination = self.root.parent / 'report.json'
        expected = self.run_scan('--compact', '--fail-on=medium')
        actual = self.run_scan('--triage', '--json', str(destination),
                               '--compact', '--no-triage', '--fail-on=medium')
        self.assertEqual(actual[0], 1)
        self.assertEqual(actual[1], '')
        self.assertIn('wrote ' + str(destination), actual[2])
        self.assertEqual(destination.read_text(encoding='utf-8'), expected[1])
        self.assertEqual(len(expected[1].splitlines()), 1)

    def test_help_documents_option_and_order(self):
        status, stdout, stderr = self.run_scan('--help')
        self.assertEqual((status, stderr), (0, ''))
        self.assertIn('--no-triage', stdout)
        self.assertIn('last triage flag wins', stdout)
