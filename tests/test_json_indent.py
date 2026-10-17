"""Configurable JSON whitespace keeps scan results unchanged, entirely offline."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from test_scan import scan


class JsonIndentTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name) / 'repo'
        self.root.mkdir()
        (self.root / 'compose.yaml').write_text(
            chr(10).join(('services:', '  app:', '    privileged: true', '')), encoding='utf-8')

    def run_scan(self, *options):
        with mock.patch.object(scan, 'datetime') as clock, \
                mock.patch.object(scan, 'query_osv') as query, \
                contextlib.redirect_stdout(io.StringIO()) as out, \
                contextlib.redirect_stderr(io.StringIO()) as err:
            clock.now.return_value.strftime.return_value = '2026-01-01T00:00:00Z'
            status = scan.main(['scan.py', str(self.root), '--no-osv', *options])
            query.assert_not_called()
        return status, out.getvalue(), err.getvalue()

    def test_widths_preserve_report_triage_hash_and_gate(self):
        for threshold, expected_status in [('none', 0), ('medium', 1), ('high', 0)]:
            flags = ('--triage', '--fail-on', threshold, '--sort-keys')
            baseline = self.run_scan(*flags)
            report = json.loads(baseline[1])
            self.assertTrue(report['findings'])
            for width in range(9):
                with self.subTest(threshold=threshold, width=width):
                    status, out, err = self.run_scan(*flags, '--indent', str(width))
                    self.assertEqual(status, expected_status)
                    self.assertEqual(err, baseline[2])
                    self.assertEqual(json.loads(out), report)
                    self.assertEqual(out, json.dumps(report, indent=width, sort_keys=True) + chr(10))

    def test_last_format_flag_wins_and_calls_are_isolated(self):
        default = self.run_scan()
        compact = self.run_scan('--compact')
        four = self.run_scan('--indent', '4')
        self.assertEqual(self.run_scan('--indent', '4', '--pretty'), default)
        self.assertEqual(self.run_scan('--indent', '4', '--compact'), compact)
        self.assertEqual(self.run_scan('--compact', '--indent', '4'), four)
        self.assertEqual(self.run_scan('--pretty', '--indent', '1', '--indent', '4'), four)
        self.assertEqual(self.run_scan(), default)

    def test_named_file_stdout_and_empty_scan(self):
        (self.root / 'compose.yaml').unlink()
        expected = self.run_scan('--indent', '0')
        self.assertEqual(json.loads(expected[1])['findings'], [])
        destination = self.root.parent / 'report.json'
        status, out, err = self.run_scan('--indent', '0', '--json', str(destination))
        self.assertEqual((status, out), (0, ''))
        self.assertIn('wrote ' + str(destination), err)
        self.assertEqual(destination.read_text(), expected[1])
        self.assertEqual(self.run_scan('--json=-', '--indent', '0'), expected)

    def test_invalid_widths_stop_before_scanning_or_writing(self):
        destination = self.root.parent / 'report.json'
        for values in [(), ('',), ('-1',), ('9',), ('1.5',), ('+2',), ('02',),
                       (' 2',), ('２',), ('--compact',), ('1000000',)]:
            with self.subTest(values=values), mock.patch.object(scan, 'walk') as walk:
                status, out, err = self.run_scan('--json', str(destination), '--indent', *values)
                self.assertEqual((status, out), (2, ''))
                self.assertIn('--indent must be one digit from 0 to 8', err)
                walk.assert_not_called()
                self.assertFalse(destination.exists())

    def test_help_documents_width_and_precedence(self):
        status, out, err = self.run_scan('--help')
        self.assertEqual((status, err), (0, ''))
        self.assertIn('--indent N', out)
        self.assertIn('0 through 8', out)
        self.assertIn('last formatting flag wins', out)
