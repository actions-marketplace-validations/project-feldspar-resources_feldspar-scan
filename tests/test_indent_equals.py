"""The equals spelling shares indentation semantics without changing report data."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from test_scan import scan


class IndentEqualsTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name) / 'repo'
        self.root.mkdir()
        (self.root / 'Dockerfile').write_text('FROM scratch' + chr(10), encoding='utf-8')

    def run_scan(self, *options):
        with mock.patch.object(scan, 'datetime') as clock, \
                mock.patch.object(scan, 'query_osv') as query, \
                contextlib.redirect_stdout(io.StringIO()) as out, \
                contextlib.redirect_stderr(io.StringIO()) as err:
            clock.now.return_value.strftime.return_value = '2026-01-01T00:00:00Z'
            status = scan.main(['scan.py', str(self.root), '--no-osv', *options])
            query.assert_not_called()
        return status, out.getvalue(), err.getvalue()

    def test_all_widths_preserve_bytes_report_triage_and_gate(self):
        for threshold, status in [('none', 0), ('low', 1), ('critical', 0)]:
            flags = ('--triage', '--sort-keys', '--fail-on', threshold)
            baseline = self.run_scan(*flags)
            self.assertEqual(baseline[0], status)
            report = json.loads(baseline[1])
            self.assertTrue(report['findings'])
            for width in range(9):
                with self.subTest(threshold=threshold, width=width):
                    result = self.run_scan(*flags, '--indent=' + str(width))
                    self.assertEqual(result, self.run_scan(*flags, '--indent', str(width)))
                    self.assertEqual(result[0], status)
                    self.assertEqual(json.loads(result[1]), report)

    def test_mixed_order_and_invocation_isolation(self):
        default = self.run_scan()
        for flags, expected in [
                (('--indent=4', '--pretty'), default),
                (('--indent=4', '--compact'), self.run_scan('--compact')),
                (('--compact', '--indent=4'), self.run_scan('--indent', '4')),
                (('--indent=4', '--indent', '1'), self.run_scan('--indent', '1')),
                (('--indent', '1', '--indent=4', '--indent=4'), self.run_scan('--indent', '4'))]:
            with self.subTest(flags=flags):
                self.assertEqual(self.run_scan(*flags), expected)
        self.assertEqual(self.run_scan(), default)

    def test_invalid_values_fail_before_scan_or_output(self):
        destination = self.root.parent / 'report.json'
        destination.write_text('preserve me', encoding='utf-8')
        for value in ['', '9', '-1', '+2', '02', '1.5', ' 2', '２', '2=3', '--pretty']:
            with self.subTest(value=value), mock.patch.object(scan, 'walk') as walk:
                result = self.run_scan('--json', str(destination), '--indent=' + value, '--indent=2')
                self.assertEqual(result, (2, '', '--indent must be one digit from 0 to 8' + chr(10)))
                walk.assert_not_called()
                self.assertEqual(destination.read_text(encoding='utf-8'), 'preserve me')

    def test_file_stdout_empty_scan_and_help(self):
        (self.root / 'Dockerfile').unlink()
        expected = self.run_scan('--indent', '0', '--unicode-json')
        self.assertEqual(json.loads(expected[1])['findings'], [])
        destination = self.root.parent / 'report.json'
        result = self.run_scan('--indent=0', '--unicode-json', '--json=' + str(destination))
        self.assertEqual(result[:2], (0, ''))
        self.assertEqual(destination.read_text(encoding='utf-8'), expected[1])
        self.assertEqual(self.run_scan('--indent=0', '--unicode-json', '--json=-'), expected)
        self.assertIn('--indent=N', self.run_scan('--help')[1])
