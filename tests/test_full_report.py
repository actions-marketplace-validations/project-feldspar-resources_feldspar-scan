"""Explicit full reports override abbreviated output without changing scan results."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from test_scan import scan


class FullReportTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name) / 'repo'
        self.root.mkdir()
        (self.root / 'Dockerfile').write_text('FROM scratch' + chr(10), encoding='utf-8')

    def run_scan(self, *options):
        with contextlib.redirect_stdout(io.StringIO()) as stdout, \
                contextlib.redirect_stderr(io.StringIO()) as stderr:
            status = scan.main(['scan.py', str(self.root), '--no-osv',
                                '--no-commit', '--no-timestamp', *options])
        return status, stdout.getvalue(), stderr.getvalue()

    def test_last_detail_flag_wins_without_enabling_triage(self):
        for triage in ((), ('--triage',), ('--triage', '--no-triage')):
            with self.subTest(triage=triage):
                baseline = self.run_scan(*triage)
                self.assertTrue(json.loads(baseline[1])['findings'])
                for flags in (('--full-report',),
                              ('--summary-only', '--full-report'),
                              ('--full-report', '--summary-only', '--full-report'),
                              ('--full-report', '--full-report')):
                    self.assertEqual(self.run_scan(*triage, *flags), baseline)
                abbreviated = self.run_scan(*triage, '--summary-only')
                self.assertNotIn('findings', json.loads(abbreviated[1]))
                self.assertNotIn('triage', json.loads(abbreviated[1]))
                self.assertEqual(self.run_scan(*triage, '--full-report', '--summary-only'),
                                 abbreviated)
                self.assertEqual(self.run_scan(*triage), baseline)

    def test_destinations_formatting_gates_and_diagnostics_are_preserved(self):
        report_path = self.root.parent / 'report.json'
        for output in ((), ('--json', '-'), ('--json=' + str(report_path),)):
            for formatting in ((), ('--compact', '--sort-keys'), ('--indent', '0')):
                for severity, status in (('low', 1), ('critical', 0)):
                    with self.subTest(output=output, formatting=formatting, severity=severity):
                        flags = (*output, *formatting, '--triage', '--fail-on', severity)
                        baseline = self.run_scan(*flags)
                        self.assertEqual(baseline[0], status)
                        expected = report_path.read_text() if len(output) == 1 else baseline[1]
                        self.assertTrue(json.loads(expected)['triage'])
                        result = self.run_scan(*flags, '--summary-only', '--full-report')
                        self.assertEqual(result, baseline)
                        actual = report_path.read_text() if len(output) == 1 else result[1]
                        self.assertEqual(actual, expected)

    def test_errors_and_empty_findings_are_restored(self):
        (self.root / 'Dockerfile').unlink()
        (self.root / 'package-lock.json').write_text('{}', encoding='utf-8')
        parser = mock.Mock(side_effect=OSError('synthetic read failure'))
        with mock.patch.dict(scan.DEP_HANDLERS, {'package-lock.json': parser}):
            baseline = self.run_scan('--triage')
            report = json.loads(baseline[1])
            self.assertEqual(report['findings'], [])
            self.assertEqual(report['triage'], {})
            self.assertTrue(report['errors'])
            self.assertEqual(self.run_scan('--triage', '--summary-only', '--full-report'),
                             baseline)

    def test_help_describes_override(self):
        status, output, error = self.run_scan('--help')
        self.assertEqual((status, error), (0, ''))
        self.assertIn('--full-report', output)
        self.assertIn('last report-detail flag wins', output)
