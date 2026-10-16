"""Inline severity thresholds use the same gate and output as split arguments."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


SCANNER = Path(__file__).resolve().parents[1] / 'scan.py'


class FailOnEqualsTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='fds-fail-equals-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.repo = self.root / 'repo'
        self.repo.mkdir()
        # The missing USER check yields a low-severity config finding.
        (self.repo / 'Dockerfile').write_text('FROM scratch' + chr(10), encoding='utf-8')

    def run_scan(self, *options):
        return subprocess.run(
            [sys.executable, str(SCANNER), str(self.repo), '--no-osv', *options],
            capture_output=True, text=True, timeout=10)

    def report(self, output):
        report = json.loads(output)
        report.pop('scanned_at')
        return report

    def test_all_thresholds_match_split_form_with_triage_and_compact(self):
        for severity in ('critical', 'high', 'medium', 'low', 'none', 'MeDiUm', 'NONE'):
            for options in ((), ('--triage', '--compact')):
                with self.subTest(severity=severity, options=options):
                    expected = self.run_scan('--fail-on', severity, *options)
                    actual = self.run_scan('--fail-on=' + severity, *options)
                    self.assertEqual(actual.returncode,
                                     int(severity.lower() == 'low'), actual.stderr)
                    self.assertEqual(actual.returncode, expected.returncode)
                    self.assertEqual(actual.stderr, expected.stderr)
                    self.assertEqual(self.report(actual.stdout), self.report(expected.stdout))
                    self.assertEqual(len(actual.stdout.splitlines()), len(expected.stdout.splitlines()))

    def test_last_threshold_wins_across_both_spellings(self):
        for options, severity in (
                (('--fail-on=low', '--fail-on', 'none'), 'none'),
                (('--fail-on', 'low', '--fail-on=none'), 'none'),
                (('--fail-on=none', '--fail-on', 'medium'), 'medium'),
                (('--fail-on', 'none', '--fail-on=medium'), 'medium')):
            with self.subTest(options=options):
                expected = self.run_scan('--fail-on', severity)
                actual = self.run_scan(*options)
                self.assertEqual(actual.returncode, expected.returncode, actual.stderr)
                self.assertEqual(actual.stderr, expected.stderr)
                self.assertEqual(self.report(actual.stdout), self.report(expected.stdout))

    def test_gated_report_still_written_to_named_file(self):
        output = self.root / 'result.json'
        expected = self.run_scan('--fail-on', 'low', '--triage')
        actual = self.run_scan('--fail-on=low', '--json', str(output), '--triage')
        self.assertEqual(actual.returncode, 1, actual.stderr)
        self.assertEqual(actual.stdout, '')
        self.assertTrue(actual.stderr.endswith(expected.stderr))
        self.assertEqual(self.report(output.read_text()), self.report(expected.stdout))

    def test_empty_and_invalid_thresholds_fail_before_scanning_or_cloning(self):
        spec = importlib.util.spec_from_file_location('fail_on_equals_scan', SCANNER)
        scan = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(scan)
        for value in ('', 'unknown', 'high=low', ' high', '--help'):
            for target in (str(self.repo), 'https://example.invalid/repo.git'):
                with self.subTest(value=value, target=target), \
                        mock.patch.object(scan, 'walk') as walk, \
                        mock.patch.object(scan.subprocess, 'run') as run, \
                        contextlib.redirect_stdout(io.StringIO()) as stdout, \
                        contextlib.redirect_stderr(io.StringIO()) as stderr:
                    result = scan.main(['scan.py', target, '--fail-on=' + value, '--no-osv'])
                    self.assertEqual(result, 2)
                    self.assertEqual(stdout.getvalue(), '')
                    self.assertEqual(stderr.getvalue(),
                                     '--fail-on must be one of critical|high|medium|low|none' + chr(10))
                    walk.assert_not_called()
                    run.assert_not_called()

    def test_help_documents_inline_spelling(self):
        actual = self.run_scan('--help')
        self.assertEqual(actual.returncode, 0)
        self.assertIn('--fail-on=SEV', actual.stdout)
