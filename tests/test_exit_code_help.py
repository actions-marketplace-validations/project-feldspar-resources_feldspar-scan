"""CLI exit-code documentation and behavior, with offline synthetic inputs."""
import contextlib
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

from test_scan import scan


class ExitCodeHelpTests(unittest.TestCase):
    def invoke(self, *args):
        output, errors = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
            status = scan.main(['scan.py', *args])
        return status, output.getvalue(), errors.getvalue()

    def test_help_explains_exit_codes_and_coverage(self):
        for args in ((), ('-h',), ('--help',)):
            with self.subTest(args=args):
                status, output, errors = self.invoke(*args)
                self.assertEqual(status, 0)
                self.assertEqual(errors, '')
                for text in ('0 no severity gate fired', '1 gate fired (--fail-on)',
                             '2 bad args / bad path', '3 clone failed',
                             'does not certify a complete assessment',
                             'errors', 'summary.notes', 'summary.lockfiles_parsed',
                             'summary.packages_found'):
                    self.assertIn(text, output)

    def test_findings_without_gate_return_zero_and_failed_gate_keeps_report(self):
        with tempfile.TemporaryDirectory() as root:
            Path(root, '.env').write_text('PORT=8080', encoding='utf-8')
            status, output, _ = self.invoke(root, '--no-osv')
            gated_status, gated_output, errors = self.invoke(
                root, '--no-osv', '--fail-on', 'high')
        plain, gated = json.loads(output), json.loads(gated_output)
        self.assertEqual(status, 0)
        self.assertEqual(len(plain['findings']), 1)
        self.assertEqual(gated_status, 1)
        self.assertIn('gate:', errors)
        self.assertEqual(plain['findings'], gated['findings'])
        self.assertEqual(plain['manifest_hash'], gated['manifest_hash'])

    def test_bad_args_and_path_return_two_without_report(self):
        with tempfile.TemporaryDirectory() as root:
            for args in ((root, '--unknown'), (root, '--fail-on', 'invalid'),
                         (str(Path(root, 'missing')),)):
                with self.subTest(args=args):
                    status, output, errors = self.invoke(*args)
                    self.assertEqual(status, 2)
                    self.assertEqual(output, '')
                    self.assertTrue(errors)

    def test_clone_failure_returns_three_without_report(self):
        with tempfile.TemporaryDirectory() as root, \
                mock.patch.object(scan.tempfile, 'mkdtemp', return_value=root), \
                mock.patch.object(scan.subprocess, 'run', return_value=
                                  subprocess.CompletedProcess([], 1, '', 'synthetic clone failure')) as run:
            status, output, errors = self.invoke('https://example.invalid/repo.git', '--no-osv')
        run.assert_called_once()
        self.assertEqual(status, 3)
        self.assertEqual(output, '')
        self.assertEqual(errors, 'synthetic clone failure')

    def test_degraded_lookup_can_return_zero_with_errors(self):
        with tempfile.TemporaryDirectory() as root:
            Path(root, 'requirements.txt').write_text('example-package==1.0', encoding='utf-8')
            with mock.patch.object(scan, 'http_json', side_effect=OSError('synthetic offline')) as request:
                status, output, _ = self.invoke(root, '--fail-on', 'low')
        request.assert_called_once()
        report = json.loads(output)
        self.assertEqual(status, 0)
        self.assertEqual(report['findings'], [])
        self.assertEqual(report['summary']['packages_found'], 1)
        self.assertEqual(report['summary']['lockfiles_parsed'], ['requirements.txt'])
        self.assertEqual(report['errors'], ['osv querybatch: synthetic offline'])
