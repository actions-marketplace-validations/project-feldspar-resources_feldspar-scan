"""Help after a target exits without starting scanner work (entirely offline)."""
import contextlib
import io
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from test_scan import scan


class TargetHelpTests(unittest.TestCase):
    def invoke(self, *args):
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.ExitStack() as stack:
            stack.enter_context(contextlib.redirect_stdout(stdout))
            stack.enter_context(contextlib.redirect_stderr(stderr))
            for obj, name in ((scan, 'walk'), (scan, 'http_json'),
                              (scan.subprocess, 'run'), (scan.tempfile, 'mkdtemp'),
                              (scan.os.path, 'isdir')):
                stack.enter_context(mock.patch.object(
                    obj, name, side_effect=AssertionError(name + ' called')))
            status = scan.main(['scan.py', *args])
        return status, stdout.getvalue(), stderr.getvalue()

    def test_help_after_missing_or_remote_target_matches_standalone(self):
        expected = self.invoke('--help')
        self.assertEqual(expected, (0, scan.__doc__.strip() + chr(10), ''))
        for target in ('missing-synthetic-directory',
                       'https://example.invalid/synthetic/repo.git'):
            for flag in ('-h', '--help'):
                with self.subTest(target=target, flag=flag):
                    self.assertEqual(self.invoke(target, flag), expected)

    def test_help_after_options_does_not_write_report(self):
        with tempfile.TemporaryDirectory() as root:
            report = Path(root, 'report.json')
            for flag in ('-h', '--help'):
                with self.subTest(flag=flag):
                    self.assertEqual(self.invoke(
                        root, '--json', str(report), '--no-osv', '--triage',
                        '--fail-on', 'high', flag), self.invoke('--help'))
                    self.assertFalse(report.exists())

    def test_help_like_json_operand_remains_a_filename(self):
        # --json consumes the next token even when it resembles a help flag.
        for operand in ('-h', '--help'):
            with self.subTest(operand=operand):
                status, stdout, stderr = self.invoke(
                    'synthetic-target', '--json', operand, '--unknown')
                self.assertEqual((status, stdout, stderr),
                                 (2, '', 'unknown arg: --unknown' + chr(10)))

    def test_invalid_option_before_help_still_fails(self):
        status, stdout, stderr = self.invoke(
            'synthetic-target', '--fail-on', 'invalid', '--help')
        self.assertEqual(status, 2)
        self.assertEqual(stdout, '')
        self.assertIn('--fail-on must be one of', stderr)


if __name__ == '__main__':
    unittest.main()
