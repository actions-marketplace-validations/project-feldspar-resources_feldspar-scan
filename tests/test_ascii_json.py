"""ASCII output can override a wrapper's Unicode setting without changing data."""
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


SCANNER = Path(__file__).resolve().parents[1] / 'scan.py'


class AsciiJsonTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='fds-ascii-')
        self.addCleanup(temporary.cleanup)
        self.cwd = Path(temporary.name)
        self.repo = self.cwd / 'repo'
        self.path = 'café-東京-🚀/Dockerfile'
        dockerfile = self.repo / self.path
        dockerfile.parent.mkdir(parents=True)
        dockerfile.write_text('FROM scratch' + chr(10), encoding='utf-8')

    def scan(self, *flags, ascii_stdout=False):
        return subprocess.run(
            [sys.executable, str(SCANNER), str(self.repo), '--no-osv', *flags],
            cwd=self.cwd, capture_output=True, text=True, encoding='utf-8',
            env=dict(os.environ, PYTHONIOENCODING='ascii' if ascii_stdout else 'utf-8'),
            timeout=10)

    def content(self, text):
        report = json.loads(text)
        self.assertEqual(report['findings'][0]['file'], self.path)
        report.pop('scanned_at')
        return report

    def test_flag_precedence_preserves_content_and_gate(self):
        orders = [(['--ascii-json'], True),
                  (['--unicode-json', '--ascii-json'], True),
                  (['--ascii-json', '--unicode-json'], False),
                  (['--unicode-json', '--ascii-json', '--ascii-json'], True)]
        for formatting in ([], ['--compact', '--sort-keys']):
            for threshold, status in (('critical', 0), ('low', 1)):
                common = [*formatting, '--triage', '--fail-on', threshold]
                baseline = self.scan(*common)
                self.assertEqual(baseline.returncode, status, baseline.stderr)
                expected = self.content(baseline.stdout)
                for flags, escaped in orders:
                    with self.subTest(formatting=formatting, threshold=threshold, flags=flags):
                        result = self.scan(*common, *flags, '--json=-')
                        self.assertEqual(result.returncode, status, result.stderr)
                        self.assertEqual(result.stderr, baseline.stderr)
                        self.assertEqual(self.content(result.stdout), expected)
                        self.assertEqual(result.stdout.isascii(), escaped)
                        self.assertTrue(result.stdout.endswith(chr(10)))

    def test_ascii_stdout_and_named_file(self):
        expected = self.content(self.scan().stdout)
        for destination in ([], ['--json', 'report.json']):
            with self.subTest(destination=destination):
                result = self.scan('--unicode-json', '--ascii-json', *destination,
                                   ascii_stdout=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                output = ((self.cwd / 'report.json').read_text(encoding='ascii')
                          if destination else result.stdout)
                self.assertTrue(output.isascii())
                self.assertEqual(self.content(output), expected)
                if destination:
                    self.assertEqual(result.stdout, '')

    def test_same_process_resets_encoding_default(self):
        spec = importlib.util.spec_from_file_location('scan_ascii_test', SCANNER)
        scanner = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(scanner)
        for flags, escaped in ((['--ascii-json', '--unicode-json'], False),
                               ([], True), (['--unicode-json', '--ascii-json'], True)):
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                status = scanner.main(['scan.py', str(self.repo), '--no-osv', *flags])
            self.assertEqual(status, 0)
            self.assertEqual(output.getvalue().isascii(), escaped)
            self.content(output.getvalue())

    def test_help_describes_override(self):
        result = self.scan('--help')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('--ascii-json', result.stdout)
        self.assertIn('last encoding flag wins', result.stdout)
