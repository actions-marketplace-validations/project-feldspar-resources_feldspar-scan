"""CLI gate precedence and documentation agree, using only local fixtures."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


SCANNER = Path(__file__).resolve().parents[1] / 'scan.py'


class FailOnPrecedenceDocsTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='fds-gate-docs-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        (self.root / '.env').write_text('MODE=development' + chr(10), encoding='utf-8')

    def run_scan(self, *options):
        return subprocess.run(
            [sys.executable, str(SCANNER), str(self.root), '--no-osv', *options],
            capture_output=True, text=True, timeout=10)

    def test_mixed_spellings_use_last_threshold_and_normalize_case(self):
        baseline = json.loads(self.run_scan().stdout)
        for options, threshold, status in (
            (('--fail-on', 'HiGh', '--fail-on=CRITICAL'), 'critical', 0),
            (('--fail-on=CRITICAL', '--fail-on', 'HiGh'), 'high', 1),
            (('--fail-on', 'LOW', '--fail-on=NoNe'), None, 0),
            (('--fail-on=NoNe', '--fail-on', 'MeDiUm'), 'medium', 1),
        ):
            with self.subTest(options=options):
                result = self.run_scan(*options)
                self.assertEqual(result.returncode, status, result.stderr)
                report = json.loads(result.stdout)
                self.assertEqual(report['findings'], baseline['findings'])
                self.assertEqual(report['manifest_hash'], baseline['manifest_hash'])
                if threshold is None:
                    self.assertNotIn('gate', report['summary'])
                else:
                    self.assertEqual(report['summary']['gate'], {
                        'threshold': threshold,
                        'matching_findings': 1 if status else 0,
                        'passed': status == 0,
                    })

    def test_later_valid_threshold_does_not_override_earlier_error(self):
        for options in (
            ('--fail-on=invalid', '--fail-on', 'none'),
            ('--fail-on', 'invalid', '--fail-on=HIGH'),
        ):
            with self.subTest(options=options):
                result = self.run_scan(*options)
                self.assertEqual(result.returncode, 2)
                self.assertEqual(result.stdout, '')
                self.assertIn('--fail-on must be one of', result.stderr)

    def test_help_documents_precedence_and_gate_omission(self):
        result = self.run_scan('--help')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('Values are case-insensitive; the last --fail-on value wins.', result.stdout)
        self.assertIn('A final none omits summary.gate.', result.stdout)


if __name__ == '__main__':
    unittest.main()
