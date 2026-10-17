"""Offline CLI examples for the documented JSON destination semantics."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


SCANNER = Path(__file__).resolve().parents[1] / 'scan.py'


class JsonOutputPathsTests(unittest.TestCase):
    def run_scan(self, cwd, target, destination, inline):
        output_args = ['--json=' + str(destination)] if inline else ['--json', str(destination)]
        result = subprocess.run(
            [sys.executable, str(SCANNER), str(target), '--no-osv', *output_args],
            cwd=cwd, capture_output=True, text=True, timeout=30,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, '')
        self.assertEqual(result.stderr, 'wrote %s (0 findings)' % destination + chr(10))
        return result

    def test_relative_output_is_relative_to_caller_not_target(self):
        for inline in (False, True):
            with self.subTest(inline=inline), tempfile.TemporaryDirectory() as tmp:
                cwd = Path(tmp)
                target = cwd / 'repository'
                target.mkdir()
                # The same relative name in the target must not be overwritten.
                (target / 'report.json').write_text('{}' + chr(10), encoding='utf-8')
                self.run_scan(cwd, 'repository', 'report.json', inline)
                report = json.loads((cwd / 'report.json').read_text(encoding='utf-8'))
                self.assertFalse(report['summary']['osv_enabled'])
                self.assertEqual(report['summary']['files_scanned'], 1)
                self.assertEqual((target / 'report.json').read_text(encoding='utf-8'), '{}' + chr(10))

    def test_absolute_output_is_independent_of_caller_and_target(self):
        for inline in (False, True):
            with self.subTest(inline=inline), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                cwd, target, reports = (root / name for name in ('caller', 'repository', 'reports'))
                for directory in (cwd, target, reports):
                    directory.mkdir()
                destination = reports / 'scan result.json'
                self.run_scan(cwd, target, destination, inline)
                report = json.loads(destination.read_text(encoding='utf-8'))
                self.assertEqual(report['summary']['files_scanned'], 0)
                self.assertEqual(report['findings'], [])
                self.assertEqual(list(cwd.iterdir()), [])
                self.assertEqual(list(target.iterdir()), [])

    def test_existing_output_in_target_is_scanned_before_replacement(self):
        for inline in (False, True):
            with self.subTest(inline=inline), tempfile.TemporaryDirectory() as tmp:
                cwd = Path(tmp)
                target = cwd / 'repository'
                target.mkdir()
                destination = target / 'requirements.txt'
                destination.write_text('example-package==1.2.3' + chr(10), encoding='utf-8')
                self.run_scan(cwd, target, destination, inline)
                report = json.loads(destination.read_text(encoding='utf-8'))
                self.assertEqual(report['summary']['files_scanned'], 1)
                self.assertEqual(report['summary']['lockfiles_parsed'], ['requirements.txt'])
                self.assertEqual(report['summary']['packages_found'], 1)
                self.assertEqual(report['summary']['packages_by_manifest'], {'requirements.txt': 1})
                self.assertFalse(report['summary']['osv_enabled'])
                self.assertEqual(report['findings'], [])


if __name__ == '__main__':
    unittest.main()
