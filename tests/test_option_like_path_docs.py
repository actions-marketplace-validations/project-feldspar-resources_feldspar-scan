"""Documented path spelling selects local directories that resemble CLI flags."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from test_scan import scan


class OptionLikePathDocsTests(unittest.TestCase):
    def invoke(self, cwd, *args):
        return subprocess.run(
            [sys.executable, scan.__file__, *args], cwd=cwd,
            capture_output=True, text=True, timeout=10)

    def test_explicit_relative_paths_scan_option_named_directories(self):
        with tempfile.TemporaryDirectory() as root:
            for name in ('-h', '--help', '--version'):
                with self.subTest(name=name):
                    target = Path(root, name)
                    target.mkdir()
                    (target / '.env').write_text('APP_MODE=production' + chr(10))
                    result = self.invoke(root, './' + name, '--no-osv',
                                         '--fail-on', 'high')
                    self.assertEqual(result.returncode, 1, result.stderr)
                    report = json.loads(result.stdout)
                    self.assertTrue(any(
                        f['file'] == '.env' and f['category'] == 'config'
                        for f in report['findings']))
                    self.assertEqual(report['summary']['errors_count'], 0)

    def test_bare_flags_keep_help_and_version_behavior_with_matching_directory(self):
        with tempfile.TemporaryDirectory() as root:
            for name in ('-h', '--help', '--version'):
                with self.subTest(name=name):
                    Path(root, name).mkdir()
                    result = self.invoke(root, name)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    expected = (scan.SCANNER + ' ' + scan.VERSION
                                if name == '--version' else scan.__doc__.strip())
                    self.assertEqual(result.stdout, expected + chr(10))
                    self.assertEqual(result.stderr, '')

    def test_help_and_readme_explain_explicit_relative_path(self):
        readme = Path(scan.__file__).with_name('README.md').read_text()
        for text in (scan.__doc__, readme):
            with self.subTest(text='help' if text == scan.__doc__ else 'README'):
                self.assertIn('./--help', text)
                self.assertIn('./--version', text)
                self.assertIn('./-h', text)


if __name__ == '__main__':
    unittest.main()
