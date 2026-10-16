"""Exercise the documented traversal boundary with synthetic, offline fixtures."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from test_scan import scan


class DirectoryExclusionDocsTests(unittest.TestCase):
    def populate(self, directory):
        directory.mkdir(parents=True, exist_ok=True)
        (directory / 'settings.txt').write_text(
            'password="A1b2C3d4E5f6G7h8"' + chr(10), encoding='utf-8')
        (directory / '.env').write_text('SETTING=enabled' + chr(10), encoding='utf-8')
        (directory / 'requirements.txt').write_text(
            'synthetic-package==1.2.3' + chr(10), encoding='utf-8')

    def report(self, root):
        output = io.StringIO()
        with mock.patch.object(scan, 'query_osv', side_effect=AssertionError('offline')), \
                contextlib.redirect_stdout(output), contextlib.redirect_stderr(io.StringIO()):
            status = scan.main(['scan.py', str(root), '--no-osv', '--fail-on', 'medium'])
        return status, json.loads(output.getvalue())

    def test_excluded_names_hide_all_scan_inputs_at_each_depth(self):
        names = ('.git', 'node_modules', 'vendor', 'dist', 'build', '.venv', 'venv',
                 '__pycache__', '.mypy_cache', '.tox', '.next', 'target')
        for parent in ('', 'src/nested'):
            for name in names:
                with self.subTest(parent=parent, name=name), tempfile.TemporaryDirectory() as root:
                    self.populate(Path(root, parent, name))
                    status, report = self.report(root)
                    self.assertEqual(status, 0)
                    self.assertEqual(report['findings'], [])
                    self.assertEqual(report['summary']['files_scanned'], 0)
                    self.assertEqual(report['summary']['packages_found'], 0)
                    self.assertEqual(report['summary']['lockfiles_parsed'], [])
                    self.assertFalse(any(report['summary']['truncated'].values()))
                    self.assertNotIn('errors', report)
                    self.assertEqual(report['summary']['errors_count'], 0)

    def test_similarly_named_directories_are_scanned(self):
        for name in ('Vendor', 'vendor-copy', 'myvenv', '.hidden'):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as root:
                self.populate(Path(root, 'src', name))
                status, report = self.report(root)
                self.assertEqual(status, 1)
                self.assertEqual(report['summary']['files_scanned'], 3)
                self.assertEqual(report['summary']['packages_found'], 1)
                self.assertEqual(report['summary']['lockfiles_parsed'],
                                 [f'src/{name}/requirements.txt'])
                self.assertEqual({hit['category'] for hit in report['findings']},
                                 {'secret', 'config'})
                self.assertEqual({hit['file'] for hit in report['findings']},
                                 {f'src/{name}/settings.txt', f'src/{name}/.env'})

    def test_explicit_target_is_not_pruned_by_its_own_basename(self):
        with tempfile.TemporaryDirectory() as root:
            target = Path(root, 'vendor')
            self.populate(target)
            self.populate(target / 'build')
            status, report = self.report(target)
            self.assertEqual(status, 1)
            self.assertEqual(report['summary']['files_scanned'], 3)
            self.assertEqual(report['summary']['lockfiles_parsed'], ['requirements.txt'])
            self.assertEqual({hit['file'] for hit in report['findings']},
                             {'settings.txt', '.env'})
