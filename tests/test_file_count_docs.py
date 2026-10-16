"""Pin the documented coverage limits of summary.files_scanned, offline."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from test_scan import scan


class FileCountDocumentationTests(unittest.TestCase):
    def report(self, root):
        output = io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(io.StringIO()):
            status = scan.main(['scan.py', str(root), '--no-osv'])
        self.assertEqual(status, 0)
        return json.loads(output.getvalue())

    def test_selected_files_can_have_no_content_assessment(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            synthetic = b'password="A1b2C3d4E5f6G7h8"'
            (root / 'binary.dat').write_bytes(b'\x00' + synthetic)
            (root / 'oversized.txt').write_bytes(synthetic + b' ' * scan.MAX_TEXT)
            (root / 'image.png').write_bytes(synthetic)
            # A valid empty lockfile is inventoried, but not secret-scanned.
            (root / 'package-lock.json').write_text(json.dumps({
                'packages': {}, 'password': 'A1b2C3d4E5f6G7h8'}))
            report = self.report(root)
        self.assertEqual(report['summary']['files_scanned'], 4)
        self.assertEqual(report['findings'], [])
        self.assertEqual(report['summary']['packages_found'], 0)
        self.assertEqual(report['summary']['lockfiles_parsed'], ['package-lock.json'])

    def test_excluded_directories_and_symlinks_do_not_count(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            (root / 'plain.txt').write_text('ordinary text')
            (root / 'node_modules').mkdir()
            (root / 'node_modules' / 'ignored.txt').write_text('ordinary text')
            (root / 'alias.txt').symlink_to('plain.txt')
            report = self.report(root)
        self.assertEqual(report['summary']['files_scanned'], 1)
        self.assertEqual(report['summary']['skipped_non_regular'], 1)

    def test_file_limit_counts_selected_paths_not_all_candidates(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            for name in ('a.txt', 'b.txt', 'c.txt'):
                (root / name).write_text('ordinary text')
            with mock.patch.object(scan, 'MAX_FILES', 2):
                report = self.report(root)
        self.assertEqual(report['summary']['files_scanned'], 2)
        self.assertTrue(report['summary']['truncated']['files'])
        self.assertEqual(report['findings'], [])
