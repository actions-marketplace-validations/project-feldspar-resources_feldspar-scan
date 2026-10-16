"""Offline examples of the documented skipped_non_regular counter."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from test_scan import scan


class NonregularSummaryDocumentationTests(unittest.TestCase):
    def report(self, root):
        output = io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(io.StringIO()):
            status = scan.main(['scan.py', str(root), '--no-osv', '--fail-on', 'low'])
        self.assertEqual(status, 0)
        report = json.loads(output.getvalue())
        self.assertEqual(report['findings'], [])
        self.assertTrue(report['summary']['gate']['passed'])
        return report['summary']

    def test_links_count_once_and_excluded_names_do_not_count(self):
        with tempfile.TemporaryDirectory() as root, tempfile.TemporaryDirectory() as outside:
            root, outside = Path(root), Path(outside)
            for name in ('one.txt', 'two.txt'):
                (outside / name).write_text('ordinary text')
            (root / 'file-link').symlink_to(outside / 'one.txt')
            (root / 'directory-link').symlink_to(outside, target_is_directory=True)
            (root / 'dangling-link').symlink_to(outside / 'absent.txt')
            (root / 'node_modules').symlink_to(outside, target_is_directory=True)
            (root / 'vendor').mkdir()
            (root / 'vendor' / 'hidden-link').symlink_to(outside / 'one.txt')
            summary = self.report(root)
        self.assertEqual(summary['skipped_non_regular'], 3)
        self.assertEqual(summary['files_scanned'], 0)
        self.assertEqual(summary['truncated'], {'files': False, 'findings': False})

    def test_regular_files_skipped_by_content_checks_do_not_count(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            (root / 'binary.dat').write_bytes(bytes([0]) + b'ordinary text')
            (root / 'oversized.txt').write_bytes(b'x' * (scan.MAX_TEXT + 1))
            summary = self.report(root)
        self.assertEqual(summary['skipped_non_regular'], 0)
        self.assertEqual(summary['files_scanned'], 2)

    def test_failed_entry_metadata_read_counts_as_a_skip(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            unreadable = root / 'unreadable.txt'
            unreadable.write_text('ordinary text')
            real_lstat = scan.os.lstat

            def failing_lstat(path, *args, **kwargs):
                if Path(path) == unreadable:
                    raise OSError('synthetic metadata failure')
                return real_lstat(path, *args, **kwargs)

            with mock.patch.object(scan.os, 'lstat', side_effect=failing_lstat):
                summary = self.report(root)
        self.assertEqual(summary['skipped_non_regular'], 1)
        self.assertEqual(summary['files_scanned'], 0)

    def test_file_cap_counter_includes_only_encountered_entries(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            for name in ('a.txt', 'b.txt'):
                (root / name).write_text('ordinary text')
            (root / 'aa-link').symlink_to('a.txt')
            (root / 'z-link').symlink_to('a.txt')
            with mock.patch.object(scan, 'MAX_FILES', 1):
                limited = self.report(root)
            full = self.report(root)
        self.assertEqual(limited['files_scanned'], 1)
        self.assertEqual(limited['skipped_non_regular'], 1)
        self.assertTrue(limited['truncated']['files'])
        self.assertEqual(full['files_scanned'], 2)
        self.assertEqual(full['skipped_non_regular'], 2)
        self.assertFalse(full['truncated']['files'])
