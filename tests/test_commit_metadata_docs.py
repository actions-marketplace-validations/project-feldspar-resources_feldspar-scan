"""Exercise the documented commit metadata with synthetic, offline fixtures."""
import contextlib
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

from test_scan import scan


class CommitMetadataDocsTests(unittest.TestCase):
    def report(self, root):
        output = io.StringIO()
        with mock.patch.object(scan, 'query_osv') as query, \
                contextlib.redirect_stdout(output):
            self.assertEqual(scan.main(['scan.py', str(root), '--no-osv']), 0)
        query.assert_not_called()
        report = json.loads(output.getvalue())
        self.assertNotIn('errors', report)
        self.assertEqual(report['summary']['errors_count'], 0)
        return report

    def git(self, root, *args):
        return subprocess.run(
            ['git', '-C', str(root), *args], check=True,
            capture_output=True, text=True).stdout.strip()

    def test_subdirectory_reports_enclosing_head_but_only_scans_subtree(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            self.git(root, 'init', '-q')
            self.git(root, '-c', 'user.name=Scanner Test',
                     '-c', 'user.email=scanner@example.invalid',
                     '-c', 'commit.gpgsign=false', 'commit', '--allow-empty',
                     '-m', 'fixture', '-m',
                     'Co-Authored-By: Paperclip <noreply@paperclip.ing>')
            head = self.git(root, 'rev-parse', 'HEAD')
            subtree = root / 'selected'
            subtree.mkdir()
            (subtree / '.env').write_text('FEATURE_FLAG=enabled' + chr(10), encoding='utf-8')
            (root / 'Dockerfile').write_text('FROM alpine:latest' + chr(10), encoding='utf-8')
            report = self.report(subtree)
        self.assertEqual(report['commit'], head)
        self.assertEqual(report['summary']['files_scanned'], 1)
        self.assertEqual(len(report['findings']), 1)
        self.assertEqual(report['findings'][0]['file'], '.env')
        self.assertEqual(report['findings'][0]['summary'],
                         'Committed .env file with assignments')

    def test_non_repository_and_unborn_repository_have_null_commit(self):
        with tempfile.TemporaryDirectory() as root:
            for initialized in (False, True):
                with self.subTest(initialized=initialized):
                    if initialized:
                        self.git(root, 'init', '-q')
                    report = self.report(root)
                    self.assertIsNone(report['commit'])
                    self.assertEqual(report['findings'], [])

    def test_git_lookup_failures_leave_scan_successful_without_errors(self):
        failures = (FileNotFoundError('synthetic missing git'),
                    subprocess.TimeoutExpired(['git'], 30))
        with tempfile.TemporaryDirectory() as root:
            Path(root, '.env').write_text('FEATURE_FLAG=enabled' + chr(10), encoding='utf-8')
            for failure in failures:
                with self.subTest(failure=type(failure).__name__), \
                        mock.patch.object(scan.subprocess, 'run', side_effect=failure):
                    report = self.report(root)
                    self.assertIsNone(report['commit'])
                    self.assertEqual(len(report['findings']), 1)
