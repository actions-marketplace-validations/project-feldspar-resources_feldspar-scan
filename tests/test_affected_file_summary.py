"""Offline tests for the count of distinct files with emitted findings."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from test_scan import scan


class AffectedFileSummaryTests(unittest.TestCase):
    def report(self, root, *options):
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(io.StringIO()):
            status = scan.main(['scan.py', str(root), '--no-osv', *options])
        return status, json.loads(stdout.getvalue())

    def test_empty_and_clean_files_count_zero(self):
        with tempfile.TemporaryDirectory() as root:
            for populated in (False, True):
                with self.subTest(populated=populated):
                    if populated:
                        Path(root, 'notes.txt').write_text('ordinary text\n')
                    status, report = self.report(root)
                    self.assertEqual(status, 0)
                    self.assertEqual(report['summary']['files_with_findings'], 0)
                    self.assertEqual(report['findings'], [])
                    self.assertEqual(report['summary']['files_scanned'], int(populated))

    def test_counts_paths_once_across_categories_and_preserves_gate_and_triage(self):
        with tempfile.TemporaryDirectory() as root:
            # Synthetic generic value; .env also produces a config finding.
            Path(root, '.env').write_text('password="A1b2C3d4E5f6G7h8"\n')
            Path(root, 'nested').mkdir()
            Path(root, 'nested', '.env').write_text('PORT=8080\n')
            Path(root, 'notes.txt').write_text('ordinary text\n')
            status, plain = self.report(root)
            self.assertEqual(status, 0)
            self.assertEqual(len(plain['findings']), 3)
            self.assertEqual({f['category'] for f in plain['findings']}, {'secret', 'config'})
            self.assertEqual(plain['summary']['files_scanned'], 3)
            self.assertEqual(plain['summary']['files_with_findings'], 2)
            status, triaged = self.report(root, '--triage', '--fail-on', 'high')
            self.assertEqual(status, 1)
            self.assertEqual(triaged['summary']['files_with_findings'], 2)
            self.assertEqual(triaged['findings'], plain['findings'])
            self.assertEqual(triaged['manifest_hash'], plain['manifest_hash'])

    def test_truncation_counts_only_files_with_emitted_findings(self):
        with tempfile.TemporaryDirectory() as root:
            Path(root, 'compose.yml').write_text('privileged: true\n')
            Path(root, 'docker-compose.yml').write_text('privileged: true\n')
            with mock.patch.object(scan, 'MAX_FINDINGS', 1):
                _, report = self.report(root)
            self.assertEqual(report['summary']['files_scanned'], 2)
            self.assertEqual(len(report['findings']), 1)
            self.assertTrue(report['summary']['truncated']['findings'])
            self.assertEqual(report['summary']['files_with_findings'], 1)
