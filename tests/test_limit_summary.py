"""Offline coverage for applied scan caps in report metadata."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from test_scan import scan


class LimitSummaryTests(unittest.TestCase):
    def report(self, root, *options):
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(io.StringIO()):
            status = scan.main(['scan.py', str(root), '--no-osv', *options])
        return status, json.loads(stdout.getvalue())

    def test_defaults_are_reported_even_for_empty_scan(self):
        with tempfile.TemporaryDirectory() as root:
            status, report = self.report(root)
        self.assertEqual(status, 0)
        self.assertEqual(report['summary']['limits'], {
            'files': 50000, 'findings': 5000, 'findings_per_file': 100})
        self.assertEqual(report['findings'], [])
        self.assertEqual(report['summary']['truncated'], {'files': False, 'findings': False})

    def test_reported_caps_match_each_truncation_boundary(self):
        cases = [
            (1, 10, 10, 1, 2, {'files': True, 'findings': False}),
            (10, 1, 10, 2, 1, {'files': False, 'findings': True}),
            (10, 10, 1, 2, 2, {'files': False, 'findings': True}),
        ]
        with tempfile.TemporaryDirectory() as root:
            for name in ('compose.yml', 'docker-compose.yml'):
                Path(root, name).write_text(('privileged: true' + chr(10)) * 2)
            for files, findings, per_file, scanned, emitted, truncated in cases:
                with self.subTest(files=files, findings=findings, per_file=per_file):
                    with mock.patch.multiple(scan, MAX_FILES=files, MAX_FINDINGS=findings,
                                             MAX_FINDINGS_PER_FILE=per_file):
                        status, report = self.report(root)
                    summary = report['summary']
                    self.assertEqual(status, 0)
                    self.assertEqual(summary['limits'], {
                        'files': files, 'findings': findings, 'findings_per_file': per_file})
                    self.assertEqual(summary['files_scanned'], scanned)
                    self.assertEqual(len(report['findings']), emitted)
                    self.assertEqual(summary['truncated'], truncated)

    def test_unused_cap_changes_preserve_findings_hash_gate_and_triage(self):
        with tempfile.TemporaryDirectory() as root:
            Path(root, 'compose.yml').write_text('privileged: true' + chr(10))
            options = ('--triage', '--fail-on', 'medium')
            status, original = self.report(root, *options)
            with mock.patch.multiple(scan, MAX_FILES=5, MAX_FINDINGS=6,
                                     MAX_FINDINGS_PER_FILE=3):
                changed_status, changed = self.report(root, *options)
        self.assertEqual(status, 1)
        self.assertEqual(changed_status, status)
        self.assertEqual(changed['summary']['limits'], {
            'files': 5, 'findings': 6, 'findings_per_file': 3})
        for field in ('findings', 'manifest_hash', 'triage', 'triage_summary'):
            self.assertEqual(changed[field], original[field])
        self.assertEqual(changed['summary']['truncated'], {'files': False, 'findings': False})
