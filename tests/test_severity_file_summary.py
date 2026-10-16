"""Offline coverage of distinct affected files per raw severity."""
import contextlib
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from test_scan import scan


class SeverityFileSummaryTests(unittest.TestCase):
    def report(self, root, *options):
        output = io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(io.StringIO()):
            status = scan.main(['scan.py', str(root), '--no-osv', *options])
        return status, json.loads(output.getvalue())

    def test_empty_and_clean_reports_include_zero_buckets(self):
        with tempfile.TemporaryDirectory() as root:
            for populated in (False, True):
                with self.subTest(populated=populated):
                    if populated:
                        Path(root, 'notes.txt').write_text('ordinary text')
                    status, report = self.report(root)
                    self.assertEqual(status, 0)
                    self.assertEqual(report['summary']['files_by_severity'],
                                     dict.fromkeys(scan.SEV_ORDER.keys() | {'unknown'}, 0))

    def test_repeated_hits_and_overlapping_severities_preserve_raw_contract(self):
        with tempfile.TemporaryDirectory() as root:
            # Synthetic assignments: one file has two medium hits and one high config hit.
            Path(root, '.env').write_text(
                chr(10).join(['password="A1b2C3d4E5f6G7h8"', 'token="J9k8L7m6N5o4P3q2"']))
            Path(root, 'compose.yml').write_text('privileged: true')
            Path(root, 'Dockerfile').write_text('FROM scratch')
            status, plain = self.report(root)
            self.assertEqual(status, 0)
            self.assertEqual(len(plain['findings']), 5)
            expected = {'critical': 0, 'high': 1, 'medium': 2, 'low': 1, 'unknown': 0}
            self.assertEqual(plain['summary']['files_by_severity'], expected)
            self.assertEqual(plain['summary']['files_with_findings'], 3)
            status, triaged = self.report(root, '--triage', '--fail-on', 'high')
            self.assertEqual(status, 1)
            self.assertEqual(triaged['summary']['files_by_severity'], expected)
            self.assertEqual(triaged['findings'], plain['findings'])
            self.assertEqual(triaged['manifest_hash'], plain['manifest_hash'])
            canonical = json.dumps({key: plain[key] for key in ('findings', 'target', 'commit')},
                                   sort_keys=True, separators=(',', ':'))
            self.assertEqual(plain['manifest_hash'], hashlib.sha256(canonical.encode()).hexdigest())

    def test_unknown_and_critical_buckets(self):
        def emit(root, files, add):
            for severity, path in [('unknown', 'a.lock'), ('unknown', 'a.lock'),
                                   ('unknown', 'nested/a.lock'), ('critical', 'a.lock')]:
                add('dependency-vuln', severity, path, None,
                    summary='Synthetic advisory', evidence='synthetic')

        with tempfile.TemporaryDirectory() as root, mock.patch.object(scan, 'scan_secrets', emit):
            _, report = self.report(root)
        self.assertEqual(report['summary']['files_by_severity'],
                         {'critical': 1, 'high': 0, 'medium': 0, 'low': 0, 'unknown': 2})

    def test_truncation_counts_only_retained_findings(self):
        with tempfile.TemporaryDirectory() as root:
            Path(root, 'compose.yml').write_text(chr(10).join(['privileged: true', 'privileged: true']))
            Path(root, 'docker-compose.yml').write_text('privileged: true')
            for limit, count in [(1, 1), (2, 1), (3, 2)]:
                with self.subTest(limit=limit), mock.patch.object(scan, 'MAX_FINDINGS', limit):
                    _, report = self.report(root)
                    self.assertEqual(report['summary']['files_by_severity'],
                                     {'critical': 0, 'high': 0, 'medium': count, 'low': 0, 'unknown': 0})
                    self.assertEqual(report['summary']['truncated']['findings'], limit < 3)
