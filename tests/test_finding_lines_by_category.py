"""Retained review locations are distinct within each finding category."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from test_scan import scan


class FindingLinesByCategoryTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def report(self, *options):
        with contextlib.redirect_stdout(io.StringIO()) as out, \
                contextlib.redirect_stderr(io.StringIO()), \
                mock.patch.object(scan, 'query_osv') as query:
            status = scan.main(['scan.py', str(self.root), '--no-osv',
                                '--no-timestamp', '--no-commit', *options])
        query.assert_not_called()
        return status, json.loads(out.getvalue())

    @staticmethod
    def findings(root, files, add):
        for category, severity, file, line, label in (
                ('secret', 'high', 'a.txt', 7, 'First rule'),
                ('secret', 'low', 'a.txt', 7, 'Same category and location'),
                ('config', 'high', 'a.txt', 7, 'Overlapping category'),
                ('secret', 'high', 'b.txt', 7, 'Different file'),
                ('secret', 'high', 'a.txt', 8, 'Different line'),
                ('config', 'low', 'a.txt', 7, 'Repeated config location'),
                ('dependency-vuln', 'critical', 'requirements.txt', None, 'Unlocated'),
                ('config', 'high', 'Dockerfile', None, 'Unlocated config')):
            add(category, severity, file, line, label, 'Synthetic fixture',
                ecosystem='PyPI' if category == 'dependency-vuln' else None)

    def test_deduplication_and_overlapping_categories(self):
        with mock.patch.object(scan, 'scan_secrets', side_effect=self.findings):
            status, report = self.report('--triage', '--fail-on=high')
        self.assertEqual(status, 1)
        self.assertEqual(report['summary']['finding_lines_by_category'],
                         {'dependency-vuln': 0, 'secret': 3, 'config': 1})
        self.assertEqual(report['summary']['finding_lines'], 3)
        self.assertEqual(report['summary']['total_findings'], 8)
        self.assertEqual(report['summary']['gate']['matching_findings'], 6)

    def test_empty_and_unlocated_reports_keep_zero_buckets(self):
        zero = {'dependency-vuln': 0, 'secret': 0, 'config': 0}
        self.assertEqual(self.report()[1]['summary']['finding_lines_by_category'], zero)
        def unlocated(root, files, add):
            add('config', 'high', 'Dockerfile', None, 'Unlocated', 'Synthetic fixture')
        with mock.patch.object(scan, 'scan_secrets', side_effect=unlocated):
            status, report = self.report('--fail-on=high')
        self.assertEqual(status, 1)
        self.assertEqual(report['summary']['total_findings'], 1)
        self.assertEqual(report['summary']['finding_lines_by_category'], zero)

    def test_caps_count_only_retained_findings(self):
        for limit, expected in (
                ('MAX_FINDINGS', {'dependency-vuln': 0, 'secret': 1, 'config': 0}),
                ('MAX_FINDINGS_PER_FILE', {'dependency-vuln': 0, 'secret': 2, 'config': 0})):
            with self.subTest(limit=limit), \
                    mock.patch.object(scan, limit, 2), \
                    mock.patch.object(scan, 'scan_secrets', side_effect=self.findings):
                report = self.report()[1]
                self.assertEqual(report['summary']['finding_lines_by_category'], expected)
                self.assertTrue(report['summary']['truncated']['findings'])

    def test_real_findings_triage_formatting_and_summary_only(self):
        (self.root / 'Dockerfile').write_text(chr(10).join((
            'FROM scratch', 'ENV PASSWORD="your_placeholder_value"', 'USER root', '')),
            encoding='utf-8')
        status, full = self.report('--triage', '--fail-on=high')
        self.assertEqual(status, 1)
        self.assertEqual(full['summary']['finding_lines_by_category'],
                         {'dependency-vuln': 0, 'secret': 1, 'config': 2})
        reduced_status, reduced = self.report('--triage', '--fail-on=high', '--summary-only')
        self.assertEqual(reduced_status, status)
        for key in ('summary', 'manifest_hash', 'triage_summary'):
            self.assertEqual(reduced[key], full[key])
        self.assertNotIn('findings', reduced)
        plain_status, plain = self.report('--compact', '--sort-keys', '--fail-on=high')
        self.assertEqual(plain_status, status)
        for key in ('summary', 'manifest_hash', 'findings'):
            self.assertEqual(plain[key], full[key])
