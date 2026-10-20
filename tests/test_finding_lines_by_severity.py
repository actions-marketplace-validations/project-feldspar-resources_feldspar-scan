"""Count distinct retained review locations independently at each severity."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from test_scan import scan


ZERO = dict.fromkeys(('critical', 'high', 'medium', 'low', 'unknown'), 0)


class FindingLinesBySeverityTests(unittest.TestCase):
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
        # Synthetic findings exercise combinations independent of detector rules.
        for category, severity, file, line, label in (
                ('secret', 'high', 'a.txt', 7, 'First rule'),
                ('config', 'high', 'a.txt', 7, 'Second rule'),
                ('config', 'low', 'a.txt', 7, 'Third rule'),
                ('config', 'high', 'b.txt', 7, 'Different file'),
                ('config', 'high', 'a.txt', 8, 'Different line'),
                ('dependency-vuln', 'critical', 'requirements.txt', None, 'Unlocated'),
                ('config', 'medium', 'a.txt', 9, 'Medium rule'),
                ('config', 'unknown', 'a.txt', 10, 'Unknown rule')):
            add(category, severity, file, line, label, 'Synthetic fixture',
                ecosystem='PyPI' if category == 'dependency-vuln' else None)

    def test_distinct_locations_and_cross_severity_overlap(self):
        with mock.patch.object(scan, 'scan_secrets', side_effect=self.findings):
            status, report = self.report('--triage', '--fail-on=high')
        self.assertEqual(status, 1)
        self.assertEqual(report['summary']['finding_lines_by_severity'],
                         dict(critical=0, high=3, medium=1, low=1, unknown=1))
        self.assertEqual(report['summary']['finding_lines'], 5)
        self.assertEqual(report['summary']['total_findings'], 8)
        self.assertFalse(report['summary']['gate']['passed'])

    def test_empty_and_entirely_unlocated_reports(self):
        self.assertEqual(self.report()[1]['summary']['finding_lines_by_severity'], ZERO)
        def unlocated(root, files, add):
            add('config', 'high', 'Dockerfile', None, 'Unlocated', 'Synthetic')
        with mock.patch.object(scan, 'scan_secrets', side_effect=unlocated):
            status, report = self.report('--fail-on=high')
        self.assertEqual(status, 1)
        self.assertEqual(report['summary']['total_findings'], 1)
        self.assertEqual(report['summary']['finding_lines_by_severity'], ZERO)

    def test_caps_count_only_retained_findings(self):
        for limit, expected in (
                ('MAX_FINDINGS', dict(ZERO, high=1)),
                ('MAX_FINDINGS_PER_FILE', dict(ZERO, high=2))):
            with self.subTest(limit=limit), \
                    mock.patch.object(scan, limit, 2), \
                    mock.patch.object(scan, 'scan_secrets', side_effect=self.findings):
                report = self.report()[1]
                self.assertEqual(report['summary']['finding_lines_by_severity'], expected)
                self.assertTrue(report['summary']['truncated']['findings'])
        with mock.patch.object(scan, 'MAX_FINDINGS', 0), \
                mock.patch.object(scan, 'scan_secrets', side_effect=self.findings):
            self.assertEqual(self.report()[1]['summary']['finding_lines_by_severity'], ZERO)

    def test_real_detector_overlap_and_summary_only(self):
        # Deliberately synthetic placeholders; no credential material.
        (self.root / 'Dockerfile').write_text(
            chr(10).join(('FROM scratch',
                          'ENV PASSWORD="your_placeholder_value" TOKEN="your_placeholder_value"',
                          'USER root', '')),
            encoding='utf-8')
        status, full = self.report('--triage', '--fail-on=high')
        self.assertEqual(full['summary']['finding_lines_by_severity'],
                         dict(ZERO, high=1, low=2))
        self.assertEqual(full['summary']['finding_lines'], 2)
        self.assertEqual(status, 1)
        reduced_status, reduced = self.report('--triage', '--fail-on=high', '--summary-only')
        self.assertEqual(reduced_status, status)
        for key in ('summary', 'manifest_hash', 'triage_summary'):
            self.assertEqual(reduced[key], full[key])
        self.assertNotIn('findings', reduced)
        plain_status, plain = self.report('--compact', '--sort-keys', '--fail-on=high')
        self.assertEqual(plain_status, status)
        for key in ('summary', 'manifest_hash', 'findings'):
            self.assertEqual(plain[key], full[key])
