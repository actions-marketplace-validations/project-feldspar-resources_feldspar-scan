"""Distinct retained finding locations grouped by the existing path heuristic."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from test_scan import scan


class FindingLinesByPathContextTests(unittest.TestCase):
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
        report = json.loads(out.getvalue())
        counts = report['summary']['finding_lines_by_path_context']
        self.assertEqual(set(counts), {'scaffold', 'other'})
        self.assertEqual(sum(counts.values()), report['summary']['finding_lines'])
        return status, report

    @staticmethod
    def findings(root, files, add):
        for category, severity, file, line, label in (
                ('secret', 'high', 'src/TESTS/a.txt', 7, 'First rule'),
                ('config', 'low', 'src/TESTS/a.txt', 7, 'Same location'),
                ('config', 'high', 'docs/a.txt', 7, 'Different file'),
                ('config', 'high', 'src/TESTS/a.txt', 8, 'Different line'),
                ('config', 'high', 'contest/a.txt', 7, 'Other path'),
                ('config', 'low', 'contest/a.txt', 7, 'Other overlap'),
                ('dependency-vuln', 'critical', 'requirements.txt', None, 'Unlocated'),
                ('config', 'high', 'examples/Dockerfile', None, 'Unlocated scaffold')):
            add(category, severity, file, line, label, 'Synthetic fixture',
                ecosystem='PyPI' if category == 'dependency-vuln' else None)

    def test_deduplicates_across_categories_and_severities(self):
        with mock.patch.object(scan, 'scan_secrets', side_effect=self.findings):
            status, report = self.report('--triage', '--fail-on=high')
        self.assertEqual(status, 1)
        self.assertEqual(report['summary']['finding_lines_by_path_context'],
                         {'scaffold': 3, 'other': 1})
        self.assertEqual(report['summary']['total_findings'], 8)
        self.assertEqual(report['summary']['gate']['matching_findings'], 6)

    def test_empty_and_entirely_unlocated_reports(self):
        zero = {'scaffold': 0, 'other': 0}
        self.assertEqual(self.report()[1]['summary']['finding_lines_by_path_context'], zero)
        def unlocated(root, files, add):
            for path in ('Dockerfile', 'examples/Dockerfile'):
                add('config', 'high', path, None, 'Unlocated', 'Synthetic fixture')
        with mock.patch.object(scan, 'scan_secrets', side_effect=unlocated):
            status, report = self.report('--fail-on=high')
        self.assertEqual(status, 1)
        self.assertEqual(report['summary']['total_findings'], 2)
        self.assertEqual(report['summary']['finding_lines_by_path_context'], zero)

    def test_caps_count_only_retained_locations(self):
        for limit, expected in (
                ('MAX_FINDINGS', {'scaffold': 1, 'other': 0}),
                ('MAX_FINDINGS_PER_FILE', {'scaffold': 2, 'other': 1})):
            with self.subTest(limit=limit), \
                    mock.patch.object(scan, limit, 2), \
                    mock.patch.object(scan, 'scan_secrets', side_effect=self.findings):
                report = self.report()[1]
                self.assertEqual(report['summary']['finding_lines_by_path_context'], expected)
                self.assertTrue(report['summary']['truncated']['findings'])

    def test_real_detectors_triage_and_summary_only(self):
        for directory in ('docs', 'src'):
            path = self.root / directory / 'Dockerfile'
            path.parent.mkdir()
            path.write_text(chr(10).join(('FROM scratch',
                'ENV PASSWORD="your_placeholder_value" TOKEN="your_placeholder_value"',
                'USER root', '')), encoding='utf-8')
        status, full = self.report('--triage', '--fail-on=high')
        self.assertEqual(status, 1)
        self.assertEqual(full['summary']['finding_lines_by_path_context'],
                         {'scaffold': 2, 'other': 2})
        self.assertGreater(full['summary']['total_findings'], 4)
        reduced_status, reduced = self.report('--triage', '--fail-on=high', '--summary-only')
        self.assertEqual(reduced_status, status)
        for key in ('summary', 'manifest_hash', 'triage_summary'):
            self.assertEqual(reduced[key], full[key])
        self.assertNotIn('findings', reduced)
        plain_status, plain = self.report('--compact', '--sort-keys', '--fail-on=high')
        self.assertEqual(plain_status, status)
        for key in ('summary', 'manifest_hash', 'findings'):
            self.assertEqual(plain[key], full[key])
