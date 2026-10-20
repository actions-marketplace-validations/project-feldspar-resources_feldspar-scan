"""Distinct retained file counts use the existing path-context heuristic."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from test_scan import scan


class FilePathContextTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)

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
        for category, severity, file, line in (
                ('secret', 'high', 'tests/a.txt', 2),
                ('config', 'low', 'tests/a.txt', 3),
                ('dependency-vuln', 'critical', 'Examples/requirements.txt', None),
                ('config', 'high', 'src/Dockerfile', None),
                ('secret', 'unknown', 'src/Dockerfile', 7),
                ('secret', 'low', 'contest/a.txt', 2),
                ('config', 'low', 'src/test_widget.py', 1)):
            add(category, severity, file, line, 'Synthetic finding', 'Synthetic evidence',
                ecosystem='PyPI' if category == 'dependency-vuln' else None)

    def test_distinct_files_across_categories_lines_and_severities(self):
        with mock.patch.object(scan, 'scan_secrets', side_effect=self.findings):
            status, report = self.report('--triage', '--fail-on=high')
        self.assertEqual(status, 1)
        summary = report['summary']
        self.assertEqual(summary['files_with_findings_by_path_context'],
                         {'scaffold': 2, 'other': 3})
        self.assertEqual(sum(summary['files_with_findings_by_path_context'].values()),
                         summary['files_with_findings'])
        self.assertEqual(summary['total_findings'], 7)
        self.assertEqual(summary['gate']['matching_findings'], 3)
        # Filename-only test hints are intentionally outside TEST_PATH_RE.
        self.assertEqual(summary['findings_by_path_context'], {'scaffold': 3, 'other': 4})

    def test_empty_and_clean_files_keep_zero_buckets(self):
        (self.root / 'clean.txt').write_text('ordinary text', encoding='utf-8')
        status, report = self.report('--summary-only')
        self.assertEqual(status, 0)
        self.assertEqual(report['summary']['files_with_findings_by_path_context'],
                         {'scaffold': 0, 'other': 0})
        self.assertEqual(report['summary']['files_scanned'], 1)

    def test_finding_caps_count_only_retained_files(self):
        for limit, expected in (
                ('MAX_FINDINGS', {'scaffold': 1, 'other': 0}),
                ('MAX_FINDINGS_PER_FILE', {'scaffold': 2, 'other': 3})):
            with self.subTest(limit=limit), mock.patch.object(scan, limit, 1), \
                    mock.patch.object(scan, 'scan_secrets', side_effect=self.findings):
                report = self.report()[1]
                self.assertEqual(report['summary']['files_with_findings_by_path_context'],
                                 expected)
                self.assertTrue(report['summary']['truncated']['findings'])

    def test_real_findings_and_output_modes(self):
        for directory in ('examples', 'src'):
            folder = self.root / directory
            folder.mkdir()
            (folder / 'Dockerfile').write_text(chr(10).join(('FROM scratch', 'USER root', '')),
                                              encoding='utf-8')
        status, full = self.report('--triage', '--fail-on=low')
        self.assertEqual(status, 1)
        self.assertEqual(full['summary']['files_with_findings_by_path_context'],
                         {'scaffold': 1, 'other': 1})
        reduced_status, reduced = self.report('--triage', '--fail-on=low', '--summary-only')
        self.assertEqual(reduced_status, status)
        for key in ('summary', 'manifest_hash', 'triage_summary'):
            self.assertEqual(reduced[key], full[key])
        self.assertNotIn('findings', reduced)
        plain_status, plain = self.report('--compact', '--sort-keys', '--fail-on=low')
        self.assertEqual(plain_status, status)
        for key in ('summary', 'manifest_hash', 'findings'):
            self.assertEqual(plain[key], full[key])
