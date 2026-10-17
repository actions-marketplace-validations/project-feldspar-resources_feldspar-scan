"""Count retained source locations without double-counting categories or rules."""
import contextlib
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from test_scan import scan


class FindingLinesTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def report(self, *options):
        with contextlib.redirect_stdout(io.StringIO()) as out, \
                contextlib.redirect_stderr(io.StringIO()):
            status = scan.main(['scan.py', str(self.root), '--no-osv', *options])
        return status, json.loads(out.getvalue())

    def fixture(self, directory):
        folder = self.root / directory
        folder.mkdir()
        # Explicit synthetic placeholders; no real credential material.
        (folder / 'Dockerfile').write_text(
            'FROM scratch' + chr(10) +
            'ENV PASSWORD="your_placeholder_value" TOKEN="your_placeholder_value"' + chr(10) +
            'USER root' + chr(10), encoding='utf-8')

    def test_empty_and_unlocated_findings(self):
        self.assertEqual(self.report()[1]['summary']['finding_lines'], 0)
        (self.root / 'Dockerfile').write_text('FROM scratch' + chr(10), encoding='utf-8')
        report = self.report()[1]
        self.assertEqual(len(report['findings']), 1)
        self.assertIsNone(report['findings'][0]['line'])
        self.assertEqual(report['summary']['finding_lines'], 0)
        # Dependency findings lack source line locations, even when retained.
        def dependency(root, files, add):
            add('dependency-vuln', 'high', 'requirements.txt', None,
                'Synthetic advisory', 'SYNTHETIC-1', ecosystem='PyPI', package='demo')
        with mock.patch.object(scan, 'scan_secrets', side_effect=dependency):
            report = self.report()[1]
        self.assertEqual(report['summary']['by_category']['dependency-vuln'], 1)
        self.assertEqual(report['summary']['finding_lines'], 0)

    def test_overlap_distinct_files_and_unchanged_report_contracts(self):
        for directory in ('one', 'two'):
            self.fixture(directory)
        status, report = self.report('--triage', '--fail-on=high')
        self.assertEqual(status, 1)
        self.assertEqual(report['summary']['secret_lines'], 2)
        self.assertEqual(report['summary']['config_lines'], 4)
        self.assertEqual(report['summary']['finding_lines'], 4)
        self.assertGreater(report['summary']['total_findings'], 4)
        self.assertEqual({f['category'] for f in report['findings']
                          if f['file'] == 'one/Dockerfile' and f['line'] == 2},
                         {'secret', 'config'})
        plain_status, plain = self.report('--fail-on=high')
        self.assertEqual(status, plain_status)
        for key in ('findings', 'summary', 'manifest_hash'):
            self.assertEqual(report[key], plain[key])
        canonical = json.dumps({k: report[k] for k in ('findings', 'target', 'commit')},
                               sort_keys=True, separators=(',', ':'))
        self.assertEqual(report['manifest_hash'], hashlib.sha256(canonical.encode()).hexdigest())
        self.assertEqual(report['summary']['gate'], {
            'threshold': 'high', 'matching_findings': 4, 'passed': False})

    def test_limits_count_only_retained_locations(self):
        self.fixture('one')
        for limit in ('MAX_FINDINGS', 'MAX_FINDINGS_PER_FILE'):
            for maximum, expected in ((0, 0), (1, 1), (2, 1)):
                with self.subTest(limit=limit, maximum=maximum), \
                        mock.patch.object(scan, limit, maximum):
                    report = self.report()[1]
                    self.assertEqual(report['summary']['finding_lines'], expected)
                    self.assertTrue(report['summary']['truncated']['findings'])
                    self.assertEqual(len(report['findings']), maximum)

    def test_secret_only_and_compact_sorted_file_output(self):
        (self.root / 'settings.txt').write_text(
            'password="your_placeholder_value"' + chr(10), encoding='utf-8')
        report = self.report()[1]
        self.assertEqual(report['summary']['finding_lines'], 1)
        self.assertEqual(report['summary']['config_issues'], 0)
        with tempfile.TemporaryDirectory() as destination:
            path = Path(destination) / 'report.json'
            with contextlib.redirect_stdout(io.StringIO()) as out, \
                    contextlib.redirect_stderr(io.StringIO()):
                status = scan.main(['scan.py', str(self.root), '--no-osv', '--compact',
                                    '--sort-keys', '--json', str(path)])
            self.assertEqual((status, out.getvalue()), (0, ''))
            text = path.read_text()
        self.assertEqual(len(text.splitlines()), 1)
        actual = json.loads(text)
        self.assertEqual(actual['summary']['finding_lines'], 1)
        self.assertEqual(actual['findings'], report['findings'])
        self.assertEqual(actual['manifest_hash'], report['manifest_hash'])
