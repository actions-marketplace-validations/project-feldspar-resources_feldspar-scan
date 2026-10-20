"""Per-file review locations count retained lines, not rules or categories."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from test_scan import scan


class FindingLinesByFileTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name) / 'repo'
        self.root.mkdir()

    def report(self, *options):
        with contextlib.redirect_stdout(io.StringIO()) as out, \
                contextlib.redirect_stderr(io.StringIO()), \
                mock.patch.object(scan, 'query_osv') as query:
            status = scan.main(['scan.py', str(self.root), '--no-osv',
                                '--no-timestamp', '--no-commit', *options])
            query.assert_not_called()
        return status, json.loads(out.getvalue()) if out.getvalue() else None

    def fixtures(self):
        # Synthetic placeholders only; two rules and categories overlap at line 2.
        for name in ('zeta', 'alpha'):
            folder = self.root / name
            folder.mkdir()
            (folder / 'Dockerfile').write_text(
                chr(10).join(('FROM scratch',
                              'ENV PASSWORD="your_placeholder_value" TOKEN="your_placeholder_value"',
                              'USER root', '')), encoding='utf-8')
        (self.root / 'Dockerfile').write_text('FROM scratch' + chr(10), encoding='utf-8')

    def test_overlap_sorted_paths_and_unlocated_omission(self):
        self.fixtures()
        status, report = self.report('--triage', '--fail-on=high')
        self.assertEqual(status, 1)
        counts = report['summary']['finding_lines_by_file']
        self.assertEqual(counts, {'alpha/Dockerfile': 2, 'zeta/Dockerfile': 2})
        self.assertEqual(list(counts), ['alpha/Dockerfile', 'zeta/Dockerfile'])
        self.assertEqual(sum(counts.values()), report['summary']['finding_lines'])
        overlap = [f for f in report['findings']
                   if f['file'] == 'alpha/Dockerfile' and f['line'] == 2]
        self.assertGreater(len(overlap), 1)
        self.assertEqual({f['category'] for f in overlap}, {'secret', 'config'})
        self.assertTrue(any(f['line'] is None for f in report['findings']))
        plain_status, plain = self.report('--fail-on=high')
        self.assertEqual(plain_status, status)
        for key in ('findings', 'manifest_hash', 'summary'):
            self.assertEqual(plain[key], report[key])

    def test_empty_and_dependency_only_reports(self):
        self.assertEqual(self.report()[1]['summary']['finding_lines_by_file'], {})
        def dependency(root, files, add):
            add('dependency-vuln', 'high', 'requirements.txt', None,
                'Synthetic advisory', 'SYNTHETIC-1', package='demo', ecosystem='PyPI')
        with mock.patch.object(scan, 'scan_secrets', side_effect=dependency):
            report = self.report()[1]
        self.assertEqual(report['summary']['total_findings'], 1)
        self.assertEqual(report['summary']['finding_lines_by_file'], {})

    def test_limits_include_only_retained_lines(self):
        self.fixtures()
        for limit in ('MAX_FINDINGS', 'MAX_FINDINGS_PER_FILE'):
            for maximum in (0, 1, 2):
                with self.subTest(limit=limit, maximum=maximum), \
                        mock.patch.object(scan, limit, maximum):
                    report = self.report()[1]
                    expected = {}
                    for finding in report['findings']:
                        if finding['line'] is not None:
                            expected.setdefault(finding['file'], set()).add(finding['line'])
                    self.assertEqual(report['summary']['finding_lines_by_file'],
                                     {path: len(lines) for path, lines in expected.items()})
                    self.assertTrue(report['summary']['truncated']['findings'])

    def test_summary_only_and_named_json_preserve_counts_and_gate(self):
        self.fixtures()
        flags = ('--triage', '--fail-on=high')
        status, full = self.report(*flags)
        reduced_status, reduced = self.report(*flags, '--summary-only')
        self.assertEqual(reduced_status, status)
        self.assertEqual(reduced['summary'], full['summary'])
        self.assertEqual(reduced['manifest_hash'], full['manifest_hash'])
        self.assertNotIn('findings', reduced)
        destination = self.root.parent / 'report.json'
        file_status, stdout = self.report(*flags, '--compact', '--sort-keys',
                                         '--json', str(destination))
        self.assertEqual((file_status, stdout), (status, None))
        self.assertEqual(json.loads(destination.read_text(encoding='utf-8')), full)
