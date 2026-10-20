"""Count finding-bearing paths using synthetic, offline fixtures."""
import contextlib
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from test_scan import scan


class FilesWithMultipleFindingsTests(unittest.TestCase):
    def report(self, root, *options):
        output = io.StringIO()
        with mock.patch.object(scan, 'query_osv', side_effect=AssertionError('offline')), \
                contextlib.redirect_stdout(output), contextlib.redirect_stderr(io.StringIO()):
            status = scan.main(['scan.py', str(root), '--no-osv', '--no-commit',
                                '--no-timestamp', *options])
        return status, json.loads(output.getvalue())

    def assert_count(self, report, expected):
        self.assertEqual(report['summary']['files_with_multiple_findings'], expected)
        counts = {}
        for finding in report['findings']:
            counts[finding['file']] = counts.get(finding['file'], 0) + 1
        self.assertEqual(sum(count >= 2 for count in counts.values()), expected)
        canonical = json.dumps({k: report[k] for k in ('findings', 'target', 'commit')},
                               sort_keys=True, separators=(',', ':'))
        self.assertEqual(report['manifest_hash'], hashlib.sha256(canonical.encode()).hexdigest())

    def fixture(self, root):
        # Two categories on one line still represent two findings in this file.
        Path(root, '.env').write_text('password="A1b2C3d4E5f6G7h8"' + chr(10))
        Path(root, 'nested').mkdir()
        Path(root, 'nested', '.env').write_text('PORT=8080' + chr(10))
        # Two same-category findings on separate lines count as one more path.
        Path(root, 'compose.yml').write_text(('privileged: true' + chr(10)) * 2)
        Path(root, 'ordinary.txt').write_text('ordinary text')

    def test_empty_single_and_repeat_invocation(self):
        with tempfile.TemporaryDirectory() as root:
            status, empty = self.report(root)
            self.assertEqual(status, 0)
            self.assert_count(empty, 0)
            Path(root, 'compose.yml').write_text('privileged: true' + chr(10))
            _, single = self.report(root)
            self.assertEqual(len(single['findings']), 1)
            self.assert_count(single, 0)
            Path(root, 'compose.yml').write_text(('privileged: true' + chr(10)) * 2)
            _, multiple = self.report(root)
            self.assert_count(multiple, 1)
            Path(root, 'compose.yml').unlink()
            _, again = self.report(root)
            self.assertEqual(empty, again)

    def test_mixed_categories_lines_paths_and_output_modes(self):
        with tempfile.TemporaryDirectory() as root:
            self.fixture(root)
            _, plain = self.report(root)
            self.assert_count(plain, 2)
            self.assertEqual(plain['summary']['findings_by_file'],
                             {'.env': 2, 'compose.yml': 2, 'nested/.env': 1})
            env = [f for f in plain['findings'] if f['file'] == '.env']
            self.assertEqual({f['category'] for f in env}, {'secret', 'config'})
            self.assertEqual({f['line'] for f in env}, {1})
            status, triaged = self.report(root, '--triage', '--fail-on', 'low', '--compact')
            self.assertEqual(status, 1)
            self.assert_count(triaged, 2)
            self.assertEqual(plain['findings'], triaged['findings'])
            self.assertEqual(plain['manifest_hash'], triaged['manifest_hash'])
            status, summary = self.report(root, '--triage', '--fail-on', 'low',
                                          '--summary-only', '--sort-keys')
            self.assertEqual(status, 1)
            self.assertEqual(summary['summary'], triaged['summary'])
            self.assertEqual(summary['triage_summary'], triaged['triage_summary'])
            self.assertEqual(summary['manifest_hash'], triaged['manifest_hash'])
            self.assertNotIn('findings', summary)

    def test_caps_count_only_retained_findings(self):
        with tempfile.TemporaryDirectory() as root:
            self.fixture(root)
            for limit, cap, expected in [('MAX_FINDINGS', 0, 0),
                                         ('MAX_FINDINGS', 1, 0),
                                         ('MAX_FINDINGS_PER_FILE', 1, 0),
                                         ('MAX_FINDINGS_PER_FILE', 2, 2)]:
                with self.subTest(limit=limit, cap=cap), mock.patch.object(scan, limit, cap):
                    _, report = self.report(root)
                    self.assert_count(report, expected)
                    if cap < 2:
                        self.assertTrue(report['summary']['truncated']['findings'])

    def test_unlocated_findings_contribute_to_file_count(self):
        with tempfile.TemporaryDirectory() as root:
            # Missing USER has line=None; untagged FROM has a concrete line.
            Path(root, 'Dockerfile').write_text('FROM alpine' + chr(10))
            _, report = self.report(root)
        self.assertEqual({f['line'] for f in report['findings']}, {None, 1})
        self.assert_count(report, 1)
