"""Selected paths absent from findings are not a certificate of scan coverage."""
import contextlib
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from test_scan import scan


class FilesWithoutFindingsTests(unittest.TestCase):
    def report(self, root, *options):
        output = io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(io.StringIO()):
            status = scan.main(['scan.py', str(root), '--no-osv', *options])
        return status, json.loads(output.getvalue())

    def assert_count(self, report, expected):
        summary = report['summary']
        self.assertEqual(summary['files_without_findings'], expected)
        self.assertEqual(expected + summary['files_with_findings'], summary['files_scanned'])
        canonical = json.dumps({k: report[k] for k in ('findings', 'target', 'commit')},
                               sort_keys=True, separators=(',', ':'))
        self.assertEqual(report['manifest_hash'], hashlib.sha256(canonical.encode()).hexdigest())

    def test_empty_and_content_skipped_files(self):
        with tempfile.TemporaryDirectory() as root:
            status, empty = self.report(root)
            self.assertEqual(status, 0)
            self.assert_count(empty, 0)
            Path(root, 'ordinary.txt').write_text('ordinary content')
            Path(root, 'binary.txt').write_bytes(bytes([0, 1, 2]))
            Path(root, 'large.txt').write_text('a' * (1024 * 1024 + 1))
            Path(root, 'node_modules').mkdir()
            Path(root, 'node_modules', '.env').write_text('PORT=8080')
            _, report = self.report(root)
            self.assert_count(report, 3)
            self.assertEqual(report['findings'], [])

    def test_mixed_findings_and_same_basename_preserve_gate_and_triage(self):
        with tempfile.TemporaryDirectory() as root:
            Path(root, '.env').write_text('password="A1b2C3d4E5f6G7h8"' + chr(10))
            Path(root, 'nested').mkdir()
            Path(root, 'nested', '.env').write_text('# comment only')
            Path(root, 'ordinary.txt').write_text('ordinary content')
            status, plain = self.report(root)
            gated, triaged = self.report(root, '--triage', '--compact', '--fail-on', 'low')
        self.assertEqual((status, gated), (0, 1))
        self.assertEqual({f['category'] for f in plain['findings']}, {'secret', 'config'})
        self.assert_count(plain, 2)
        self.assert_count(triaged, 2)
        self.assertEqual(plain['findings'], triaged['findings'])
        self.assertEqual(plain['manifest_hash'], triaged['manifest_hash'])

    def test_finding_caps_count_files_without_retained_findings(self):
        with tempfile.TemporaryDirectory() as root:
            Path(root, '.env').write_text('password="A1b2C3d4E5f6G7h8"' + chr(10))
            Path(root, 'compose.yml').write_text('privileged: true' + chr(10))
            for limit, cap, expected in (('MAX_FINDINGS', 1, 1),
                                         ('MAX_FINDINGS', 0, 2),
                                         ('MAX_FINDINGS_PER_FILE', 1, 0)):
                with self.subTest(limit=limit, cap=cap), mock.patch.object(scan, limit, cap):
                    _, report = self.report(root)
                    self.assert_count(report, expected)
                    self.assertTrue(report['summary']['truncated']['findings'])

    def test_file_cap_counts_only_selected_paths(self):
        with tempfile.TemporaryDirectory() as root:
            Path(root, 'a.txt').write_text('ordinary content')
            Path(root, 'b.txt').write_text('ordinary content')
            with mock.patch.object(scan, 'MAX_FILES', 1):
                _, report = self.report(root)
        self.assert_count(report, 1)
        self.assertTrue(report['summary']['truncated']['files'])
