"""Per-file finding counts with synthetic fixtures and no advisory network calls."""
import contextlib
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from test_scan import scan


class FindingsByFileTests(unittest.TestCase):
    def report(self, root, *options):
        output = io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(io.StringIO()):
            status = scan.main(['scan.py', str(root), *options])
        return status, json.loads(output.getvalue())

    def test_empty_scan_and_clean_files_have_no_entries(self):
        with tempfile.TemporaryDirectory() as root:
            for clean in (False, True):
                if clean:
                    Path(root, 'clean.txt').write_text('ordinary content')
                with self.subTest(clean=clean):
                    status, report = self.report(root, '--no-osv')
                    self.assertEqual(status, 0)
                    self.assertEqual(report['summary']['findings_by_file'], {})

    def test_mixed_findings_count_per_path_and_preserve_report_contract(self):
        with tempfile.TemporaryDirectory() as root:
            Path(root, 'requirements.txt').write_text('synthetic-package==1.0')
            Path(root, '.env').write_text('password="A1b2C3d4E5f6G7h8"')
            Path(root, 'nested').mkdir()
            Path(root, 'nested', '.env').write_text('FLAG=1')
            Path(root, 'clean.txt').write_text('ordinary content')
            key = ('PyPI', 'synthetic-package', '1.0')
            details = {'severity': 'high', 'fixed_in': ['1.1'], 'summary': 'Synthetic advisory'}
            with mock.patch.object(scan, 'query_osv', return_value={key: ['TEST-1', 'TEST-2']}), \
                    mock.patch.object(scan, 'vuln_details', return_value=details):
                status, plain = self.report(root)
                gated, triaged = self.report(root, '--triage', '--fail-on', 'high')
        counts = plain['summary']['findings_by_file']
        self.assertEqual(counts, {'.env': 2, 'nested/.env': 1, 'requirements.txt': 1})
        self.assertEqual(list(counts), sorted(counts))
        self.assertEqual(sum(counts.values()), len(plain['findings']))
        self.assertEqual(len(counts), plain['summary']['files_with_findings'])
        self.assertEqual((status, gated), (0, 1))
        self.assertEqual(counts, triaged['summary']['findings_by_file'])
        self.assertEqual(plain['findings'], triaged['findings'])
        self.assertEqual(plain['manifest_hash'], triaged['manifest_hash'])
        canonical = json.dumps({k: plain[k] for k in ('findings', 'target', 'commit')},
                               sort_keys=True, separators=(',', ':'))
        self.assertEqual(plain['manifest_hash'], hashlib.sha256(canonical.encode()).hexdigest())

    def test_finding_caps_count_only_retained_findings(self):
        for limit in ('MAX_FINDINGS', 'MAX_FINDINGS_PER_FILE'):
            with self.subTest(limit=limit), tempfile.TemporaryDirectory() as root:
                Path(root, '.env').write_text('password="A1b2C3d4E5f6G7h8"')
                Path(root, 'z.env').write_text('password="Q1w2E3r4T5y6U7i8"')
                with mock.patch.object(scan, limit, 1):
                    status, report = self.report(root, '--no-osv')
                expected = {'.env': 1} if limit == 'MAX_FINDINGS' else {'.env': 1, 'z.env': 1}
                self.assertEqual(status, 0)
                self.assertEqual(report['summary']['findings_by_file'], expected)
                self.assertTrue(report['summary']['truncated']['findings'])
                self.assertEqual(sum(expected.values()), len(report['findings']))

    def test_file_cap_omits_unscanned_paths(self):
        with tempfile.TemporaryDirectory() as root:
            for name in ('a.txt', 'b.txt'):
                Path(root, name).write_text('password="A1b2C3d4E5f6G7h8"')
            with mock.patch.object(scan, 'MAX_FILES', 1):
                status, report = self.report(root, '--no-osv')
        self.assertEqual(status, 0)
        self.assertEqual(report['summary']['findings_by_file'], {'a.txt': 1})
        self.assertTrue(report['summary']['truncated']['files'])
