"""Distinct affected-file counts, using synthetic fixtures and mocked OSV."""
import contextlib
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from test_scan import scan

NEWLINE = chr(10)


class CategoryFileSummaryTests(unittest.TestCase):
    def report(self, root, *options):
        output = io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(io.StringIO()):
            status = scan.main(['scan.py', str(root), *options])
        return status, json.loads(output.getvalue())

    def test_empty_and_clean_scans_include_all_zero_counts(self):
        with tempfile.TemporaryDirectory() as root:
            for populated in (False, True):
                with self.subTest(populated=populated):
                    if populated:
                        Path(root, 'notes.txt').write_text('ordinary text' + NEWLINE)
                    status, report = self.report(root, '--no-osv')
                    self.assertEqual(status, 0)
                    self.assertEqual(report['summary']['files_with_findings_by_category'],
                                     {'dependency-vuln': 0, 'secret': 0, 'config': 0})

    def test_duplicate_hits_overlap_and_distinct_paths(self):
        with tempfile.TemporaryDirectory() as root:
            Path(root, '.env').write_text(('password="A1b2C3d4E5f6G7h8"' + NEWLINE) * 2)
            Path(root, 'nested').mkdir()
            Path(root, 'nested', '.env').write_text('PORT=8080' + NEWLINE)
            Path(root, 'requirements.txt').write_text(NEWLINE.join(['sample-one==1.0', 'sample-two==2.0', '']))
            hits = {('PyPI', name, version): ['TEST-1', 'TEST-2']
                    for name, version in [('sample-one', '1.0'), ('sample-two', '2.0')]}
            details = {'severity': 'high', 'fixed_in': ['3.0'], 'summary': 'Synthetic advisory'}
            with mock.patch.object(scan, 'query_osv', return_value=hits), \
                    mock.patch.object(scan, 'vuln_details', return_value=details):
                status, plain = self.report(root)
                gated, triaged = self.report(root, '--triage', '--fail-on', 'high')
        self.assertEqual(status, 0)
        self.assertEqual(gated, 1)
        self.assertEqual(plain['summary']['by_category'],
                         {'dependency-vuln': 2, 'secret': 2, 'config': 2})
        expected = {'dependency-vuln': 1, 'secret': 1, 'config': 2}
        self.assertEqual(plain['summary']['files_with_findings_by_category'], expected)
        self.assertEqual(triaged['summary']['files_with_findings_by_category'], expected)
        self.assertEqual(plain['summary']['files_with_findings'], 3)
        self.assertEqual(plain['findings'], triaged['findings'])
        self.assertEqual(plain['manifest_hash'], triaged['manifest_hash'])
        canonical = json.dumps({k: plain[k] for k in ('findings', 'target', 'commit')},
                               sort_keys=True, separators=(',', ':'))
        self.assertEqual(plain['manifest_hash'], hashlib.sha256(canonical.encode()).hexdigest())

    def test_truncation_counts_only_emitted_paths_and_categories(self):
        for limit in ('MAX_FINDINGS', 'MAX_FINDINGS_PER_FILE'):
            with self.subTest(limit=limit), tempfile.TemporaryDirectory() as root:
                for filename in ('a.env', 'b.env'):
                    Path(root, filename).write_text(('password="A1b2C3d4E5f6G7h8"' + NEWLINE) * 2)
                with mock.patch.object(scan, limit, 1):
                    _, report = self.report(root, '--no-osv')
                self.assertTrue(report['summary']['truncated']['findings'])
                self.assertEqual(report['summary']['files_with_findings_by_category'],
                                 {'dependency-vuln': 0, 'secret': 1 if limit == 'MAX_FINDINGS' else 2,
                                  'config': 0})
