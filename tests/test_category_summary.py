"""Category summary counts using offline, synthetic fixtures."""
import contextlib
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from test_scan import scan


class CategorySummaryTests(unittest.TestCase):
    def report(self, root, *options):
        output = io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(io.StringIO()):
            status = scan.main(['scan.py', str(root), *options])
        return status, json.loads(output.getvalue())

    def assert_counts(self, report, expected):
        counts = report['summary']['by_category']
        self.assertEqual(counts, expected)
        self.assertEqual(sum(counts.values()), len(report['findings']))
        self.assertEqual(counts['secret'], report['summary']['secret_hits'])
        self.assertEqual(counts['config'], report['summary']['config_issues'])

    def test_empty_scan_includes_zero_for_each_category(self):
        with tempfile.TemporaryDirectory() as root:
            status, report = self.report(root, '--no-osv')
        self.assertEqual(status, 0)
        self.assert_counts(report, {'dependency-vuln': 0, 'secret': 0, 'config': 0})

    def test_mixed_categories_count_findings_not_advisories_or_files(self):
        with tempfile.TemporaryDirectory() as root:
            Path(root, 'requirements.txt').write_text('sample-package==1.0\n')
            Path(root, '.env').write_text('password="A1b2C3d4E5f6G7h8"\n')
            key = ('PyPI', 'sample-package', '1.0')
            details = {'severity': 'high', 'fixed_in': ['1.1'], 'summary': 'Synthetic advisory'}
            with mock.patch.object(scan, 'query_osv', return_value={key: ['TEST-1', 'TEST-2']}), \
                    mock.patch.object(scan, 'vuln_details', return_value=details):
                status, plain = self.report(root)
                gated_status, triaged = self.report(root, '--triage', '--fail-on', 'high')
        self.assertEqual(status, 0)
        self.assertEqual(gated_status, 1)
        self.assert_counts(plain, {'dependency-vuln': 1, 'secret': 1, 'config': 1})
        self.assertEqual(plain['summary']['files_with_findings'], 2)
        self.assertEqual(plain['summary']['by_category'], triaged['summary']['by_category'])
        self.assertEqual(plain['findings'], triaged['findings'])
        self.assertEqual(plain['manifest_hash'], triaged['manifest_hash'])
        canonical = json.dumps({k: plain[k] for k in ('findings', 'target', 'commit')},
                               sort_keys=True, separators=(',', ':'))
        self.assertEqual(plain['manifest_hash'], hashlib.sha256(canonical.encode()).hexdigest())

    def test_no_osv_keeps_dependency_count_zero(self):
        with tempfile.TemporaryDirectory() as root:
            Path(root, 'requirements.txt').write_text('sample-package==1.0\n')
            with mock.patch.object(scan, 'query_osv') as query:
                status, report = self.report(root, '--no-osv')
                query.assert_not_called()
        self.assertEqual(status, 0)
        self.assertEqual(report['summary']['packages_found'], 1)
        self.assert_counts(report, {'dependency-vuln': 0, 'secret': 0, 'config': 0})

    def test_limits_count_only_emitted_findings(self):
        for limit in ('MAX_FINDINGS', 'MAX_FINDINGS_PER_FILE'):
            with self.subTest(limit=limit), tempfile.TemporaryDirectory() as root:
                Path(root, '.env').write_text('password="A1b2C3d4E5f6G7h8"\n')
                with mock.patch.object(scan, limit, 1):
                    _, report = self.report(root, '--no-osv')
                self.assertTrue(report['summary']['truncated']['findings'])
                self.assert_counts(report, {'dependency-vuln': 0, 'secret': 1, 'config': 0})
