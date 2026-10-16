"""Severity counts within each finding category, using only offline fixtures."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from test_scan import scan


class CategorySeveritySummaryTests(unittest.TestCase):
    def report(self, root, *options):
        output = io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(io.StringIO()):
            status = scan.main(['scan.py', str(root), *options])
        return status, json.loads(output.getvalue())

    def assert_counts(self, report, nonzero):
        expected = {category: dict.fromkeys(
            ('critical', 'high', 'medium', 'low', 'unknown'), 0)
            for category in ('dependency-vuln', 'secret', 'config')}
        for category, severities in nonzero.items():
            expected[category].update(severities)
        counts = report['summary']['by_category_severity']
        self.assertEqual(counts, expected)
        self.assertEqual({c: sum(row.values()) for c, row in counts.items()},
                         report['summary']['by_category'])
        for severity, total in report['summary']['by_severity'].items():
            self.assertEqual(sum(row[severity] for row in counts.values()), total)

    def test_empty_scan_has_zero_filled_categories(self):
        with tempfile.TemporaryDirectory() as root:
            status, report = self.report(root, '--no-osv')
        self.assertEqual(status, 0)
        self.assert_counts(report, {})

    def test_mixed_findings_with_unknown_dependency_severity(self):
        with tempfile.TemporaryDirectory() as root:
            Path(root, 'requirements.txt').write_text('sample-package==1.0')
            Path(root, '.env').write_text('password="A1b2C3d4E5f6G7h8"')
            key = ('PyPI', 'sample-package', '1.0')
            details = {'severity': 'unknown', 'fixed_in': [], 'summary': 'Synthetic advisory'}
            with mock.patch.object(scan, 'query_osv', return_value={key: ['TEST-1', 'TEST-2']}), \
                    mock.patch.object(scan, 'vuln_details', return_value=details):
                status, plain = self.report(root)
                gated_status, triaged = self.report(root, '--triage', '--fail-on', 'high')
        self.assertEqual(status, 0)
        self.assertEqual(gated_status, 1)
        self.assert_counts(plain, {'dependency-vuln': {'unknown': 1},
                                   'secret': {'medium': 1}, 'config': {'high': 1}})
        self.assertEqual(plain['summary']['by_category_severity'],
                         triaged['summary']['by_category_severity'])
        self.assertEqual(plain['findings'], triaged['findings'])
        self.assertEqual(plain['manifest_hash'], triaged['manifest_hash'])

    def test_multiple_severities_in_one_category_without_osv(self):
        with tempfile.TemporaryDirectory() as root:
            Path(root, 'settings.py').write_text(
                chr(10).join(['password="A1b2C3d4E5f6G7h8"', 'password="placeholder-value"']))
            with mock.patch.object(scan, 'query_osv') as query:
                status, report = self.report(root, '--no-osv')
                query.assert_not_called()
        self.assertEqual(status, 0)
        self.assert_counts(report, {'secret': {'medium': 1, 'low': 1}})

    def test_limits_count_only_emitted_findings(self):
        for limit in ('MAX_FINDINGS', 'MAX_FINDINGS_PER_FILE'):
            with self.subTest(limit=limit), tempfile.TemporaryDirectory() as root:
                Path(root, '.env').write_text('password="A1b2C3d4E5f6G7h8"')
                with mock.patch.object(scan, limit, 1):
                    _, report = self.report(root, '--no-osv')
                self.assertTrue(report['summary']['truncated']['findings'])
                self.assert_counts(report, {'secret': {'medium': 1}})
