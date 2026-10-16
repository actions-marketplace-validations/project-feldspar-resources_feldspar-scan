"""Reported fix counts use emitted findings, with synthetic offline advisories."""
import contextlib
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from test_scan import scan


class DependencyFixSummaryTests(unittest.TestCase):
    def report(self, root, *options):
        output = io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(io.StringIO()):
            status = scan.main(['scan.py', str(root), *options])
        return status, json.loads(output.getvalue())

    def test_empty_and_offline_inventory_have_zero_reported_fixes(self):
        for manifest in ('', """sample-package==1.0
"""):
            with self.subTest(manifest=manifest), tempfile.TemporaryDirectory() as root:
                Path(root, 'requirements.txt').write_text(manifest)
                with mock.patch.object(scan, 'query_osv') as query:
                    status, report = self.report(root, '--no-osv')
                query.assert_not_called()
                self.assertEqual(status, 0)
                self.assertEqual(report['summary']['dependency_findings_with_fixes'], 0)

    def test_count_is_per_finding_not_advisory_or_fixed_version(self):
        hits = {
            ('PyPI', 'sample-a', '1.0'): ['TEST-1', 'TEST-2'],
            ('PyPI', 'sample-a', '2.0'): ['TEST-3'],
            ('PyPI', 'sample-b', '1.0'): ['TEST-4'],
        }
        def details(vid, cache):
            return {'severity': 'high', 'summary': 'Synthetic advisory',
                    'fixed_in': [] if vid in ('TEST-2', 'TEST-4') else ['3.0', '4.0']}

        with tempfile.TemporaryDirectory() as root:
            Path(root, 'requirements.txt').write_text(
                """sample-a==1.0
sample-a==2.0
sample-b==1.0
""")
            Path(root, '.env').write_text('''password="A1b2C3d4E5f6G7h8"
''')
            with mock.patch.object(scan, 'query_osv', return_value=hits), \
                    mock.patch.object(scan, 'vuln_details', side_effect=details):
                status, plain = self.report(root)
                gated_status, triaged = self.report(root, '--triage', '--fail-on', 'high')
        self.assertEqual(status, 0)
        self.assertEqual(gated_status, 1)
        self.assertEqual(plain['summary']['vulnerable_packages'], 3)
        self.assertEqual(plain['summary']['dependency_findings_with_fixes'], 2)
        self.assertEqual(plain['summary']['secret_hits'], 1)
        self.assertEqual(plain['summary']['config_issues'], 1)
        self.assertNotIn('gate', plain['summary'])
        self.assertEqual(triaged['summary']['gate'], {
            'threshold': 'high', 'matching_findings': 4, 'passed': False})
        self.assertEqual(plain['summary'],
                         {k: v for k, v in triaged['summary'].items() if k != 'gate'})
        self.assertEqual(plain['findings'], triaged['findings'])
        self.assertEqual(plain['manifest_hash'], triaged['manifest_hash'])
        canonical = json.dumps({k: plain[k] for k in ('findings', 'target', 'commit')},
                               sort_keys=True, separators=(',', ':'))
        self.assertEqual(plain['manifest_hash'], hashlib.sha256(canonical.encode()).hexdigest())

    def test_vulnerable_package_without_fix_metadata_counts_zero(self):
        with tempfile.TemporaryDirectory() as root:
            Path(root, 'requirements.txt').write_text("""sample-package==1.0
""")
            with mock.patch.object(scan, 'query_osv', return_value={
                    ('PyPI', 'sample-package', '1.0'): ['TEST-1']}), \
                    mock.patch.object(scan, 'vuln_details', return_value={
                        'severity': 'unknown', 'summary': 'Synthetic advisory', 'fixed_in': []}):
                _, report = self.report(root)
        self.assertEqual(report['summary']['vulnerable_packages'], 1)
        self.assertEqual(report['summary']['dependency_findings_with_fixes'], 0)

    def test_finding_limits_count_only_emitted_dependencies(self):
        for limit in ('MAX_FINDINGS', 'MAX_FINDINGS_PER_FILE'):
            with self.subTest(limit=limit), tempfile.TemporaryDirectory() as root:
                Path(root, 'requirements.txt').write_text("""sample-a==1.0
sample-b==1.0
""")
                hits = {('PyPI', name, '1.0'): ['TEST-1'] for name in ('sample-a', 'sample-b')}
                with mock.patch.object(scan, 'query_osv', return_value=hits), \
                        mock.patch.object(scan, 'vuln_details', return_value={
                            'severity': 'high', 'summary': 'Synthetic advisory', 'fixed_in': ['2.0']}), \
                        mock.patch.object(scan, limit, 1):
                    _, report = self.report(root)
                self.assertTrue(report['summary']['truncated']['findings'])
                self.assertEqual(report['summary']['vulnerable_packages'], 2)
                self.assertEqual(len(report['findings']), 1)
                self.assertEqual(report['summary']['dependency_findings_with_fixes'], 1)
