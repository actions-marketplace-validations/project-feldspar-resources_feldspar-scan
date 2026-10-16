"""Count distinct advisory IDs in emitted findings using synthetic offline data."""
import contextlib
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from test_scan import scan


class UniqueAdvisorySummaryTests(unittest.TestCase):
    def report(self, root, *options):
        output = io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(io.StringIO()):
            status = scan.main(['scan.py', str(root), *options])
        return status, json.loads(output.getvalue())

    def populate(self, root):
        Path(root, 'requirements.txt').write_text('''alpha==1.0
alpha==2.0
beta==1.0
''')

    def advisories(self):
        return {
            ('PyPI', 'alpha', '1.0'): ['SYNTHETIC-1', 'SYNTHETIC-2'],
            ('PyPI', 'alpha', '2.0'): ['SYNTHETIC-1'],
            ('PyPI', 'beta', '1.0'): ['SYNTHETIC-2', 'SYNTHETIC-ALIAS'],
        }

    def details(self):
        return {'severity': 'high', 'fixed_in': ['3.0'], 'summary': 'Synthetic advisory'}

    def test_empty_and_offline_inventory_report_zero(self):
        with tempfile.TemporaryDirectory() as root:
            with mock.patch.object(scan, 'query_osv', side_effect=AssertionError('offline')):
                for populated in (False, True):
                    with self.subTest(populated=populated):
                        if populated:
                            self.populate(root)
                        status, report = self.report(root, '--no-osv')
                        self.assertEqual(status, 0)
                        self.assertEqual(report['summary']['unique_advisories'], 0)
                        self.assertEqual(report['summary']['packages_found'], 3 if populated else 0)

    def test_shared_ids_count_once_but_distinct_alias_ids_remain_distinct(self):
        with tempfile.TemporaryDirectory() as root:
            self.populate(root)
            with mock.patch.object(scan, 'query_osv', return_value=self.advisories()), \
                    mock.patch.object(scan, 'vuln_details', return_value=self.details()):
                status, plain = self.report(root)
                gated, triaged = self.report(root, '--triage', '--fail-on', 'high')
        self.assertEqual((status, gated), (0, 1))
        self.assertEqual(plain['summary']['unique_advisories'], 3)
        self.assertEqual(plain['summary']['vulnerable_packages'], 3)
        self.assertEqual(sum(len(f['vuln_ids']) for f in plain['findings']), 5)
        self.assertEqual(plain['findings'], triaged['findings'])
        self.assertNotIn('gate', plain['summary'])
        self.assertEqual(triaged['summary'], {
            **plain['summary'],
            'gate': {'threshold': 'high', 'matching_findings': 3, 'passed': False},
        })
        self.assertEqual(plain['manifest_hash'], triaged['manifest_hash'])
        canonical = json.dumps({k: plain[k] for k in ('findings', 'target', 'commit')},
                               sort_keys=True, separators=(',', ':'))
        self.assertEqual(plain['manifest_hash'], hashlib.sha256(canonical.encode()).hexdigest())

    def test_scan_limits_count_only_emitted_advisories(self):
        with tempfile.TemporaryDirectory() as root:
            self.populate(root)
            for limit, value, expected in [('MAX_FINDINGS', 1, 2),
                                           ('MAX_FINDINGS_PER_FILE', 1, 2),
                                           ('MAX_FILES', 0, 0)]:
                with self.subTest(limit=limit), mock.patch.object(scan, limit, value), \
                        mock.patch.object(scan, 'query_osv', return_value=self.advisories()), \
                        mock.patch.object(scan, 'vuln_details', return_value=self.details()):
                    _, report = self.report(root)
                self.assertEqual(report['summary']['unique_advisories'], expected)
                self.assertTrue(any(report['summary']['truncated'].values()))

    def test_non_dependency_findings_do_not_contribute(self):
        def config(root, files, add):
            add('config', 'low', 'config.txt', 1, 'Synthetic config', 'redacted',
                vuln_ids=['SYNTHETIC-NON-DEPENDENCY'])

        with tempfile.TemporaryDirectory() as root, mock.patch.object(scan, 'scan_config', config):
            _, report = self.report(root, '--no-osv')
        self.assertEqual(len(report['findings']), 1)
        self.assertEqual(report['summary']['unique_advisories'], 0)

    def test_lookup_without_advisories_reports_zero(self):
        with tempfile.TemporaryDirectory() as root:
            self.populate(root)
            with mock.patch.object(scan, 'query_osv', return_value={}):
                _, report = self.report(root)
        self.assertTrue(report['summary']['osv_enabled'])
        self.assertEqual(report['summary']['unique_advisories'], 0)
