"""Offline coverage for inventory counts by ecosystem, independent of advisories."""
import contextlib
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from test_scan import scan


class EcosystemSummaryTests(unittest.TestCase):
    def report(self, root, *options, osv=False):
        stdout = io.StringIO()
        args = ['scan.py', str(root), *([] if osv else ['--no-osv']), *options]
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(io.StringIO()):
            status = scan.main(args)
        return status, json.loads(stdout.getvalue())

    def assert_counts(self, report, expected):
        counts = report['summary']['packages_by_ecosystem']
        self.assertEqual(counts, expected)
        self.assertEqual(list(counts), sorted(counts))
        self.assertEqual(sum(counts.values()), report['summary']['packages_found'])

    def populate(self, root):
        Path(root, 'requirements.txt').write_text("""demo==1.0
demo==2.0
""")
        Path(root, 'requirements-dev.txt').write_text("""demo==1.0
""")
        Path(root, 'package-lock.json').write_text(json.dumps({
            'packages': {'node_modules/demo': {'version': '1.0'}}}))
        Path(root, 'go.mod').write_text("""module example.invalid/app
require example.invalid/lib v1.2.3
""")
        Path(root, 'go.sum').write_text("""example.invalid/lib v0.9.0 h1:synthetic
""")

    def test_empty_clean_and_empty_manifest_have_no_ecosystems(self):
        with tempfile.TemporaryDirectory() as root:
            for filename, content in [(None, ''), ('notes.txt', 'plain text'),
                                      ('requirements.txt', '# no pinned packages')]:
                with self.subTest(filename=filename):
                    if filename:
                        Path(root, filename).write_text(content)
                    status, report = self.report(root)
                    self.assertEqual(status, 0)
                    self.assert_counts(report, {})

    def test_unique_versions_and_ecosystems_count_once_across_manifests(self):
        with tempfile.TemporaryDirectory() as root:
            self.populate(root)
            with mock.patch.object(scan, 'query_osv', side_effect=AssertionError('offline')):
                status, report = self.report(root)
            self.assertEqual(status, 0)
            self.assert_counts(report, {'Go': 1, 'PyPI': 2, 'npm': 1})
            self.assertNotIn('go.sum', report['summary']['lockfiles_parsed'])
            self.assertEqual(report['findings'], [])

    def test_advisories_triage_and_gate_do_not_change_inventory(self):
        with tempfile.TemporaryDirectory() as root:
            self.populate(root)
            _, offline = self.report(root)
            advisory = {'severity': 'high', 'fixed_in': ['3.0'], 'summary': 'Synthetic advisory'}
            with mock.patch.object(scan, 'query_osv', return_value={
                    ('PyPI', 'demo', '1.0'): ['SYNTHETIC-1', 'SYNTHETIC-2']}), \
                    mock.patch.object(scan, 'vuln_details', return_value=advisory):
                status, plain = self.report(root, osv=True)
                gate, triaged = self.report(root, '--triage', '--fail-on', 'high', osv=True)
            self.assertEqual((status, gate), (0, 1))
            self.assertEqual(len(plain['findings']), 1)
            for report in (offline, plain, triaged):
                self.assert_counts(report, {'Go': 1, 'PyPI': 2, 'npm': 1})
            self.assertEqual(plain['findings'], triaged['findings'])
            self.assertEqual(plain['manifest_hash'], triaged['manifest_hash'])
            canon = json.dumps({key: plain[key] for key in ('findings', 'target', 'commit')},
                               sort_keys=True, separators=(',', ':'))
            self.assertEqual(plain['manifest_hash'], hashlib.sha256(canon.encode()).hexdigest())

    def test_finding_limits_preserve_inventory_but_file_limit_bounds_it(self):
        with tempfile.TemporaryDirectory() as root:
            self.populate(root)
            Path(root, '.env').write_text('PORT=8080')
            with mock.patch.object(scan, 'MAX_FINDINGS', 0):
                _, report = self.report(root)
            self.assertTrue(report['summary']['truncated']['findings'])
            self.assertEqual(report['findings'], [])
            self.assert_counts(report, {'Go': 1, 'PyPI': 2, 'npm': 1})
            with mock.patch.object(scan, 'MAX_FILES', 1):
                _, report = self.report(root)
            self.assertTrue(report['summary']['truncated']['files'])
            self.assertEqual(report['summary']['files_scanned'], 1)
            self.assert_counts(report, {})
