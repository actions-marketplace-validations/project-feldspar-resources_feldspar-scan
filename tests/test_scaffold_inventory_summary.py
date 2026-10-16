"""Inventory path context is heuristic and independent of advisory lookup."""
import contextlib
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from test_scan import scan


class ScaffoldInventorySummaryTests(unittest.TestCase):
    def report(self, root, *options, osv=False):
        output = io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(io.StringIO()):
            status = scan.main(['scan.py', str(root),
                                *([] if osv else ['--no-osv']), *options])
        return status, json.loads(output.getvalue())

    def assert_counts(self, report, scaffold, other):
        counts = report['summary']['packages_by_path_context']
        self.assertEqual(counts, {'scaffold': scaffold, 'other': other})
        self.assertEqual(sum(counts.values()), report['summary']['packages_found'])

    def write(self, root, name, content):
        path = Path(root, name)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)

    def populate(self, root):
        self.write(root, 'examples/requirements.txt', """shared==1.0
sample==1.0
sample==2.0
sample==2.0
""")
        self.write(root, 'tests/requirements.txt', """sample==1.0
""")
        self.write(root, 'src/requirements.txt', """shared==1.0
production==1.0
""")
        self.write(root, 'tests/package-lock.json', json.dumps({
            'packages': {'node_modules/sample': {'version': '1.0'}}}))

    def test_empty_and_unpinned_inventory(self):
        with tempfile.TemporaryDirectory() as root:
            for text in (None, '# no pinned packages'):
                if text is not None:
                    self.write(root, 'tests/requirements.txt', text)
                status, report = self.report(root)
                self.assertEqual(status, 0)
                self.assert_counts(report, 0, 0)

    def test_deduplicated_tuples_and_other_path_attribution_preferred(self):
        with tempfile.TemporaryDirectory() as root:
            self.populate(root)
            with mock.patch.object(scan, 'query_osv', side_effect=AssertionError('offline')):
                _, report = self.report(root)
            self.assert_counts(report, 3, 2)

    def test_path_heuristic_does_not_classify_dependency_usage(self):
        for folder, scaffold in (('benchmarks', 1), ('fixtures', 1), ('testdata', 1),
                                 ('src', 0), ('contest', 0), ('production', 0)):
            with self.subTest(folder=folder), tempfile.TemporaryDirectory() as root:
                self.write(root, folder + '/requirements-dev.txt', 'demo==1.0')
                _, report = self.report(root)
                self.assert_counts(report, scaffold, 1 - scaffold)

    def test_advisories_triage_hash_and_gate(self):
        with tempfile.TemporaryDirectory() as root:
            self.populate(root)
            details = {'severity': 'high', 'fixed_in': ['3.0'], 'summary': 'Synthetic advisory'}
            with mock.patch.object(scan, 'query_osv', return_value={
                    ('PyPI', 'sample', '1.0'): ['SYNTHETIC-1']}), \
                    mock.patch.object(scan, 'vuln_details', return_value=details):
                status, plain = self.report(root, osv=True)
                gated, triaged = self.report(root, '--triage', '--fail-on', 'high', osv=True)
            self.assertEqual((status, gated), (0, 1))
            for report in (plain, triaged):
                self.assert_counts(report, 3, 2)
            self.assertEqual(plain['findings'], triaged['findings'])
            self.assertEqual(plain['manifest_hash'], triaged['manifest_hash'])
            canonical = json.dumps({k: plain[k] for k in ('findings', 'target', 'commit')},
                                   sort_keys=True, separators=(',', ':'))
            self.assertEqual(plain['manifest_hash'], hashlib.sha256(canonical.encode()).hexdigest())
            self.assertTrue(next(iter(triaged['triage'].values()))['scaffold'])

    def test_finding_limits_preserve_inventory_file_limits_bound_it(self):
        with tempfile.TemporaryDirectory() as root:
            self.populate(root)
            self.write(root, '.env', 'PORT=8080')
            with mock.patch.object(scan, 'MAX_FINDINGS', 0):
                _, report = self.report(root)
            self.assertTrue(report['summary']['truncated']['findings'])
            self.assertEqual(report['findings'], [])
            self.assert_counts(report, 3, 2)
            with mock.patch.object(scan, 'MAX_FILES', 1):
                _, report = self.report(root)
            self.assertTrue(report['summary']['truncated']['files'])
            self.assert_counts(report, 0, 0)
