"""Distinct package-name counts describe inventory, independent of findings."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from test_scan import scan


class PackageNameCountsTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name) / 'repo'
        self.root.mkdir()
        self.output = Path(tmp.name) / 'report.json'
        patch = mock.patch.object(scan, 'query_osv', return_value={})
        self.query = patch.start()
        self.addCleanup(patch.stop)

    def report(self, *args, osv=False, named=False):
        stdout = io.StringIO()
        flags = [] if osv else ['--no-osv']
        if named:
            flags += ['--json', str(self.output)]
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(io.StringIO()):
            status = scan.main(['scan.py', str(self.root), *flags, *args])
        text = self.output.read_text() if named else stdout.getvalue()
        return status, json.loads(text), text

    def populate(self):
        (self.root / 'requirements.txt').write_text(
            chr(10).join(('shared==1.0', 'shared==2.0', 'solo==1.0', '')))
        (self.root / 'requirements-dev.txt').write_text('shared==1.0' + chr(10))
        (self.root / 'package-lock.json').write_text(json.dumps({'packages': {
            'node_modules/shared': {'version': '1.0'},
            'node_modules/nested/node_modules/shared': {'version': '2.0'},
            'node_modules/@scope/shared': {'version': '1.0'},
            'node_modules/solo': {'version': '1.0'},
        }}))

    def test_names_deduplicate_versions_and_manifests_within_ecosystem(self):
        self.populate()
        status, doc, _ = self.report()
        self.assertEqual(status, 0)
        self.query.assert_not_called()
        self.assertEqual(doc['summary']['packages_found'], 7)
        self.assertEqual(doc['summary']['packages_by_ecosystem'], {'PyPI': 3, 'npm': 4})
        self.assertEqual(doc['summary']['package_names_by_ecosystem'], {'PyPI': 2, 'npm': 3})
        self.assertEqual(list(doc['summary']['package_names_by_ecosystem']), ['PyPI', 'npm'])
        self.assertEqual(doc['findings'], [])

    def test_empty_unpinned_and_repeat_scans_do_not_retain_counts(self):
        self.populate()
        self.report()
        for path in self.root.iterdir():
            path.unlink()
        for content, expected in ((None, {}), ('unpinned' + chr(10), {}),
                                  (('single==1.0' + chr(10)) * 2, {'PyPI': 1})):
            with self.subTest(content=content):
                if content is not None:
                    (self.root / 'requirements.txt').write_text(content)
                _, doc, _ = self.report()
                self.assertEqual(doc['summary']['package_names_by_ecosystem'], expected)

    def test_advisories_gate_triage_and_named_output(self):
        self.populate()
        self.query.return_value = {('PyPI', 'shared', '1.0'): ['SYNTHETIC-1']}
        details = {'severity': 'high', 'fixed_in': ['3.0'], 'summary': 'Synthetic advisory'}
        with mock.patch.object(scan, 'vuln_details', return_value=details):
            _, plain, _ = self.report(osv=True)
            status, doc, text = self.report('--triage', '--fail-on', 'high', '--compact',
                                            '--sort-keys', osv=True, named=True)
        self.assertEqual(status, 1)
        self.assertEqual(len(text.splitlines()), 1)
        self.assertEqual(doc['summary']['package_names_by_ecosystem'], {'PyPI': 2, 'npm': 3})
        self.assertEqual(doc['findings'], plain['findings'])
        self.assertEqual(doc['manifest_hash'], plain['manifest_hash'])
        self.assertEqual(doc['summary']['gate'], {
            'threshold': 'high', 'matching_findings': 1, 'passed': False})
        self.assertEqual(doc['triage_summary']['by_action']['upgrade'], 1)

    def test_finding_caps_preserve_inventory_and_file_cap_bounds_it(self):
        self.populate()
        (self.root / '.env').write_text('PORT=8080' + chr(10))
        for limit in ('MAX_FINDINGS', 'MAX_FINDINGS_PER_FILE'):
            with self.subTest(limit=limit), mock.patch.object(scan, limit, 0):
                _, doc, _ = self.report()
                self.assertEqual(doc['summary']['package_names_by_ecosystem'],
                                 {'PyPI': 2, 'npm': 3})
                self.assertTrue(doc['summary']['truncated']['findings'])
                self.assertEqual(doc['findings'], [])
        with mock.patch.object(scan, 'MAX_FILES', 0):
            _, doc, _ = self.report()
            self.assertEqual(doc['summary']['package_names_by_ecosystem'], {})
            self.assertTrue(doc['summary']['truncated']['files'])
