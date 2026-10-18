"""Multi-version inventory uses parsed packages, independently of findings."""
import contextlib
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from test_scan import scan


class MultiVersionPackagesTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name) / 'repo'
        self.root.mkdir()
        self.outfile = Path(tmp.name) / 'report.json'
        # Prevent all advisory HTTP calls, including tests selecting OSV mode.
        self.query = mock.patch.object(scan, 'query_osv', return_value={}).start()
        self.addCleanup(mock.patch.stopall)
        mock.patch.object(scan, 'vuln_details', return_value={
            'severity': 'high', 'fixed_in': ['3.0'], 'summary': 'Synthetic advisory'
        }).start()

    def report(self, *args, osv=False, named=False):
        stdout = io.StringIO()
        flags = [] if osv else ['--no-osv']
        if named:
            flags += ['--json', str(self.outfile)]
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(io.StringIO()):
            status = scan.main(['scan.py', str(self.root), *flags, *args])
        text = self.outfile.read_text() if named else stdout.getvalue()
        return status, json.loads(text), text

    def populate(self):
        (self.root / 'requirements.txt').write_text(
            chr(10).join(('zeta==2.0', 'zeta==10.0', 'alpha==3.0', 'alpha==1.0', 'single==1.0', '')))
        (self.root / 'requirements-dev.txt').write_text('zeta==2.0' + chr(10))
        (self.root / 'package-lock.json').write_text(json.dumps({'packages': {
            'node_modules/zeta': {'version': '4.0'},
            'node_modules/other/node_modules/zeta': {'version': '5.0'},
            'node_modules/single': {'version': '2.0'},
        }}))
        return {'PyPI': {'alpha': ['1.0', '3.0'], 'zeta': ['10.0', '2.0']},
                'npm': {'zeta': ['4.0', '5.0']}}

    def test_deduplicated_versions_and_ecosystem_name_separation(self):
        expected = self.populate()
        status, doc, _ = self.report()
        self.assertEqual(status, 0)
        self.query.assert_not_called()
        actual = doc['summary']['multi_version_packages']
        self.assertEqual(actual, expected)
        self.assertEqual(list(actual), ['PyPI', 'npm'])
        self.assertEqual(list(actual['PyPI']), ['alpha', 'zeta'])
        self.assertEqual(doc['summary']['packages_found'], 8)
        self.assertEqual(doc['findings'], [])

    def test_empty_single_version_and_repeated_invocations(self):
        self.populate()
        self.report()
        for path in self.root.iterdir():
            path.unlink()
        for content in (None, '# no pins' + chr(10), ('demo==1.0' + chr(10)) * 2):
            with self.subTest(content=content):
                if content is not None:
                    (self.root / 'requirements.txt').write_text(content)
                status, doc, _ = self.report()
                self.assertEqual(status, 0)
                self.assertEqual(doc['summary']['multi_version_packages'], {})

    def test_advisories_output_triage_gate_and_hash(self):
        expected = self.populate()
        self.query.return_value = {('PyPI', 'alpha', '1.0'): ['SYNTHETIC-1']}
        _, plain, _ = self.report(osv=True)
        status, doc, text = self.report('--triage', '--fail-on', 'high', '--compact',
                                        '--sort-keys', osv=True, named=True)
        self.assertEqual(status, 1)
        self.assertEqual(len(text.splitlines()), 1)
        self.assertEqual(doc['summary']['multi_version_packages'], expected)
        self.assertEqual(doc['findings'], plain['findings'])
        self.assertEqual(doc['manifest_hash'], plain['manifest_hash'])
        self.assertEqual(doc['summary']['gate'], {
            'threshold': 'high', 'matching_findings': 1, 'passed': False})
        self.assertIn('triage_summary', doc)
        canon = json.dumps({k: doc[k] for k in ('findings', 'target', 'commit')},
                           sort_keys=True, separators=(',', ':'))
        self.assertEqual(doc['manifest_hash'], hashlib.sha256(canon.encode()).hexdigest())

    def test_inventory_survives_finding_limits_but_respects_file_limit(self):
        expected = self.populate()
        (self.root / '.env').write_text('PORT=8080' + chr(10))
        for limit in ('MAX_FINDINGS', 'MAX_FINDINGS_PER_FILE'):
            with self.subTest(limit=limit), mock.patch.object(scan, limit, 0):
                _, doc, _ = self.report()
                self.assertEqual(doc['findings'], [])
                self.assertTrue(doc['summary']['truncated']['findings'])
                self.assertEqual(doc['summary']['multi_version_packages'], expected)
        with mock.patch.object(scan, 'MAX_FILES', 1):
            _, doc, _ = self.report()
            self.assertTrue(doc['summary']['truncated']['files'])
            self.assertEqual(doc['summary']['multi_version_packages'], {})
