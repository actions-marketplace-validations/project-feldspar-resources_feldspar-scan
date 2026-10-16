"""Per-manifest attribution coverage using local fixtures and mocked advisories."""
import contextlib
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from test_scan import scan


class ManifestInventorySummaryTests(unittest.TestCase):
    def report(self, root, *options, osv=False):
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(io.StringIO()):
            status = scan.main(['scan.py', str(root),
                                *([] if osv else ['--no-osv']), *options])
        return status, json.loads(stdout.getvalue())

    def assert_counts(self, report, expected):
        counts = report['summary']['packages_by_manifest']
        self.assertEqual(counts, expected)
        self.assertEqual(list(counts), sorted(counts))
        self.assertEqual(list(counts), report['summary']['lockfiles_parsed'])
        self.assertEqual(sum(counts.values()), report['summary']['packages_found'])

    def populate(self, root):
        Path(root, 'requirements.txt').write_text("""demo==1.0
demo==2.0
demo==2.0
""")
        Path(root, 'requirements-dev.txt').write_text("""demo==1.0
""")
        Path(root, 'package-lock.json').write_text(json.dumps({
            'packages': {'node_modules/demo': {'version': '1.0'}}}))
        Path(root, 'go.mod').write_text("""module example.invalid/app
""")
        Path(root, 'go.sum').write_text("""example.invalid/lib v1.0 h1:synthetic
""")

    def test_empty_and_zero_attribution_manifests(self):
        with tempfile.TemporaryDirectory() as root:
            _, report = self.report(root)
            self.assert_counts(report, {})
            Path(root, 'requirements.txt').write_text("""# no pins
""")
            _, report = self.report(root)
            self.assert_counts(report, {'requirements.txt': 0})

    def test_duplicates_versions_ecosystems_and_go_precedence(self):
        with tempfile.TemporaryDirectory() as root:
            self.populate(root)
            with mock.patch.object(scan, 'query_osv', side_effect=AssertionError('offline')):
                status, report = self.report(root)
            self.assertEqual(status, 0)
            self.assert_counts(report, {'go.mod': 0, 'package-lock.json': 1,
                                       'requirements-dev.txt': 1, 'requirements.txt': 1})

    def test_shipped_manifest_replaces_scaffold_attribution(self):
        with tempfile.TemporaryDirectory() as root:
            for folder in ('examples', 'src', 'tests'):
                Path(root, folder).mkdir()
                Path(root, folder, 'requirements.txt').write_text("""demo==1.0
""")
            _, report = self.report(root)
            self.assert_counts(report, {'examples/requirements.txt': 0,
                                       'src/requirements.txt': 1,
                                       'tests/requirements.txt': 0})

    def test_mocked_advisories_triage_and_gate_preserve_inventory_and_hash(self):
        with tempfile.TemporaryDirectory() as root:
            self.populate(root)
            _, offline = self.report(root)
            details = {'severity': 'high', 'fixed_in': ['3.0'], 'summary': 'Synthetic advisory'}
            with mock.patch.object(scan, 'query_osv', return_value={
                    ('PyPI', 'demo', '1.0'): ['SYNTHETIC-1']}), \
                    mock.patch.object(scan, 'vuln_details', return_value=details):
                status, plain = self.report(root, osv=True)
                gate, triaged = self.report(root, '--triage', '--fail-on', 'high', osv=True)
            self.assertEqual((status, gate), (0, 1))
            expected = offline['summary']['packages_by_manifest']
            for report in (plain, triaged):
                self.assert_counts(report, expected)
            self.assertEqual(len(plain['findings']), 1)
            self.assertEqual(plain['findings'][0]['file'], 'requirements-dev.txt')
            self.assertEqual(plain['findings'], triaged['findings'])
            self.assertEqual(plain['manifest_hash'], triaged['manifest_hash'])
            canon = json.dumps({key: plain[key] for key in ('findings', 'target', 'commit')},
                               sort_keys=True, separators=(',', ':'))
            self.assertEqual(plain['manifest_hash'], hashlib.sha256(canon.encode()).hexdigest())

    def test_finding_limits_preserve_inventory_and_file_limits_bound_it(self):
        with tempfile.TemporaryDirectory() as root:
            self.populate(root)
            Path(root, '.env').write_text("""PORT=8080
""")
            _, plain = self.report(root)
            with mock.patch.object(scan, 'MAX_FINDINGS', 0):
                _, limited = self.report(root)
            self.assertTrue(limited['summary']['truncated']['findings'])
            self.assertEqual(limited['findings'], [])
            self.assert_counts(limited, plain['summary']['packages_by_manifest'])
            with mock.patch.object(scan, 'MAX_FILES', 1):
                _, limited = self.report(root)
            self.assertTrue(limited['summary']['truncated']['files'])
            self.assert_counts(limited, {})
