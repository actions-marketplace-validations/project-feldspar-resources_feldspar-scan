"""Report how many retained findings lack a source line, using offline fixtures."""
import contextlib
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from test_scan import scan


class FindingsWithoutLineTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.hits = {
            ('PyPI', 'demo-one', '1.0'): ['TEST-1'],
            ('PyPI', 'demo-two', '2.0'): ['TEST-2', 'TEST-3'],
        }

    def report(self, *options):
        with mock.patch.object(scan, 'query_osv', return_value=self.hits), \
                mock.patch.object(scan, 'vuln_details', return_value={
                    'severity': 'high', 'fixed_in': [], 'summary': 'Synthetic advisory'}), \
                contextlib.redirect_stdout(io.StringIO()) as out, \
                contextlib.redirect_stderr(io.StringIO()) as err:
            status = scan.main(['scan.py', str(self.root), '--no-timestamp',
                                '--no-commit', *options])
        return status, json.loads(out.getvalue()), err.getvalue()

    def fixture(self):
        (self.root / 'requirements.txt').write_text(chr(10).join(('demo-one==1.0', 'demo-two==2.0', '')))
        (self.root / 'Dockerfile').write_text('FROM scratch' + chr(10))
        (self.root / 'compose.yaml').write_text(chr(10).join(('services:', '  app:', '    privileged: true', '')))
        # Deliberately synthetic placeholder, never a real credential.
        (self.root / 'settings.txt').write_text('password="your_placeholder_value"' + chr(10))

    def test_empty_and_located_only_reports_are_zero(self):
        empty = self.report('--no-osv')[1]
        self.assertEqual(empty['summary']['findings_without_line'], 0)
        (self.root / 'compose.yaml').write_text('privileged: true' + chr(10))
        located = self.report('--no-osv')[1]
        self.assertEqual(len(located['findings']), 1)
        self.assertEqual(located['findings'][0]['line'], 1)
        self.assertEqual(located['summary']['findings_without_line'], 0)

    def test_counts_findings_not_files_or_advisories(self):
        self.fixture()
        status, report, _ = self.report('--triage', '--fail-on=high')
        self.assertEqual(status, 1)
        self.assertEqual(report['summary']['total_findings'], 5)
        self.assertEqual(report['summary']['findings_without_line'], 3)
        self.assertEqual(report['summary']['by_category'], {
            'dependency-vuln': 2, 'secret': 1, 'config': 2})
        unlocated = [f for f in report['findings'] if f['line'] is None]
        self.assertEqual([f['file'] for f in unlocated].count('requirements.txt'), 2)
        self.assertEqual([f['file'] for f in unlocated].count('Dockerfile'), 1)
        self.assertEqual(report['summary']['gate'], {
            'threshold': 'high', 'matching_findings': 2, 'passed': False})
        canonical = json.dumps({k: report[k] for k in ('findings', 'target', 'commit')},
                               sort_keys=True, separators=(',', ':'))
        self.assertEqual(report['manifest_hash'], hashlib.sha256(canonical.encode()).hexdigest())
        plain = self.report()[1]
        for key in ('findings', 'manifest_hash'):
            self.assertEqual(plain[key], report[key])

    def test_global_and_per_file_caps_count_only_retained_findings(self):
        self.fixture()
        for limit, maximum, expected in (
                ('MAX_FINDINGS', 0, 0), ('MAX_FINDINGS', 2, 2),
                ('MAX_FINDINGS_PER_FILE', 1, 2)):
            with self.subTest(limit=limit, maximum=maximum), \
                    mock.patch.object(scan, limit, maximum):
                report = self.report()[1]
            self.assertTrue(report['summary']['truncated']['findings'])
            self.assertEqual(report['summary']['findings_without_line'], expected)

    def test_summary_only_retains_count_and_gate_diagnostics(self):
        self.fixture()
        options = ('--triage', '--fail-on=high', '--compact', '--sort-keys')
        full_status, full, full_error = self.report(*options)
        status, abbreviated, error = self.report(*options, '--summary-only')
        self.assertEqual(abbreviated['summary']['findings_without_line'], 3)
        self.assertEqual((status, error), (full_status, full_error))
        full.pop('findings')
        full.pop('triage')
        self.assertEqual(abbreviated, full)
