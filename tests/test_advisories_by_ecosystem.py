"""Count distinct emitted advisory IDs per ecosystem without changing findings."""
import contextlib
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from test_scan import scan


class AdvisoriesByEcosystemTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.root = self.directory / 'repo'
        self.root.mkdir()
        (self.root / 'requirements.txt').write_text(chr(10).join(('alpha==1.0', 'beta==1.0', '')))
        (self.root / 'nested').mkdir()
        (self.root / 'nested/requirements.txt').write_text('alpha==2.0' + chr(10))
        (self.root / 'package-lock.json').write_text(json.dumps({
            'packages': {'node_modules/alpha': {'version': '1.0'}}}))
        (self.root / 'Dockerfile').write_text('FROM scratch' + chr(10))
        self.hits = {
            ('PyPI', 'alpha', '1.0'): ['TEST-SHARED', 'TEST-A', 'TEST-A'],
            ('PyPI', 'alpha', '2.0'): ['TEST-SHARED'],
            ('PyPI', 'beta', '1.0'): ['TEST-B'],
            ('npm', 'alpha', '1.0'): ['TEST-SHARED', 'TEST-NPM'],
        }
        query_patch = mock.patch.object(scan, 'query_osv', return_value=self.hits)
        self.query = query_patch.start()
        self.addCleanup(query_patch.stop)
        details_patch = mock.patch.object(scan, 'vuln_details', return_value={
            'severity': 'unknown', 'fixed_in': [], 'summary': 'Synthetic advisory'})
        details_patch.start()
        self.addCleanup(details_patch.stop)

    def report(self, *options):
        output = io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(io.StringIO()):
            status = scan.main(['scan.py', str(self.root), *options])
        return status, output.getvalue()

    def assert_counts(self, report, expected):
        counts = report['summary']['unique_advisories_by_ecosystem']
        self.assertEqual(counts, expected)
        self.assertEqual(list(counts), sorted(counts))
        canonical = json.dumps({'findings': report['findings'], 'target': report['target'],
                                'commit': report['commit']},
                               sort_keys=True, separators=(',', ':'))
        self.assertEqual(report['manifest_hash'], hashlib.sha256(canonical.encode()).hexdigest())

    def test_shared_and_duplicate_ids_across_versions_files_and_ecosystems(self):
        _, text = self.report()
        report = json.loads(text)
        self.assert_counts(report, {'PyPI': 3, 'npm': 2})
        self.assertEqual(report['summary']['unique_advisories'], 4)
        self.assertEqual(report['summary']['by_category']['dependency-vuln'], 4)
        self.assertEqual(report['summary']['dependency_findings_by_advisory']['TEST-SHARED'], 3)
        self.assertGreater(report['summary']['config_issues'], 0)

    def test_empty_offline_and_no_advisory_reports(self):
        _, offline = self.report('--no-osv')
        self.query.assert_not_called()
        self.assert_counts(json.loads(offline), {})
        self.query.return_value = {}
        _, checked = self.report()
        self.assert_counts(json.loads(checked), {})
        self.query.assert_called_once()
        self.root = self.directory / 'empty'
        self.root.mkdir()
        _, empty = self.report('--no-osv')
        self.assert_counts(json.loads(empty), {})

    def test_global_and_per_file_limits_count_only_retained_advisories(self):
        for constant, limit, expected in (
                ('MAX_FINDINGS', 1, {'PyPI': 2}),
                ('MAX_FINDINGS_PER_FILE', 1, {'PyPI': 2, 'npm': 2}),
                ('MAX_FINDINGS', 0, {})):
            with self.subTest(constant=constant, limit=limit), \
                    mock.patch.object(scan, constant, limit):
                _, text = self.report()
                report = json.loads(text)
                self.assert_counts(report, expected)
                self.assertTrue(report['summary']['truncated']['findings'])

    def test_formatting_triage_gate_and_named_output_preserve_data(self):
        status, text = self.report('--triage', '--fail-on', 'low')
        baseline = json.loads(text)
        self.assertEqual(status, 1)  # Config findings trigger; unknown advisories do not.
        self.assert_counts(baseline, {'PyPI': 3, 'npm': 2})
        self.assertEqual(baseline['summary']['gate']['matching_findings'],
                         baseline['summary']['config_issues'])
        for destination in ((), ('--json', str(self.directory / 'report.json'))):
            with self.subTest(destination=destination):
                status, text = self.report('--triage', '--fail-on', 'low', '--compact',
                                           '--sort-keys', '--unicode-json', *destination)
                self.assertEqual(status, 1)
                if destination:
                    self.assertEqual(text, '')
                    text = Path(destination[1]).read_text(encoding='utf-8')
                self.assertEqual(len(text.splitlines()), 1)
                report = json.loads(text)
                self.assert_counts(report, {'PyPI': 3, 'npm': 2})
                for item in (report, baseline):
                    item.pop('scanned_at', None)
                self.assertEqual(report, baseline)


if __name__ == '__main__':
    unittest.main()
