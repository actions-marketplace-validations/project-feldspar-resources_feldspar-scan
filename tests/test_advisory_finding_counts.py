"""Advisory impact counts use synthetic offline responses and retained findings."""
import contextlib
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from test_scan import scan

NL = chr(10)


class AdvisoryFindingCountTests(unittest.TestCase):
    def report(self, root, *options):
        output = io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(io.StringIO()):
            status = scan.main(['scan.py', str(root), *options])
        report = json.loads(output.getvalue())
        counts = report['summary']['dependency_findings_by_advisory']
        self.assertEqual(list(counts), sorted(counts))
        self.assertEqual(len(counts), report['summary']['unique_advisories'])
        return status, report

    def test_empty_offline_and_no_hits(self):
        for populated in (False, True):
            for offline in (False, True):
                with self.subTest(populated=populated, offline=offline), \
                        tempfile.TemporaryDirectory() as root:
                    if populated:
                        Path(root, 'requirements.txt').write_text('sample-a==1.0' + NL)
                        Path(root, 'Dockerfile').write_text('FROM alpine:3.20' + NL)
                    with mock.patch.object(scan, 'query_osv', return_value={}) as query:
                        status, report = self.report(root, *(['--no-osv'] if offline else []))
                    if offline or not populated:
                        query.assert_not_called()
                    self.assertEqual(status, 0)
                    self.assertEqual(report['summary']['dependency_findings_by_advisory'], {})
                    if populated:
                        self.assertGreater(report['summary']['config_issues'], 0)

    def test_counts_deduplicate_ids_and_manifests_but_keep_package_versions(self):
        hits = {('PyPI', 'sample-a', '1.0'): ['SYNTH-Z', 'SYNTH-A', 'SYNTH-Z'],
                ('PyPI', 'sample-a', '2.0'): ['SYNTH-Z'],
                ('PyPI', 'sample-b', '1.0'): ['SYNTH-A'],
                ('npm', 'sample-a', '1.0'): ['SYNTH-Z']}
        with tempfile.TemporaryDirectory() as root:
            requirements = NL.join(('sample-a==1.0', 'sample-a==2.0', 'sample-b==1.0', ''))
            Path(root, 'requirements.txt').write_text(requirements)
            Path(root, 'nested').mkdir()
            Path(root, 'nested', 'requirements.txt').write_text(requirements)
            Path(root, 'package-lock.json').write_text(json.dumps({
                'lockfileVersion': 3, 'packages': {
                    'node_modules/sample-a': {'version': '1.0'}}}))
            with mock.patch.object(scan, 'query_osv', return_value=hits), \
                    mock.patch.object(scan, 'vuln_details', return_value={
                        'severity': 'high', 'summary': 'Synthetic advisory', 'fixed_in': []}):
                status, plain = self.report(root)
                gated_status, gated = self.report(root, '--triage', '--fail-on', 'high')
        self.assertEqual((status, gated_status), (0, 1))
        self.assertEqual(plain['summary']['packages_found'], 4)
        expected = {'SYNTH-A': 2, 'SYNTH-Z': 3}
        self.assertEqual(plain['summary']['dependency_findings_by_advisory'], expected)
        self.assertEqual(gated['summary']['dependency_findings_by_advisory'], expected)
        self.assertEqual(gated['summary']['gate'], {
            'threshold': 'high', 'matching_findings': 4, 'passed': False})
        self.assertEqual(plain['findings'], gated['findings'])
        self.assertEqual(plain['manifest_hash'], gated['manifest_hash'])
        canonical = json.dumps({k: plain[k] for k in ('findings', 'target', 'commit')},
                               sort_keys=True, separators=(',', ':'))
        self.assertEqual(plain['manifest_hash'], hashlib.sha256(canonical.encode()).hexdigest())

    def test_unknown_severity_is_counted_without_tripping_gate(self):
        with tempfile.TemporaryDirectory() as root:
            Path(root, 'requirements.txt').write_text('sample-a==1.0' + NL)
            with mock.patch.object(scan, 'query_osv', return_value={
                    ('PyPI', 'sample-a', '1.0'): ['SYNTH-UNKNOWN']}), \
                    mock.patch.object(scan, 'vuln_details', return_value={
                        'severity': 'unknown', 'summary': 'Synthetic', 'fixed_in': []}):
                status, report = self.report(root, '--fail-on', 'low')
        self.assertEqual(status, 0)
        self.assertEqual(report['summary']['dependency_findings_by_advisory'],
                         {'SYNTH-UNKNOWN': 1})
        self.assertTrue(report['summary']['gate']['passed'])

    def test_caps_count_retained_findings_only(self):
        hits = {('PyPI', 'sample-a', '1.0'): ['SYNTH-SHARED', 'SYNTH-A'],
                ('PyPI', 'sample-b', '1.0'): ['SYNTH-SHARED', 'SYNTH-B']}
        for limit in ('MAX_FINDINGS', 'MAX_FINDINGS_PER_FILE'):
            for cap in (0, 1):
                with self.subTest(limit=limit, cap=cap), tempfile.TemporaryDirectory() as root:
                    Path(root, 'requirements.txt').write_text('sample-a==1.0' + NL + 'sample-b==1.0' + NL)
                    with mock.patch.object(scan, 'query_osv', return_value=hits), \
                            mock.patch.object(scan, 'vuln_details', return_value={
                                'severity': 'high', 'summary': 'Synthetic', 'fixed_in': []}), \
                            mock.patch.object(scan, limit, cap):
                        _, report = self.report(root)
                    self.assertTrue(report['summary']['truncated']['findings'])
                    self.assertEqual(report['summary']['vulnerable_packages'], 2)
                    self.assertEqual(report['summary']['dependency_findings_by_advisory'],
                                     {'SYNTH-A': 1, 'SYNTH-SHARED': 1} if cap else {})
