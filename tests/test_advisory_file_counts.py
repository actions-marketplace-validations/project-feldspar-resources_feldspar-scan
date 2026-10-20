"""Distinct advisory file counts, using synthetic offline advisory responses."""
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


class AdvisoryFileCountTests(unittest.TestCase):
    def report(self, root, *flags):
        output = io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(io.StringIO()):
            status = scan.main(['scan.py', str(root), *flags])
        return status, json.loads(output.getvalue())

    def test_distinct_files_not_packages_versions_or_duplicate_ids(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            pins = NL.join(('sample-a==1.0', 'sample-a==2.0', 'sample-b==1.0', ''))
            (root / 'requirements.txt').write_text(pins)
            (root / 'nested').mkdir()
            (root / 'nested/requirements.txt').write_text(pins)
            (root / 'package-lock.json').write_text(json.dumps({
                'lockfileVersion': 3, 'packages': {
                    'node_modules/sample-a': {'version': '1.0'}}}))
            (root / 'Dockerfile').write_text('FROM alpine:3.20' + NL)
            hits = {('PyPI', 'sample-a', '1.0'): ['SYNTH-Z', 'SYNTH-A', 'SYNTH-Z'],
                    ('PyPI', 'sample-a', '2.0'): ['SYNTH-Z'],
                    ('PyPI', 'sample-b', '1.0'): ['SYNTH-A'],
                    ('npm', 'sample-a', '1.0'): ['SYNTH-Z']}
            with mock.patch.object(scan, 'query_osv', return_value=hits), \
                    mock.patch.object(scan, 'vuln_details', return_value={
                        'severity': 'high', 'summary': 'Synthetic', 'fixed_in': ['3.0']}):
                status, plain = self.report(root)
                gated_status, gated = self.report(root, '--triage', '--fail-on', 'high',
                                                 '--compact', '--sort-keys')
        self.assertEqual((status, gated_status), (0, 1))
        self.assertEqual(plain['summary']['packages_found'], 4)
        self.assertEqual(plain['summary']['dependency_findings_by_advisory'],
                         {'SYNTH-A': 2, 'SYNTH-Z': 3})
        expected = {'SYNTH-A': 1, 'SYNTH-Z': 2}
        self.assertEqual(plain['summary']['dependency_files_by_advisory'], expected)
        self.assertEqual(list(plain['summary']['dependency_files_by_advisory']),
                         ['SYNTH-A', 'SYNTH-Z'])
        self.assertEqual(gated['summary']['dependency_files_by_advisory'], expected)
        self.assertEqual(gated['summary']['gate'], {
            'threshold': 'high', 'matching_findings': 4, 'passed': False})
        self.assertEqual(gated['triage_summary']['by_action']['upgrade'], 4)
        self.assertEqual(plain['findings'], gated['findings'])
        self.assertEqual(plain['manifest_hash'], gated['manifest_hash'])
        canonical = json.dumps({k: plain[k] for k in ('findings', 'target', 'commit')},
                               sort_keys=True, separators=(',', ':'))
        self.assertEqual(plain['manifest_hash'], hashlib.sha256(canonical.encode()).hexdigest())

    def test_empty_offline_and_no_advisories(self):
        with tempfile.TemporaryDirectory() as root:
            with mock.patch.object(scan, 'query_osv', return_value={}) as query:
                _, empty = self.report(root)
                query.assert_not_called()
                Path(root, 'requirements.txt').write_text('sample-a==1.0' + NL)
                Path(root, 'Dockerfile').write_text('FROM alpine:3.20' + NL)
                _, offline = self.report(root, '--no-osv')
                query.assert_not_called()
                _, no_hits = self.report(root)
                query.assert_called_once()
        for report in (empty, offline, no_hits):
            self.assertEqual(report['summary']['dependency_files_by_advisory'], {})
        self.assertGreater(no_hits['summary']['config_issues'], 0)

    def test_unknown_severity_counts_in_named_output_without_firing_gate(self):
        with tempfile.TemporaryDirectory() as root, tempfile.TemporaryDirectory() as output:
            Path(root, 'requirements.txt').write_text('sample-a==1.0' + NL)
            destination = Path(output, 'report.json')
            with mock.patch.object(scan, 'query_osv', return_value={
                    ('PyPI', 'sample-a', '1.0'): ['SYNTH-UNKNOWN']}), \
                    mock.patch.object(scan, 'vuln_details', return_value={
                        'severity': 'unknown', 'summary': 'Synthetic', 'fixed_in': []}), \
                    contextlib.redirect_stderr(io.StringIO()):
                status = scan.main(['scan.py', root, '--fail-on', 'low',
                                    '--json=' + str(destination)])
            report = json.loads(destination.read_text())
        self.assertEqual(status, 0)
        self.assertEqual(report['summary']['dependency_files_by_advisory'],
                         {'SYNTH-UNKNOWN': 1})
        self.assertTrue(report['summary']['gate']['passed'])

    def test_limits_only_count_retained_paths_and_advisories(self):
        with tempfile.TemporaryDirectory() as root:
            Path(root, 'requirements.txt').write_text(NL.join(('sample-a==1.0', 'sample-b==1.0', '')))
            Path(root, 'other').mkdir()
            Path(root, 'other/requirements.txt').write_text('sample-c==1.0' + NL)
            hits = {('PyPI', 'sample-a', '1.0'): ['SYNTH-SHARED', 'SYNTH-A'],
                    ('PyPI', 'sample-b', '1.0'): ['SYNTH-SHARED', 'SYNTH-B'],
                    ('PyPI', 'sample-c', '1.0'): ['SYNTH-SHARED', 'SYNTH-C']}
            for limit, cap, expected in (
                    ('MAX_FINDINGS', 0, {}),
                    ('MAX_FINDINGS', 1, {'SYNTH-A': 1, 'SYNTH-SHARED': 1}),
                    ('MAX_FINDINGS_PER_FILE', 1,
                     {'SYNTH-A': 1, 'SYNTH-C': 1, 'SYNTH-SHARED': 2})):
                with self.subTest(limit=limit, cap=cap), \
                        mock.patch.object(scan, 'query_osv', return_value=hits), \
                        mock.patch.object(scan, 'vuln_details', return_value={
                            'severity': 'high', 'summary': 'Synthetic', 'fixed_in': []}), \
                        mock.patch.object(scan, limit, cap):
                    _, report = self.report(root)
                self.assertTrue(report['summary']['truncated']['findings'])
                self.assertEqual(report['summary']['vulnerable_packages'], 3)
                self.assertEqual(report['summary']['dependency_files_by_advisory'], expected)
