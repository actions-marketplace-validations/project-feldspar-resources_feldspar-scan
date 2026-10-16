"""No-fix metadata counts; all advisory responses are synthetic and offline."""
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


class DependencyWithoutFixesTests(unittest.TestCase):
    def report(self, root, *options):
        output = io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(io.StringIO()):
            status = scan.main(['scan.py', str(root), *options])
        report = json.loads(output.getvalue())
        summary = report['summary']
        self.assertEqual(summary['dependency_findings_without_fixes'] +
                         summary['dependency_findings_with_fixes'],
                         summary['by_category']['dependency-vuln'])
        return status, report

    def test_empty_offline_and_config_only(self):
        for populated in (False, True):
            with self.subTest(populated=populated), tempfile.TemporaryDirectory() as root:
                if populated:
                    Path(root, 'requirements.txt').write_text('sample-a==1.0' + NL)
                    Path(root, 'Dockerfile').write_text('FROM alpine:3.20' + NL)
                with mock.patch.object(scan, 'query_osv') as query:
                    status, report = self.report(root, '--no-osv')
                query.assert_not_called()
                self.assertEqual(status, 0)
                self.assertEqual(report['summary']['dependency_findings_without_fixes'], 0)
                if populated:
                    self.assertGreater(report['summary']['config_issues'], 0)

    def test_mixed_advisories_count_findings_and_preserve_gate_and_hash(self):
        hits = {('PyPI', 'sample-a', '1.0'): ['SYNTH-1', 'SYNTH-2'],
                ('PyPI', 'sample-b', '1.0'): ['SYNTH-3', 'SYNTH-4'],
                ('PyPI', 'sample-b', '2.0'): ['SYNTH-3']}
        def details(vid, cache):
            return {'severity': 'high', 'summary': 'Synthetic advisory',
                    'fixed_in': ['3.0', '4.0'] if vid == 'SYNTH-1' else []}
        with tempfile.TemporaryDirectory() as root:
            Path(root, 'requirements.txt').write_text(
                'sample-a==1.0' + NL + 'sample-b==1.0' + NL + 'sample-b==2.0' + NL)
            with mock.patch.object(scan, 'query_osv', return_value=hits), \
                    mock.patch.object(scan, 'vuln_details', side_effect=details):
                status, plain = self.report(root)
                gated_status, gated = self.report(root, '--triage', '--fail-on', 'high')
        self.assertEqual((status, gated_status), (0, 1))
        self.assertEqual(plain['summary']['dependency_findings_without_fixes'], 2)
        self.assertEqual(plain['summary']['dependency_findings_with_fixes'], 1)
        self.assertEqual(gated['summary']['dependency_findings_without_fixes'], 2)
        self.assertEqual(gated['summary']['gate'], {
            'threshold': 'high', 'matching_findings': 3, 'passed': False})
        self.assertEqual(plain['findings'], gated['findings'])
        self.assertEqual(plain['manifest_hash'], gated['manifest_hash'])
        canonical = json.dumps({k: plain[k] for k in ('findings', 'target', 'commit')},
                               sort_keys=True, separators=(',', ':'))
        self.assertEqual(plain['manifest_hash'], hashlib.sha256(canonical.encode()).hexdigest())

    def test_no_hits_and_unknown_advisory_without_fix(self):
        for hits, expected in (({}, 0), ({('PyPI', 'sample-a', '1.0'): ['SYNTH-1']}, 1)):
            with self.subTest(expected=expected), tempfile.TemporaryDirectory() as root:
                Path(root, 'requirements.txt').write_text('sample-a==1.0' + NL)
                with mock.patch.object(scan, 'query_osv', return_value=hits), \
                        mock.patch.object(scan, 'vuln_details', return_value={
                            'severity': 'unknown', 'summary': 'Synthetic', 'fixed_in': []}):
                    status, report = self.report(root, '--fail-on', 'low')
                self.assertEqual(status, 0)
                self.assertEqual(report['summary']['dependency_findings_without_fixes'], expected)
                self.assertTrue(report['summary']['gate']['passed'])

    def test_caps_count_retained_findings_only(self):
        for limit in ('MAX_FINDINGS', 'MAX_FINDINGS_PER_FILE'):
            with self.subTest(limit=limit), tempfile.TemporaryDirectory() as root:
                Path(root, 'requirements.txt').write_text('sample-a==1.0' + NL + 'sample-b==1.0' + NL)
                hits = {('PyPI', name, '1.0'): ['SYNTH-1'] for name in ('sample-a', 'sample-b')}
                with mock.patch.object(scan, 'query_osv', return_value=hits), \
                        mock.patch.object(scan, 'vuln_details', return_value={
                            'severity': 'high', 'summary': 'Synthetic', 'fixed_in': []}), \
                        mock.patch.object(scan, limit, 1):
                    _, report = self.report(root)
                self.assertTrue(report['summary']['truncated']['findings'])
                self.assertEqual(report['summary']['vulnerable_packages'], 2)
                self.assertEqual(report['summary']['dependency_findings_without_fixes'], 1)
