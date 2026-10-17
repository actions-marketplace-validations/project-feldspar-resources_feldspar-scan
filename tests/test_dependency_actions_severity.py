"""Offline coverage for dependency triage action/severity counts."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from test_scan import scan


class DependencyActionsSeverityTests(unittest.TestCase):
    def test_actions_severities_scaffolds_and_other_categories(self):
        findings = []
        for action in ('upgrade', 'monitor'):
            for severity in ('critical', 'high', 'medium', 'low', 'unknown'):
                findings.append(dict(id=action + severity, category='dependency-vuln',
                    severity=severity, file='tests/requirements.txt', package='sample',
                    fixed_in=['2.0', '3.0'] if action == 'upgrade' else []))
        findings.extend([
            dict(id='missing', category='dependency-vuln', file='requirements.txt'),
            dict(id='config', category='config', severity='high'),
            dict(id='secret', category='secret', severity='high',
                 file='settings.txt', evidence='synthetic'),
        ])
        per_id, summary = scan.triage_findings(findings)
        self.assertEqual(summary['dependency_actions_by_severity'], {
            'upgrade': dict(critical=1, high=1, medium=1, low=1, unknown=1),
            'monitor': dict(critical=1, high=1, medium=1, low=1, unknown=2),
        })
        self.assertEqual(summary['dependency'], dict(
            upgradeable=5, monitor_only=6, in_scaffold_lockfiles=10))
        for f in findings[:10]:
            self.assertEqual(per_id[f['id']]['action'],
                             'upgrade' if f['fixed_in'] else 'monitor')
            self.assertTrue(per_id[f['id']]['scaffold'])
            self.assertEqual(per_id[f['id']]['priority'], 'low')

    def report(self, root, *args):
        output = io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(io.StringIO()):
            status = scan.main(['scan.py', str(root), *args])
        return status, json.loads(output.getvalue())

    def test_empty_and_disabled_lookup_zero_buckets(self):
        for manifest in ('', 'sample==1.0' + chr(10)):
            with self.subTest(manifest=manifest), tempfile.TemporaryDirectory() as root:
                Path(root, 'requirements.txt').write_text(manifest)
                with mock.patch.object(scan, 'query_osv') as query:
                    status, report = self.report(root, '--no-osv', '--triage')
                query.assert_not_called()
                self.assertEqual(status, 0)
                self.assertEqual(report['triage_summary']['dependency_actions_by_severity'], {
                    action: dict(critical=0, high=0, medium=0, low=0, unknown=0)
                    for action in ('upgrade', 'monitor')})

    def test_cli_opt_in_gate_hash_and_retained_counts(self):
        hits = {('PyPI', 'sample-a', '1.0'): ['TEST-A', 'TEST-B'],
                ('PyPI', 'sample-b', '1.0'): ['TEST-C']}

        def details(vid, cache):
            return dict(severity='high' if vid == 'TEST-A' else 'unknown',
                        summary='Synthetic advisory',
                        fixed_in=['2.0', '3.0'] if vid == 'TEST-A' else [])

        with tempfile.TemporaryDirectory() as root:
            Path(root, 'requirements.txt').write_text(chr(10).join(('sample-a==1.0', 'sample-b==1.0', '')))
            with mock.patch.object(scan, 'query_osv', return_value=hits), \
                    mock.patch.object(scan, 'vuln_details', side_effect=details):
                plain_status, plain = self.report(root, '--fail-on', 'high')
                status, report = self.report(root, '--triage', '--fail-on', 'high')
                self.assertEqual((plain_status, status), (1, 1))
                self.assertNotIn('triage_summary', plain)
                for key in ('findings', 'summary', 'manifest_hash'):
                    self.assertEqual(plain[key], report[key])
                self.assertEqual(report['triage_summary']['dependency_actions_by_severity'], {
                    'upgrade': dict(critical=0, high=1, medium=0, low=0, unknown=0),
                    'monitor': dict(critical=0, high=0, medium=0, low=0, unknown=1)})
                for limit, value in (('MAX_FINDINGS', 1), ('MAX_FINDINGS_PER_FILE', 1),
                                     ('MAX_FINDINGS', 0)):
                    with self.subTest(limit=limit, value=value), \
                            mock.patch.object(scan, limit, value):
                        _, capped = self.report(root, '--triage')
                    self.assertTrue(capped['summary']['truncated']['findings'])
                    counts = capped['triage_summary']['dependency_actions_by_severity']
                    self.assertEqual(sum(sum(row.values()) for row in counts.values()), value)
                    self.assertEqual(counts['upgrade']['high'], value)
                    self.assertEqual(sum(counts['monitor'].values()), 0)
