"""Offline checks for retained dependency action counts by ecosystem."""
import contextlib
import copy
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from test_scan import scan


class DependencyActionsEcosystemTests(unittest.TestCase):
    def test_mixed_ecosystems_actions_scaffolds_and_missing_metadata(self):
        findings = [
            dict(id='a', category='dependency-vuln', ecosystem='npm',
                 file='tests/package-lock.json', package='sample', fixed_in=['2', '3']),
            dict(id='b', category='dependency-vuln', ecosystem='PyPI',
                 file='requirements.txt', package='sample', fixed_in=[]),
            dict(id='c', category='dependency-vuln', ecosystem='npm',
                 file='package-lock.json', package='sample', fixed_in=['2']),
            dict(id='d', category='dependency-vuln', ecosystem='npm',
                 file='package-lock.json', package='other', fixed_in=[]),
            dict(id='e', category='dependency-vuln', file='manifest'),
            dict(id='f', category='config', severity='high', file='Dockerfile'),
            dict(id='g', category='secret', severity='high',
                 file='settings.txt', evidence='synthetic'),
        ]
        before = copy.deepcopy(findings)
        actions, summary = scan.triage_findings(findings)
        counts = summary['dependency_actions_by_ecosystem']
        self.assertEqual(list(counts), ['PyPI', 'npm', 'unknown'])
        self.assertEqual(counts, {
            'PyPI': {'upgrade': 0, 'monitor': 1},
            'npm': {'upgrade': 2, 'monitor': 1},
            'unknown': {'upgrade': 0, 'monitor': 1},
        })
        self.assertTrue(actions['a']['scaffold'])
        self.assertEqual(actions['a']['priority'], 'low')
        self.assertEqual(findings, before)
        for action in ('upgrade', 'monitor'):
            self.assertEqual(sum(row[action] for row in counts.values()),
                             summary['by_action'][action])
        self.assertEqual(scan.triage_findings(list(reversed(findings)))[1]
                         ['dependency_actions_by_ecosystem'], counts)

    def report(self, root, *args):
        output = io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(io.StringIO()):
            status = scan.main(['scan.py', str(root), *args])
        return status, json.loads(output.getvalue())

    def test_empty_offline_and_repeated_invocations(self):
        self.assertEqual(scan.triage_findings([])[1]['dependency_actions_by_ecosystem'], {})
        with tempfile.TemporaryDirectory() as root:
            Path(root, 'requirements.txt').write_text('sample==1.0' + chr(10))
            Path(root, 'Dockerfile').write_text('FROM scratch' + chr(10))
            with mock.patch.object(scan, 'query_osv') as query:
                for _ in range(2):
                    status, report = self.report(root, '--no-osv', '--triage')
                    self.assertEqual(status, 0)
                    self.assertEqual(report['triage_summary']['dependency_actions_by_ecosystem'], {})
                    self.assertGreater(report['summary']['config_issues'], 0)
            query.assert_not_called()

    def test_cli_counts_format_gate_hash_and_limits(self):
        hits = {('PyPI', 'sample-a', '1.0'): ['TEST-A', 'TEST-B'],
                ('npm', 'sample-b', '1.0'): ['TEST-C']}

        def details(vid, cache):
            return dict(severity='high', summary='Synthetic advisory',
                        fixed_in=['2.0', '3.0'] if vid == 'TEST-A' else [])

        with tempfile.TemporaryDirectory() as root:
            Path(root, 'requirements.txt').write_text('sample-a==1.0' + chr(10))
            Path(root, 'package-lock.json').write_text(json.dumps({
                'lockfileVersion': 3, 'packages': {
                    'node_modules/sample-b': {'version': '1.0'}}}))
            with mock.patch.object(scan, 'query_osv', return_value=hits), \
                    mock.patch.object(scan, 'vuln_details', side_effect=details):
                plain_status, plain = self.report(root, '--fail-on', 'high')
                status, report = self.report(root, '--triage', '--fail-on', 'high',
                                             '--compact', '--sort-keys')
                self.assertEqual((plain_status, status), (1, 1))
                self.assertNotIn('triage_summary', plain)
                self.assertEqual(report['triage_summary']['dependency_actions_by_ecosystem'], {
                    'PyPI': {'upgrade': 1, 'monitor': 0},
                    'npm': {'upgrade': 0, 'monitor': 1}})
                for key in ('findings', 'summary', 'manifest_hash'):
                    self.assertEqual(plain[key], report[key])
                for limit, value in (('MAX_FINDINGS', 1), ('MAX_FINDINGS', 0),
                                     ('MAX_FINDINGS_PER_FILE', 0)):
                    with self.subTest(limit=limit, value=value), \
                            mock.patch.object(scan, limit, value):
                        _, capped = self.report(root, '--triage')
                    self.assertTrue(capped['summary']['truncated']['findings'])
                    counts = capped['triage_summary']['dependency_actions_by_ecosystem']
                    self.assertEqual(sum(sum(row.values()) for row in counts.values()), value)
                    self.assertEqual(set(counts), {f['ecosystem'] for f in capped['findings']})

    def test_named_output_matches_stdout(self):
        with tempfile.TemporaryDirectory() as root, tempfile.TemporaryDirectory() as output:
            destination = Path(output, 'report.json')
            _, expected = self.report(root, '--no-osv', '--triage')
            with contextlib.redirect_stdout(io.StringIO()) as stdout, \
                    contextlib.redirect_stderr(io.StringIO()):
                status = scan.main(['scan.py', root, '--no-osv', '--triage',
                                    '--json', str(destination), '--compact'])
            actual = json.loads(destination.read_text())
            for report in (actual, expected):
                report.pop('scanned_at')
            self.assertEqual(status, 0)
            self.assertEqual(stdout.getvalue(), '')
            self.assertEqual(actual, expected)
