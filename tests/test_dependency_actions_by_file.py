"""Per-manifest triage counts, using only synthetic offline advisories."""
import contextlib
import copy
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from test_scan import scan


class DependencyActionsByFileTests(unittest.TestCase):
    def report(self, root, *options):
        output = io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(io.StringIO()):
            status = scan.main(['scan.py', str(root), *options])
        return status, json.loads(output.getvalue())

    def test_mixed_actions_paths_and_categories_preserve_input(self):
        findings = [
            {'id': '1', 'category': 'dependency-vuln', 'file': 'z/requirements.txt',
             'package': 'sample-a', 'severity': 'high', 'fixed_in': ['2', '3']},
            {'id': '2', 'category': 'dependency-vuln', 'file': 'z/requirements.txt',
             'package': 'sample-b', 'severity': 'unknown', 'fixed_in': []},
            {'id': '3', 'category': 'dependency-vuln', 'file': 'z/requirements.txt',
             'package': 'sample-c', 'severity': 'low', 'fixed_in': []},
            {'id': '4', 'category': 'dependency-vuln', 'file': 'tests/go.sum',
             'package': 'sample-d', 'severity': 'critical', 'fixed_in': ['4']},
            {'id': '5', 'category': 'config', 'file': 'Dockerfile', 'severity': 'low'},
            {'id': '6', 'category': 'secret', 'file': 'tests/demo.txt', 'severity': 'high'},
        ]
        original = copy.deepcopy(findings)
        per_id, summary = scan.triage_findings(findings)
        self.assertEqual(findings, original)
        counts = summary['dependency_actions_by_file']
        self.assertEqual(counts, {
            'tests/go.sum': {'upgrade': 1, 'monitor': 0},
            'z/requirements.txt': {'upgrade': 1, 'monitor': 2}})
        self.assertEqual(list(counts), sorted(counts))
        self.assertTrue(per_id['4']['scaffold'])
        for action in ('upgrade', 'monitor'):
            self.assertEqual(sum(row[action] for row in counts.values()), summary['by_action'][action])
        self.assertEqual(scan.triage_findings([])[1]['dependency_actions_by_file'], {})

    def test_empty_and_non_dependency_reports(self):
        with tempfile.TemporaryDirectory() as root:
            for config in (False, True):
                if config:
                    Path(root, 'Dockerfile').write_text("""FROM python:latest
""")
                with self.subTest(config=config), mock.patch.object(scan, 'query_osv') as query:
                    _, doc = self.report(root, '--no-osv', '--triage')
                query.assert_not_called()
                self.assertEqual(doc['triage_summary']['dependency_actions_by_file'], {})

    def test_cli_opt_in_and_preserves_findings_hash_gate(self):
        with tempfile.TemporaryDirectory() as root:
            Path(root, 'requirements.txt').write_text("""sample-a==1.0
sample-b==1.0
""")
            Path(root, 'tests').mkdir()
            Path(root, 'tests', 'requirements.txt').write_text("""sample-c==1.0
""")
            hits = {('PyPI', 'sample-' + name, '1.0'): [name] for name in ('a', 'b', 'c')}
            def details(vid, cache):
                return {'severity': 'high', 'summary': 'Synthetic advisory',
                        'fixed_in': [] if vid == 'b' else ['2.0', '3.0']}
            with mock.patch.object(scan, 'query_osv', return_value=hits), \
                    mock.patch.object(scan, 'vuln_details', side_effect=details):
                plain_status, plain = self.report(root, '--fail-on', 'high')
                for options in ((), ('--compact', '--sort-keys')):
                    status, doc = self.report(root, '--triage', '--fail-on', 'high', *options)
                    self.assertEqual(status, plain_status)
                    self.assertEqual(status, 1)
                    self.assertEqual(doc['summary'], plain['summary'])
                    self.assertEqual(doc['findings'], plain['findings'])
                    self.assertEqual(doc['manifest_hash'], plain['manifest_hash'])
                    self.assertEqual(doc['triage_summary']['dependency_actions_by_file'], {
                        'requirements.txt': {'upgrade': 1, 'monitor': 1},
                        'tests/requirements.txt': {'upgrade': 1, 'monitor': 0}})
            self.assertNotIn('triage_summary', plain)

    def test_finding_caps_count_only_retained_dependencies(self):
        with tempfile.TemporaryDirectory() as root:
            Path(root, 'requirements.txt').write_text("""sample-a==1.0
sample-b==1.0
""")
            hits = {('PyPI', name, '1.0'): ['SYNTHETIC'] for name in ('sample-a', 'sample-b')}
            for limit in ('MAX_FINDINGS', 'MAX_FINDINGS_PER_FILE'):
                with self.subTest(limit=limit), mock.patch.object(scan, limit, 1), \
                        mock.patch.object(scan, 'query_osv', return_value=hits), \
                        mock.patch.object(scan, 'vuln_details', return_value={
                            'severity': 'high', 'summary': 'Synthetic advisory', 'fixed_in': []}):
                    _, doc = self.report(root, '--triage')
                self.assertTrue(doc['summary']['truncated']['findings'])
                self.assertEqual(doc['summary']['vulnerable_packages'], 2)
                self.assertEqual(doc['triage_summary']['dependency_actions_by_file'], {
                    'requirements.txt': {'upgrade': 0, 'monitor': 1}})
