"""Configuration review must not disappear from the triage headline."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from test_scan import scan


class ConfigTriageTests(unittest.TestCase):
    def report(self, root, *options):
        output = io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(io.StringIO()):
            status = scan.main(['scan.py', str(root), '--no-osv', *options])
        return status, json.loads(output.getvalue())

    def test_empty_scan_retains_empty_headline(self):
        with tempfile.TemporaryDirectory() as root:
            status, report = self.report(root, '--triage')
        self.assertEqual(status, 0)
        self.assertEqual(report['triage_summary']['config'], {'needs_review': 0})
        self.assertEqual(report['triage_summary']['headline'], 'no actionable findings after triage')

    def test_config_only_headline_and_unchanged_raw_report(self):
        with tempfile.TemporaryDirectory() as root:
            Path(root, 'Dockerfile').write_text('FROM scratch' + chr(10))
            plain_status, plain = self.report(root, '--fail-on', 'low')
            status, report = self.report(root, '--triage', '--fail-on', 'low')
        self.assertEqual((plain_status, status), (1, 1))
        self.assertEqual(report['triage_summary']['config'], {'needs_review': 1})
        self.assertEqual(report['triage_summary']['headline'], '1 configuration finding(s) needing review')
        self.assertEqual(report['findings'], plain['findings'])
        self.assertEqual(report['manifest_hash'], plain['manifest_hash'])
        self.assertNotIn('triage_summary', plain)
        self.assertEqual(report['triage'][report['findings'][0]['id']], {'action': 'review'})

    def test_mixed_categories_keep_their_existing_interpretations(self):
        findings = [
            {'id': 'C1', 'category': 'config'},
            {'id': 'C2', 'category': 'config'},
            {'id': 'S1', 'category': 'secret', 'file': 'settings.txt', 'evidence': 'omitted'},
            {'id': 'S2', 'category': 'secret', 'file': 'tests/data.txt', 'evidence': 'omitted'},
            {'id': 'D1', 'category': 'dependency-vuln', 'fixed_in': ['2.0'], 'package': 'demo'},
            {'id': 'D2', 'category': 'dependency-vuln'},
        ]
        before = json.dumps(findings, sort_keys=True)
        triage, summary = scan.triage_findings(findings)
        self.assertEqual(json.dumps(findings, sort_keys=True), before)
        self.assertEqual(summary['config'], {'needs_review': 2})
        self.assertEqual(summary['secrets'], {'total': 2, 'likely_false_positive': 1, 'needs_review': 1})
        self.assertEqual(summary['dependency'], {'upgradeable': 1, 'monitor_only': 1, 'in_scaffold_lockfiles': 0})
        self.assertIn('2 configuration finding(s) needing review', summary['headline'])
        self.assertEqual([triage[f['id']]['action'] for f in findings],
                         ['review', 'review', 'review', 'informational', 'upgrade', 'monitor'])

    def test_counts_only_emitted_config_findings_when_truncated(self):
        for limit in ('MAX_FINDINGS', 'MAX_FINDINGS_PER_FILE'):
            with self.subTest(limit=limit), tempfile.TemporaryDirectory() as root:
                Path(root, 'compose.yaml').write_text('privileged: true' + chr(10) + 'privileged: true' + chr(10))
                with mock.patch.object(scan, limit, 1):
                    status, report = self.report(root, '--triage')
            self.assertEqual(status, 0)
            self.assertTrue(report['summary']['truncated']['findings'])
            self.assertEqual(len(report['findings']), 1)
            self.assertEqual(report['triage_summary']['config'], {'needs_review': 1})
            self.assertEqual(report['triage_summary']['headline'], '1 configuration finding(s) needing review')
