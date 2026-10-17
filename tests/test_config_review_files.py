"""Count configuration review files without changing findings or triage actions."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from test_scan import scan


class ConfigReviewFilesTests(unittest.TestCase):
    def report(self, root, *options):
        with contextlib.redirect_stdout(io.StringIO()) as output, \
                contextlib.redirect_stderr(io.StringIO()), \
                mock.patch.object(scan, 'query_osv', side_effect=AssertionError('offline')):
            status = scan.main(['scan.py', str(root), '--no-osv', *options])
        return status, json.loads(output.getvalue())

    def test_distinct_paths_mixed_categories_and_missing_paths(self):
        findings = [
            {'id': 'C1', 'category': 'config', 'file': 'app/compose.yaml'},
            {'id': 'C2', 'category': 'config', 'file': 'app/compose.yaml'},
            {'id': 'C3', 'category': 'config', 'file': 'tests/compose.yaml'},
            {'id': 'C4', 'category': 'config'},
            {'id': 'C5', 'category': 'config', 'file': None},
            {'id': 'C6', 'category': 'config', 'file': ''},
            {'id': 'S1', 'category': 'secret', 'file': 'settings.txt', 'evidence': 'omitted'},
            {'id': 'D1', 'category': 'dependency-vuln', 'file': 'requirements.txt'},
            {'id': 'O1', 'category': 'other', 'file': 'other.txt'},
        ]
        before = json.dumps(findings, sort_keys=True)
        actions, summary = scan.triage_findings(findings)
        self.assertEqual(summary['config_files_needing_review'], 2)
        self.assertEqual(summary['config'], {'needs_review': 6})
        self.assertEqual(summary['by_action']['review'], 8)
        self.assertEqual(actions['C3'], {'action': 'review'})
        self.assertEqual(json.dumps(findings, sort_keys=True), before)

    def test_empty_and_non_config_inputs_count_zero(self):
        for findings in ([], [{'id': 'D1', 'category': 'dependency-vuln', 'file': 'go.mod'}]):
            with self.subTest(findings=findings):
                self.assertEqual(scan.triage_findings(findings)[1]['config_files_needing_review'], 0)
        with tempfile.TemporaryDirectory() as root:
            status, report = self.report(root, '--triage')
        self.assertEqual(status, 0)
        self.assertEqual(report['triage_summary']['config_files_needing_review'], 0)

    def test_cli_opt_in_preserves_gate_findings_and_hash(self):
        with tempfile.TemporaryDirectory() as root:
            for name in ('app', 'tests'):
                folder = Path(root, name)
                folder.mkdir()
                (folder / 'compose.yaml').write_text(('privileged: true' + chr(10)) * 2)
            raw_status, raw = self.report(root, '--fail-on=medium')
            status, report = self.report(root, '--triage', '--fail-on=medium')
        self.assertEqual((raw_status, status), (1, 1))
        self.assertNotIn('triage_summary', raw)
        self.assertEqual(report['triage_summary']['config_files_needing_review'], 2)
        self.assertEqual(report['triage_summary']['config'], {'needs_review': 4})
        for key in ('findings', 'summary', 'manifest_hash'):
            self.assertEqual(report[key], raw[key])
        self.assertTrue(all(value == {'action': 'review'} for value in report['triage'].values()))

    def test_limits_count_only_files_with_retained_config_findings(self):
        for limit, expected in (('MAX_FINDINGS', 1), ('MAX_FINDINGS_PER_FILE', 2)):
            with self.subTest(limit=limit), tempfile.TemporaryDirectory() as root:
                for name in ('app', 'tests'):
                    folder = Path(root, name)
                    folder.mkdir()
                    (folder / 'compose.yaml').write_text(('privileged: true' + chr(10)) * 2)
                with mock.patch.object(scan, limit, 1):
                    _, report = self.report(root, '--triage')
            self.assertTrue(report['summary']['truncated']['findings'])
            self.assertEqual(report['triage_summary']['config_files_needing_review'], expected)
            self.assertEqual(len(report['findings']), expected)
