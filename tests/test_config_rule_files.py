"""Offline coverage for distinct config-file counts per finding label."""
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
COMPOSE = 'docker-compose service runs privileged'
ENV = 'Committed .env file with assignments'


class ConfigRuleFileTests(unittest.TestCase):
    def report(self, root, *options):
        output = io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(io.StringIO()):
            status = scan.main(['scan.py', str(root), '--no-osv', *options])
        return status, json.loads(output.getvalue())

    def test_empty_and_secret_only_reports_have_empty_mapping(self):
        with tempfile.TemporaryDirectory() as root:
            for populated in (False, True):
                with self.subTest(populated=populated):
                    if populated:
                        Path(root, 'settings.txt').write_text('password="A1b2C3d4E5f6G7h8"')
                    status, report = self.report(root)
                    self.assertEqual(status, 0)
                    self.assertEqual(report['summary']['config_files_by_rule'], {})
                    self.assertEqual(report['summary']['secret_hits'], int(populated))

    def test_real_rules_count_distinct_relative_paths(self):
        with tempfile.TemporaryDirectory() as root:
            Path(root, 'nested').mkdir()
            for name in ('compose.yml', 'nested/compose.yml'):
                Path(root, name).write_text(NL.join(['privileged: true'] * 2))
            Path(root, '.env').write_text('PORT=8080')
            status, plain = self.report(root)
            gated, triaged = self.report(root, '--triage', '--compact', '--fail-on', 'high')
        self.assertEqual(status, 0)
        self.assertEqual(gated, 1)
        expected = {ENV: 1, COMPOSE: 2}
        self.assertEqual(plain['summary']['config_issues'], 5)
        self.assertEqual(plain['summary']['config_files_by_rule'], expected)
        self.assertEqual(list(plain['summary']['config_files_by_rule']), sorted(expected))
        self.assertEqual(triaged['summary']['config_files_by_rule'], expected)
        self.assertEqual(plain['findings'], triaged['findings'])
        self.assertEqual(plain['manifest_hash'], triaged['manifest_hash'])
        canonical = json.dumps({k: plain[k] for k in ('findings', 'target', 'commit')},
                               sort_keys=True, separators=(',', ':'))
        self.assertEqual(plain['manifest_hash'], hashlib.sha256(canonical.encode()).hexdigest())

    def test_shared_file_and_label_across_severities(self):
        def config(root, files, add):
            for label, file, severity in [('Z rule', 'one', 'high'),
                                           ('A rule', 'one', 'low'),
                                           ('Z rule', 'one', 'medium'),
                                           ('Z rule', 'two', 'unknown')]:
                add('config', severity, file, 1, summary=label, evidence='synthetic')
        with tempfile.TemporaryDirectory() as root, mock.patch.object(scan, 'scan_config', config):
            _, report = self.report(root)
        self.assertEqual(report['summary']['config_files_by_rule'], {'A rule': 1, 'Z rule': 2})
        self.assertEqual(report['summary']['files_with_findings'], 2)

    def test_limits_count_only_retained_findings(self):
        cases = [('MAX_FINDINGS', 1, 1, 'findings'),
                 ('MAX_FINDINGS_PER_FILE', 1, 2, 'findings'),
                 ('MAX_FILES', 1, 1, 'files')]
        with tempfile.TemporaryDirectory() as root:
            for name in ('compose.yml', 'compose.yaml'):
                Path(root, name).write_text(NL.join(['privileged: true'] * 2))
            for limit, value, count, flag in cases:
                with self.subTest(limit=limit), mock.patch.object(scan, limit, value):
                    _, report = self.report(root)
                    self.assertTrue(report['summary']['truncated'][flag])
                    self.assertEqual(report['summary']['config_files_by_rule'], {COMPOSE: count})
