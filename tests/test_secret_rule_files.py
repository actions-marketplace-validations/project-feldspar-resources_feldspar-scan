"""Offline coverage for distinct affected-file counts per secret label."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from test_scan import scan

NL = chr(10)


class SecretRuleFileTests(unittest.TestCase):
    def report(self, root, *options):
        output = io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(io.StringIO()):
            status = scan.main(['scan.py', str(root), '--no-osv', *options])
        return status, json.loads(output.getvalue())

    def test_empty_and_config_only_reports(self):
        with tempfile.TemporaryDirectory() as root:
            for populated in (False, True):
                with self.subTest(populated=populated):
                    if populated:
                        Path(root, '.env').write_text('PORT=8080')
                    status, report = self.report(root)
                    self.assertEqual(status, 0)
                    self.assertEqual(report['summary']['secret_files_by_rule'], {})
                    self.assertEqual(report['summary']['config_issues'], int(populated))

    def test_real_rules_distinct_paths_and_triage(self):
        value = 'A1b2C3d4E5f6G7h8'
        with tempfile.TemporaryDirectory() as root:
            Path(root, 'tests').mkdir()
            for name in ('settings.txt', 'tests/settings.txt'):
                Path(root, name).write_text(NL.join([
                    'password="%s"' % value,
                    'password="%s"' % value,
                    'api_key="%s"' % value,
                ]))
            status, plain = self.report(root)
            gated, triaged = self.report(root, '--triage', '--compact', '--fail-on', 'medium')
        self.assertEqual(status, 0)
        self.assertEqual(gated, 1)
        expected = {'Hardcoded api_key assignment': 2, 'Hardcoded password assignment': 2}
        self.assertEqual(plain['summary']['secret_hits'], 6)
        self.assertEqual(plain['summary']['secret_files_by_rule'], expected)
        self.assertEqual(list(plain['summary']['secret_files_by_rule']), sorted(expected))
        self.assertEqual(triaged['summary']['secret_files_by_rule'], expected)
        self.assertEqual(plain['findings'], triaged['findings'])
        self.assertEqual(plain['manifest_hash'], triaged['manifest_hash'])
        self.assertNotIn(value, json.dumps(triaged))

    def test_category_and_severity_do_not_leak_into_grouping(self):
        def secrets(root, files, add):
            for label, file, severity in [('Z rule', 'one', 'high'),
                                           ('A rule', 'one', 'low'),
                                           ('Z rule', 'one', 'medium'),
                                           ('Z rule', 'two', 'unknown')]:
                add('secret', severity, file, 1, summary=label, evidence='synthetic')
            add('dependency-vuln', 'high', 'three', None,
                summary='Z rule', evidence='synthetic')
            add('config', 'high', 'four', 1, summary='Z rule', evidence='synthetic')
        with tempfile.TemporaryDirectory() as root, mock.patch.object(scan, 'scan_secrets', secrets):
            _, report = self.report(root)
        self.assertEqual(report['summary']['secret_files_by_rule'], {'A rule': 1, 'Z rule': 2})
        self.assertEqual(report['summary']['secret_hits'], 4)

    def test_limits_count_only_retained_findings(self):
        cases = [('MAX_FINDINGS', 1, 1, 'findings'),
                 ('MAX_FINDINGS_PER_FILE', 1, 2, 'findings'),
                 ('MAX_FILES', 1, 1, 'files')]
        with tempfile.TemporaryDirectory() as root:
            for name in ('one.txt', 'two.txt'):
                Path(root, name).write_text(('password="A1b2C3d4E5f6G7h8"' + NL) * 2)
            for limit, value, count, flag in cases:
                with self.subTest(limit=limit), mock.patch.object(scan, limit, value):
                    _, report = self.report(root)
                    self.assertTrue(report['summary']['truncated'][flag])
                    self.assertEqual(report['summary']['secret_files_by_rule'],
                                     {'Hardcoded password assignment': count})
