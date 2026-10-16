"""Secret rule-label counts using only synthetic values and offline scans."""
import contextlib
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from test_scan import scan


class SecretRuleSummaryTests(unittest.TestCase):
    def write_lines(self, root, name, *lines):
        Path(root, name).write_text(chr(10).join(lines) + chr(10))

    def report(self, root, *options):
        output = io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(io.StringIO()):
            status = scan.main(['scan.py', str(root), '--no-osv', *options])
        return status, json.loads(output.getvalue())

    def assert_counts(self, report, expected):
        counts = report['summary']['secret_hits_by_rule']
        self.assertEqual(counts, expected)
        self.assertEqual(list(counts), sorted(counts))
        self.assertEqual(sum(counts.values()), report['summary']['secret_hits'])

    def test_empty_and_config_only_reports_have_empty_counts(self):
        with tempfile.TemporaryDirectory() as root:
            self.assert_counts(self.report(root)[1], {})
            self.write_lines(root, '.env', 'MODE=development')
            report = self.report(root)[1]
            self.assertEqual(report['summary']['config_issues'], 1)
            self.assert_counts(report, {})

    def test_repeated_rules_multiple_files_and_hints_count_each_hit(self):
        with tempfile.TemporaryDirectory() as root:
            self.write_lines(root, 'a.txt',
                            'token="A1b2C3d4E5f6G7h8" password="A1b2C3d4E5f6G7h8"',
                            'token="placeholder_value1234"')
            self.write_lines(root, 'b.txt', 'token="A1b2C3d4E5f6G7h8"')
            self.write_lines(root, '.env', 'MODE=development')
            report = self.report(root)[1]
        self.assert_counts(report, {
            'Hardcoded password assignment': 1, 'Hardcoded token assignment': 3})
        self.assertEqual(report['summary']['config_issues'], 1)
        self.assertEqual(report['summary']['by_severity']['low'], 1)
        self.assertNotIn('A1b2C3d4E5f6G7h8', json.dumps(report))
        self.assertNotIn('placeholder_value1234', json.dumps(report))

    def test_provider_and_generic_hits_keep_individual_labels(self):
        value = 'ghp_' + 'Ab3D' * 9
        with tempfile.TemporaryDirectory() as root:
            self.write_lines(root, 'config.txt', 'token="' + value + '"')
            status, plain = self.report(root)
            gated_status, triaged = self.report(root, '--triage', '--fail-on', 'high')
            critical_status, _ = self.report(root, '--fail-on', 'critical')
        self.assertEqual((status, gated_status, critical_status), (0, 1, 0))
        self.assert_counts(plain, {'GitHub token detected': 1, 'Hardcoded token assignment': 1})
        self.assertNotIn('gate', plain['summary'])
        self.assertEqual(triaged['summary']['gate'],
                         {'threshold': 'high', 'matching_findings': 1, 'passed': False})
        self.assertEqual(plain['summary'],
                         {key: value for key, value in triaged['summary'].items() if key != 'gate'})
        self.assertEqual(plain['findings'], triaged['findings'])
        self.assertEqual(plain['manifest_hash'], triaged['manifest_hash'])
        canonical = json.dumps({k: plain[k] for k in ('findings', 'target', 'commit')},
                               sort_keys=True, separators=(',', ':'))
        self.assertEqual(plain['manifest_hash'], hashlib.sha256(canonical.encode()).hexdigest())
        self.assertNotIn(value, json.dumps(plain))

    def test_finding_caps_count_only_retained_rules(self):
        for limit in ('MAX_FINDINGS', 'MAX_FINDINGS_PER_FILE'):
            with self.subTest(limit=limit), tempfile.TemporaryDirectory() as root:
                self.write_lines(root, 'config.txt',
                                'token="A1b2C3d4E5f6G7h8"', 'password="A1b2C3d4E5f6G7h8"')
                with mock.patch.object(scan, limit, 1):
                    report = self.report(root)[1]
                self.assertTrue(report['summary']['truncated']['findings'])
                self.assert_counts(report, {'Hardcoded token assignment': 1})

    def test_file_cap_omits_unscanned_rules(self):
        with tempfile.TemporaryDirectory() as root:
            self.write_lines(root, 'a.txt', 'token="A1b2C3d4E5f6G7h8"')
            self.write_lines(root, 'b.txt', 'password="A1b2C3d4E5f6G7h8"')
            with mock.patch.object(scan, 'MAX_FILES', 1):
                report = self.report(root)[1]
        self.assertTrue(report['summary']['truncated']['files'])
        self.assert_counts(report, {'Hardcoded token assignment': 1})
