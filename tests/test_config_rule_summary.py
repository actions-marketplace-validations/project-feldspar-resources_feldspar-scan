"""Configuration rule counts with offline, synthetic fixtures."""
import contextlib
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from test_scan import scan


class ConfigRuleSummaryTests(unittest.TestCase):
    def report(self, root, *options):
        output = io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(io.StringIO()):
            status = scan.main(['scan.py', str(root), '--no-osv', *options])
        return status, json.loads(output.getvalue())

    def write_lines(self, root, name, *lines):
        Path(root, name).write_text(chr(10).join(lines) + chr(10))

    def assert_counts(self, report, expected):
        counts = report['summary']['config_issues_by_rule']
        self.assertEqual(counts, expected)
        self.assertEqual(list(counts), sorted(counts))
        self.assertEqual(sum(counts.values()), report['summary']['config_issues'])

    def test_empty_and_secret_only_reports(self):
        with tempfile.TemporaryDirectory() as root:
            self.assert_counts(self.report(root)[1], {})
            self.write_lines(root, 'config.txt', 'token="A1b2C3d4E5f6G7h8"')
            report = self.report(root)[1]
        self.assertEqual(report['summary']['secret_hits'], 1)
        self.assert_counts(report, {})

    def test_repeated_rules_and_mixed_categories(self):
        with tempfile.TemporaryDirectory() as root:
            self.write_lines(root, '.env', 'MODE=development', 'DEBUG=1')
            self.write_lines(root, '.env.local', 'MODE=local')
            self.write_lines(root, 'Dockerfile', 'FROM scratch')
            self.write_lines(root, 'config.txt', 'token="A1b2C3d4E5f6G7h8"')
            status, plain = self.report(root)
            gated_status, triaged = self.report(root, '--triage', '--fail-on', 'high')
            critical_status, _ = self.report(root, '--fail-on', 'critical')
        self.assertEqual((status, gated_status, critical_status), (0, 1, 0))
        self.assert_counts(plain, {
            'Committed .env file with assignments': 2,
            'Dockerfile has no USER instruction (runtime user unverified)': 1})
        self.assertEqual(plain['summary']['secret_hits'], 1)
        self.assertNotIn('gate', plain['summary'])
        self.assertEqual(triaged['summary']['gate'],
                         {'threshold': 'high', 'matching_findings': 2, 'passed': False})
        self.assertEqual(plain['summary'],
                         {key: value for key, value in triaged['summary'].items() if key != 'gate'})
        self.assertEqual(plain['findings'], triaged['findings'])
        self.assertEqual(plain['manifest_hash'], triaged['manifest_hash'])
        canonical = json.dumps({k: plain[k] for k in ('findings', 'target', 'commit')},
                               sort_keys=True, separators=(',', ':'))
        self.assertEqual(plain['manifest_hash'], hashlib.sha256(canonical.encode()).hexdigest())
        self.assertNotIn('A1b2C3d4E5f6G7h8', json.dumps(plain))

    def test_distinct_rules_in_one_file(self):
        with tempfile.TemporaryDirectory() as root:
            self.write_lines(root, 'Dockerfile', 'FROM synthetic:latest', 'USER root')
            report = self.report(root)[1]
        self.assert_counts(report, {
            'Dockerfile base image uses latest (explicit or implicit)': 1,
            'Dockerfile final USER explicitly runs as root': 1})

    def test_finding_caps_count_only_retained_findings(self):
        for limit in ('MAX_FINDINGS', 'MAX_FINDINGS_PER_FILE'):
            with self.subTest(limit=limit), tempfile.TemporaryDirectory() as root:
                self.write_lines(root, 'Dockerfile', 'FROM synthetic:latest', 'USER root')
                with mock.patch.object(scan, limit, 1):
                    report = self.report(root)[1]
                self.assertTrue(report['summary']['truncated']['findings'])
                self.assert_counts(report, {
                    'Dockerfile base image uses latest (explicit or implicit)': 1})

    def test_file_cap_omits_unscanned_rules(self):
        with tempfile.TemporaryDirectory() as root:
            self.write_lines(root, '.env', 'MODE=development')
            self.write_lines(root, 'Dockerfile', 'FROM scratch')
            with mock.patch.object(scan, 'MAX_FILES', 1):
                report = self.report(root)[1]
        self.assertTrue(report['summary']['truncated']['files'])
        self.assert_counts(report, {'Committed .env file with assignments': 1})
