"""Per-file configuration totals use retained findings, without network access."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from test_scan import scan

NEWLINE = chr(10)


class ConfigIssuesByFileTests(unittest.TestCase):
    def report(self, root, *options, output=None):
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(io.StringIO()):
            status = scan.main(['scan.py', str(root), '--no-osv', *options])
        return status, json.loads(output.read_text() if output else stdout.getvalue())

    def assert_counts(self, report, expected):
        counts = report['summary']['config_issues_by_file']
        self.assertEqual(counts, expected)
        self.assertEqual(list(counts), sorted(counts))
        self.assertEqual(sum(counts.values()), report['summary']['config_issues'])

    def test_empty_and_secret_only(self):
        with tempfile.TemporaryDirectory() as root:
            _, empty = self.report(root)
            Path(root, 'sample.txt').write_text('ghp_' + 'A1' * 18 + NEWLINE)
            _, secret = self.report(root)
        self.assert_counts(empty, {})
        self.assert_counts(secret, {})
        self.assertEqual(secret['summary']['secret_hits'], 1)

    def test_multiple_rules_file_level_findings_and_output_modes(self):
        with tempfile.TemporaryDirectory() as root, tempfile.TemporaryDirectory() as outputs:
            Path(root, 'Dockerfile').write_text('FROM alpine:latest' + NEWLINE)
            Path(root, 'compose.yaml').write_text(('privileged: true' + NEWLINE) * 2)
            Path(root, 'clean.txt').write_text('ordinary prose' + NEWLINE)
            destination = Path(outputs, 'report.json')
            plain_status, plain = self.report(root)
            gated_status, gated = self.report(root, '--triage', '--fail-on', 'medium')
            saved_status, saved = self.report(root, '--triage', '--fail-on', 'medium',
                                              '--compact', '--sort-keys', '--json', str(destination),
                                              output=destination)
        self.assertEqual((plain_status, gated_status, saved_status), (0, 1, 1))
        for report in (plain, gated, saved):
            self.assert_counts(report, {'Dockerfile': 2, 'compose.yaml': 2})
            self.assertEqual(report['findings'], plain['findings'])
            self.assertEqual(report['manifest_hash'], plain['manifest_hash'])
        self.assertTrue(any(f['line'] is None for f in plain['findings']))
        self.assertEqual(gated['summary']['gate'], saved['summary']['gate'])
        self.assertEqual(gated['triage'], saved['triage'])

    @staticmethod
    def mixed_findings(_root, _files, add):
        add('config', 'high', 'z.txt', None, 'Synthetic file-level config', 'fixture')
        add('config', 'low', 'z.txt', 2, 'Synthetic line-level config', 'fixture')
        add('secret', 'high', 'z.txt', 2, 'Synthetic secret', 'redacted')
        add('dependency-vuln', 'high', 'z.txt', None, 'Synthetic dependency', 'TEST-1',
            package='sample', ecosystem='PyPI', version='1.0', vuln_ids=['TEST-1'])
        add('config', 'medium', 'a.txt', 1, 'Synthetic config', 'fixture')

    def test_categories_on_same_path_and_sorted_keys(self):
        with tempfile.TemporaryDirectory() as root, \
                mock.patch.object(scan, 'scan_secrets', side_effect=self.mixed_findings):
            _, report = self.report(root)
        self.assert_counts(report, {'a.txt': 1, 'z.txt': 2})
        self.assertEqual(report['summary']['findings_by_file'], {'a.txt': 1, 'z.txt': 4})

    def test_counts_only_retained_findings_under_caps(self):
        with tempfile.TemporaryDirectory() as root, \
                mock.patch.object(scan, 'scan_secrets', side_effect=self.mixed_findings):
            with mock.patch.object(scan, 'MAX_FINDINGS', 1):
                _, global_cap = self.report(root)
            with mock.patch.object(scan, 'MAX_FINDINGS_PER_FILE', 1):
                _, per_file_cap = self.report(root)
        self.assert_counts(global_cap, {'z.txt': 1})
        self.assert_counts(per_file_cap, {'a.txt': 1, 'z.txt': 1})
        for report in (global_cap, per_file_cap):
            self.assertTrue(report['summary']['truncated']['findings'])


if __name__ == '__main__':
    unittest.main()
