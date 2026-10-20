"""Per-path retained secret counts, using synthetic data and no network."""
import contextlib
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from test_scan import scan

NEWLINE = chr(10)


class SecretHitsByFileTests(unittest.TestCase):
    def report(self, root, *options, output=None):
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(io.StringIO()):
            status = scan.main(['scan.py', str(root), '--no-osv', *options])
        return status, json.loads(output.read_text() if output else stdout.getvalue())

    def fixtures(self, root):
        # Construct synthetic, repeated-character tokens; no real credentials.
        token = 'ghp_' + 'A1' * 18
        Path(root, 'z.txt').write_text(NEWLINE.join((token + ' ' + token, token, '')))
        Path(root, 'a.txt').write_text(token + NEWLINE)
        Path(root, 'clean.txt').write_text('ordinary prose' + NEWLINE)
        Path(root, 'compose.yaml').write_text(NEWLINE.join(('services:', '  app:', '    privileged: true', '')))

    def assert_counts(self, report, expected):
        counts = report['summary']['secret_hits_by_file']
        self.assertEqual(counts, expected)
        self.assertEqual(list(counts), sorted(counts))
        self.assertEqual(sum(counts.values()), report['summary']['secret_hits'])
        canon = json.dumps({k: report[k] for k in ('findings', 'target', 'commit')},
                           sort_keys=True, separators=(',', ':'))
        self.assertEqual(report['manifest_hash'], hashlib.sha256(canon.encode()).hexdigest())

    def test_empty_and_config_only(self):
        with tempfile.TemporaryDirectory() as root:
            _, empty = self.report(root)
            Path(root, 'compose.yaml').write_text('privileged: true' + NEWLINE)
            _, config = self.report(root)
        self.assert_counts(empty, {})
        self.assert_counts(config, {})
        self.assertEqual(config['summary']['config_issues'], 1)

    def test_repeated_hits_sorted_paths_and_output_modes(self):
        with tempfile.TemporaryDirectory() as root, tempfile.TemporaryDirectory() as outputs:
            self.fixtures(root)
            destination = Path(outputs, 'report.json')
            plain_status, plain = self.report(root)
            failed, triaged = self.report(root, '--triage', '--fail-on', 'high')
            saved_status, saved = self.report(root, '--triage', '--fail-on', 'high',
                                              '--compact', '--sort-keys', '--json', str(destination),
                                              output=destination)
        self.assertEqual((plain_status, failed, saved_status), (0, 1, 1))
        for report in (plain, triaged, saved):
            self.assert_counts(report, {'a.txt': 1, 'z.txt': 3})
            self.assertEqual(report['findings'], plain['findings'])
            self.assertEqual(report['manifest_hash'], plain['manifest_hash'])
        self.assertEqual(triaged['triage'], saved['triage'])
        self.assertEqual(triaged['summary']['gate'], saved['summary']['gate'])
        self.assertEqual(triaged['summary']['gate']['matching_findings'], 4)

    def test_global_and_per_file_caps(self):
        with tempfile.TemporaryDirectory() as root:
            self.fixtures(root)
            with mock.patch.object(scan, 'MAX_FINDINGS', 2):
                _, global_cap = self.report(root)
            with mock.patch.object(scan, 'MAX_FINDINGS_PER_FILE', 1):
                _, per_file = self.report(root)
        self.assert_counts(global_cap, {'a.txt': 1, 'z.txt': 1})
        self.assert_counts(per_file, {'a.txt': 1, 'z.txt': 1})
        for report in (global_cap, per_file):
            self.assertTrue(report['summary']['truncated']['findings'])

    def test_category_isolation_same_path_and_low_severity(self):
        def synthetic(_root, _files, add):
            add('secret', 'low', 'shared.txt', 1, 'Synthetic secret', 'redacted')
            add('config', 'high', 'shared.txt', 1, 'Synthetic config', 'fixture')
            add('dependency-vuln', 'high', 'shared.txt', None, 'Synthetic dependency',
                'TEST-1', package='sample', ecosystem='PyPI', version='1.0', vuln_ids=['TEST-1'])
            add('config', 'low', 'other.txt', 1, 'Synthetic config', 'fixture')
        with tempfile.TemporaryDirectory() as root, \
                mock.patch.object(scan, 'scan_secrets', side_effect=synthetic):
            _, report = self.report(root, '--triage')
        self.assert_counts(report, {'shared.txt': 1})
        self.assertEqual(report['summary']['findings_by_file'], {'other.txt': 1, 'shared.txt': 3})


if __name__ == '__main__':
    unittest.main()
