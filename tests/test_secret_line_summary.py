"""Offline regression coverage for distinct emitted secret locations."""
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


class SecretLineSummaryTests(unittest.TestCase):
    def report(self, root, *options):
        output = io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(io.StringIO()):
            status = scan.main(['scan.py', str(root), '--no-osv', *options])
        return status, json.loads(output.getvalue())

    def test_empty_and_config_only_reports_have_zero_secret_lines(self):
        with tempfile.TemporaryDirectory() as root:
            for config in (False, True):
                with self.subTest(config=config):
                    if config:
                        Path(root, '.env').write_text('MODE=production' + NL)
                    status, report = self.report(root, '--fail-on', 'high')
                    self.assertEqual(status, int(config))
                    self.assertEqual(report['summary']['secret_lines'], 0)
                    self.assertEqual(report['summary']['secret_hits'], 0)
                    self.assertEqual(report['summary']['config_issues'], int(config))

    def test_shared_lines_and_equal_line_numbers_in_different_files(self):
        token = 'ghp_' + 'A1b2C3' * 6  # Synthetic, never used as a credential.
        with tempfile.TemporaryDirectory() as root:
            Path(root, 'settings.txt').write_text(
                'token="' + token + '"' + NL + 'password="A1b2C3d4E5f6G7h8"' + NL)
            Path(root, 'other.txt').write_text(token + NL)
            status, plain = self.report(root, '--fail-on', 'critical')
            gated, triaged = self.report(root, '--triage', '--fail-on', 'high')
        self.assertEqual((status, gated), (0, 1))
        self.assertEqual(plain['summary']['secret_hits'], 4)
        self.assertEqual(plain['summary']['secret_lines'], 3)
        self.assertEqual([(f['file'], f['line']) for f in plain['findings']],
                         [('other.txt', 1), ('settings.txt', 1),
                          ('settings.txt', 1), ('settings.txt', 2)])
        self.assertEqual(plain['summary']['gate'], {
            'threshold': 'critical', 'matching_findings': 0, 'passed': True})
        self.assertEqual(triaged['summary'], {
            **plain['summary'],
            'gate': {'threshold': 'high', 'matching_findings': 2, 'passed': False},
        })
        self.assertEqual(plain['findings'], triaged['findings'])
        self.assertEqual(plain['manifest_hash'], triaged['manifest_hash'])
        canonical = json.dumps({k: plain[k] for k in ('findings', 'target', 'commit')},
                               sort_keys=True, separators=(',', ':'))
        self.assertEqual(plain['manifest_hash'], hashlib.sha256(canonical.encode()).hexdigest())
        self.assertNotIn(token, json.dumps(plain))

    def test_low_severity_examples_still_count_with_triage(self):
        with tempfile.TemporaryDirectory() as root:
            Path(root, 'settings.txt').write_text('password="your_placeholder_value"' + NL)
            status, report = self.report(root, '--triage', '--fail-on', 'medium')
        self.assertEqual(status, 0)
        self.assertEqual(report['summary']['secret_hits'], 1)
        self.assertEqual(report['summary']['secret_lines'], 1)
        self.assertEqual(report['findings'][0]['severity'], 'low')
        self.assertIn('(placeholder?)', report['findings'][0]['evidence'])

    def test_multiline_block_counts_only_its_reported_header_line(self):
        block = NL.join(['-----BEGIN PRIVATE KEY-----'] +
                        ['Ab1Cd2Ef3Gh4Ij5Kl6Mn7Op8'] * 3 +
                        ['-----END PRIVATE KEY-----', ''])
        with tempfile.TemporaryDirectory() as root:
            Path(root, 'settings.txt').write_text(NL + block)
            status, report = self.report(root, '--fail-on', 'critical')
        self.assertEqual(status, 1)
        self.assertEqual(report['summary']['secret_lines'], 1)
        self.assertEqual(report['summary']['secret_hits'], 1)
        self.assertEqual(report['findings'][0]['line'], 2)
        self.assertEqual(report['findings'][0]['summary'], 'Multiline private key block detected')

    def test_limits_count_only_locations_in_emitted_findings(self):
        token = 'ghp_' + 'A1b2C3' * 6
        for limit in ('MAX_FINDINGS', 'MAX_FINDINGS_PER_FILE'):
            with self.subTest(limit=limit), tempfile.TemporaryDirectory() as root:
                Path(root, 'settings.txt').write_text(
                    'token="' + token + '"' + NL + 'password="A1b2C3d4E5f6G7h8"' + NL)
                with mock.patch.object(scan, limit, 2):
                    status, report = self.report(root, '--fail-on', 'high')
            self.assertEqual(status, 1)
            self.assertTrue(report['summary']['truncated']['findings'])
            self.assertEqual(report['summary']['secret_hits'], 2)
            self.assertEqual(report['summary']['secret_lines'], 1)
            self.assertEqual({f['line'] for f in report['findings']}, {1})
