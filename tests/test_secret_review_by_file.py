"""Offline coverage for secret review counts grouped by path."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from test_scan import scan


class SecretReviewByFileTests(unittest.TestCase):
    def test_mixed_findings_count_only_secret_reviews_in_sorted_paths(self):
        findings = []
        for category, path, evidence in (
            ('secret', 'z.txt', 'synthetic'),
            ('secret', 'a.txt', 'synthetic'),
            ('secret', 'z.txt', 'synthetic'),
            ('secret', 'tests/z.txt', 'synthetic'),
            ('secret', 'z.txt', 'synthetic (example-key?)'),
            ('secret', 'locales/en.txt', 'synthetic'),
            ('config', 'a.txt', 'synthetic'),
            ('dependency-vuln', 'requirements.txt', ''),
        ):
            findings.append(dict(id=str(len(findings)), category=category,
                                 file=path, evidence=evidence, severity='medium'))
        per_id, summary = scan.triage_findings(findings)
        counts = summary['secret_review_by_file']
        self.assertEqual(counts, {'a.txt': 1, 'z.txt': 2})
        self.assertEqual(list(counts), ['a.txt', 'z.txt'])
        self.assertEqual(sum(counts.values()), summary['secrets']['needs_review'])
        self.assertEqual(len(counts), summary['secret_files_needing_review'])
        self.assertEqual(per_id['3']['action'], 'informational')
        self.assertEqual(per_id['4']['action'], 'informational')
        self.assertEqual(per_id['6']['action'], 'review')

    def report(self, root, *args):
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(io.StringIO()):
            status = scan.main(['scan.py', str(root), '--no-osv', *args])
        return status, json.loads(stdout.getvalue())

    def test_empty_and_only_informational_reports(self):
        with tempfile.TemporaryDirectory() as root:
            _, empty = self.report(root, '--triage')
            Path(root, 'tests').mkdir()
            Path(root, 'tests/settings.txt').write_text(('password="A1b2C3d4E5f6G7h8"' + chr(10)))
            _, info = self.report(root, '--triage')
        self.assertEqual(empty['triage_summary']['secret_review_by_file'], {})
        self.assertGreater(info['summary']['secret_hits'], 0)
        self.assertEqual(info['triage_summary']['secret_review_by_file'], {})

    def test_cli_opt_in_preserves_findings_hash_and_gate(self):
        with tempfile.TemporaryDirectory() as root:
            Path(root, 'settings.txt').write_text(('password="A1b2C3d4E5f6G7h8"' + chr(10)) * 2)
            plain_status, plain = self.report(root, '--fail-on', 'medium')
            status, report = self.report(root, '--triage', '--fail-on', 'medium')
        self.assertEqual((plain_status, status), (1, 1))
        self.assertNotIn('triage_summary', plain)
        self.assertEqual(report['triage_summary']['secret_review_by_file'], {'settings.txt': 2})
        for field in ('findings', 'manifest_hash', 'summary'):
            self.assertEqual(report[field], plain[field])

    def test_limits_count_only_retained_findings_and_reset_between_calls(self):
        with tempfile.TemporaryDirectory() as root:
            Path(root, 'settings.txt').write_text(('password="A1b2C3d4E5f6G7h8"' + chr(10)) * 3)
            for limit in ('MAX_FINDINGS', 'MAX_FINDINGS_PER_FILE'):
                with self.subTest(limit=limit), mock.patch.object(scan, limit, 1):
                    _, report = self.report(root, '--triage')
                self.assertTrue(report['summary']['truncated']['findings'])
                self.assertEqual(report['triage_summary']['secret_review_by_file'], {'settings.txt': 1})
            Path(root, 'settings.txt').unlink()
            _, empty = self.report(root, '--triage')
        self.assertEqual(empty['triage_summary']['secret_review_by_file'], {})
