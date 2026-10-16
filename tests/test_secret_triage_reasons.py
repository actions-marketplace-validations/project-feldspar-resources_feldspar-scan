"""Offline coverage for the reasons behind informational secret triage."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from test_scan import scan


class SecretTriageReasonTests(unittest.TestCase):
    def test_counts_existing_reasons_once_with_classification_precedence(self):
        fixtures = [
            ('tests/a.txt', 'synthetic (example-key?)', 'secret'),
            ('tests/b.txt', 'synthetic', 'secret'),
            ('test_config.py', 'synthetic', 'secret'),
            ('locales/en.txt', 'synthetic', 'secret'),
            ('settings.txt', 'synthetic (example-key?)', 'secret'),
            ('settings.txt', 'synthetic', 'secret'),
            ('tests/a.txt', 'synthetic', 'config'),
            ('tests/requirements.txt', '', 'dependency-vuln'),
        ]
        findings = [dict(id=str(i), file=path, evidence=ev, category=cat)
                    for i, (path, ev, cat) in enumerate(fixtures)]
        triage, summary = scan.triage_findings(findings)
        counts = summary['secret_false_positive_reasons']
        self.assertEqual(counts, {
            'in a test/fixture/example path (tests)': 2,
            'filename marks it as a test/example/template': 1,
            'in a localization path (locales): translated UI text, not a credential': 1,
            scan.VALUE_HINTS['example-key?']: 1,
        })
        self.assertEqual(list(counts), sorted(counts))
        self.assertEqual(sum(counts.values()), summary['secrets']['likely_false_positive'])
        self.assertEqual(summary['secrets']['needs_review'], 1)
        self.assertEqual(triage['0']['reason'], 'in a test/fixture/example path (tests)')
        self.assertEqual(triage['5']['action'], 'review')

    def test_empty_and_review_only_have_empty_counts(self):
        for findings in ([], [dict(id='1', category='secret', file='app.txt', evidence='synthetic')]):
            with self.subTest(findings=findings):
                self.assertEqual(scan.triage_findings(findings)[1]['secret_false_positive_reasons'], {})

    def report(self, root, *args):
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(io.StringIO()):
            status = scan.main(['scan.py', str(root), '--no-osv', *args])
        return status, json.loads(stdout.getvalue())

    def test_cli_opt_in_preserves_raw_findings_hash_and_gate(self):
        with tempfile.TemporaryDirectory() as root:
            Path(root, 'tests').mkdir()
            Path(root, 'tests', 'settings.txt').write_text(('password="A1b2C3d4E5f6G7h8"' + chr(10)))
            plain_status, plain = self.report(root, '--fail-on', 'medium')
            status, report = self.report(root, '--triage', '--fail-on', 'medium')
        self.assertEqual((plain_status, status), (1, 1))
        self.assertNotIn('triage_summary', plain)
        self.assertEqual(report['findings'], plain['findings'])
        self.assertEqual(report['manifest_hash'], plain['manifest_hash'])
        self.assertEqual(report['triage_summary']['secret_false_positive_reasons'],
                         {'in a test/fixture/example path (tests)': 1})

    def test_truncation_counts_only_emitted_findings(self):
        with tempfile.TemporaryDirectory() as root:
            Path(root, 'tests').mkdir()
            Path(root, 'tests', 'settings.txt').write_text(('password="A1b2C3d4E5f6G7h8"' + chr(10)) * 3)
            with mock.patch.object(scan, 'MAX_FINDINGS', 1):
                _, report = self.report(root, '--triage')
        self.assertTrue(report['summary']['truncated']['findings'])
        self.assertEqual(report['triage_summary']['secret_false_positive_reasons'],
                         {'in a test/fixture/example path (tests)': 1})


if __name__ == '__main__':
    unittest.main()
