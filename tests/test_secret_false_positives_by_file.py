"""Offline coverage of per-file informational secret counts."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from test_scan import scan

NL = chr(10)


class SecretFalsePositivesByFileTests(unittest.TestCase):
    def report(self, root, *flags):
        output = io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(io.StringIO()):
            status = scan.main(['scan.py', str(root), '--no-osv', *flags])
        return status, json.loads(output.getvalue())

    def test_empty_and_config_only_have_empty_map(self):
        with tempfile.TemporaryDirectory() as root:
            for config in (False, True):
                if config:
                    Path(root, '.env').write_text('MODE=production' + NL)
                with self.subTest(config=config):
                    _, doc = self.report(root, '--triage')
                    self.assertEqual(doc['triage_summary']['secret_false_positives_by_file'], {})

    def test_mixed_classifications_count_findings_and_sort_paths(self):
        with tempfile.TemporaryDirectory() as root:
            Path(root, 'z.txt').write_text('password="your_placeholder_value"' + NL)
            Path(root, 'a.txt').write_text(
                'password="your_placeholder_value" token="your_placeholder_value"' + NL +
                'password="A1b2C3d4E5f6G7h8"' + NL)
            Path(root, '.env').write_text('MODE=production' + NL)
            plain_status, plain = self.report(root, '--fail-on', 'medium')
            status, doc = self.report(root, '--triage', '--fail-on', 'medium')
        counts = doc['triage_summary']['secret_false_positives_by_file']
        self.assertEqual(counts, {'a.txt': 2, 'z.txt': 1})
        self.assertEqual(list(counts), ['a.txt', 'z.txt'])
        self.assertEqual(sum(counts.values()), doc['triage_summary']['secrets']['likely_false_positive'])
        self.assertEqual(doc['triage_summary']['secrets']['needs_review'], 1)
        self.assertEqual((plain_status, status), (1, 1))
        self.assertNotIn('triage_summary', plain)
        for key in ('findings', 'manifest_hash', 'summary'):
            self.assertEqual(plain[key], doc[key])
        self.assertNotIn('your_placeholder_value', json.dumps(counts))

    def test_path_based_classification_includes_high_severity_findings(self):
        token = 'ghp_' + 'A1b2C3' * 6  # Synthetic fixture only.
        with tempfile.TemporaryDirectory() as root:
            Path(root, 'tests').mkdir()
            Path(root, 'tests', 'sample.txt').write_text(token + NL + token + NL)
            status, doc = self.report(root, '--triage', '--fail-on', 'high')
        self.assertEqual(status, 1)
        self.assertEqual(doc['triage_summary']['secret_false_positives_by_file'],
                         {'tests/sample.txt': 2})
        self.assertEqual(doc['summary']['gate']['matching_findings'], 2)

    def test_limits_count_retained_findings_and_invocations_reset(self):
        with tempfile.TemporaryDirectory() as root, tempfile.TemporaryDirectory() as empty:
            Path(root, 'settings.txt').write_text(('password="your_placeholder_value"' + NL) * 3)
            for limit in ('MAX_FINDINGS', 'MAX_FINDINGS_PER_FILE'):
                with self.subTest(limit=limit), mock.patch.object(scan, limit, 1):
                    _, doc = self.report(root, '--triage')
                    self.assertTrue(doc['summary']['truncated']['findings'])
                    self.assertEqual(doc['triage_summary']['secret_false_positives_by_file'],
                                     {'settings.txt': 1})
            _, doc = self.report(empty, '--triage')
            self.assertEqual(doc['triage_summary']['secret_false_positives_by_file'], {})
