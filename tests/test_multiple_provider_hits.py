"""Multiple provider-token occurrences, using synthetic values and no network."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from test_scan import scan


class MultipleProviderHitTests(unittest.TestCase):
    FIRST = 'npm_' + 'A1b2C3' * 6
    SECOND = 'npm_' + 'D4e5F6' * 6
    MASKED = 'npm_' + 'x' * 36

    def report(self, text, *options):
        with tempfile.TemporaryDirectory() as root:
            Path(root, 'settings.txt').write_text(text, encoding='utf-8')
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(io.StringIO()):
                status = scan.main(['scan.py', root, '--no-osv', *options])
            return status, json.loads(stdout.getvalue())

    def test_two_values_on_one_line_are_separate_redacted_findings(self):
        status, report = self.report('\n' + json.dumps([self.FIRST, self.SECOND]))
        self.assertEqual(status, 0)
        hits = report['findings']
        self.assertEqual(len(hits), 2)
        self.assertEqual([f['id'] for f in hits], ['F-001', 'F-002'])
        for hit in hits:
            self.assertEqual(hit['category'], 'secret')
            self.assertEqual(hit['summary'], 'npm access token detected')
            self.assertEqual(hit['severity'], 'high')
            self.assertEqual(hit['file'], 'settings.txt')
            self.assertEqual(hit['line'], 2)
            self.assertEqual(hit['evidence'], 'npm_…')
        self.assertEqual(report['summary']['secret_hits'], 2)
        self.assertEqual(report['summary']['by_severity']['high'], 2)
        for value in (self.FIRST, self.SECOND):
            self.assertNotIn(value, json.dumps(report))

    def test_hint_downgrade_does_not_leak_to_next_match(self):
        for values in ((self.MASKED, self.FIRST), (self.FIRST, self.MASKED)):
            with self.subTest(masked_first=values[0] == self.MASKED):
                status, report = self.report(' '.join(values), '--fail-on', 'high', '--triage')
                self.assertEqual(status, 1)
                self.assertEqual([f['severity'] for f in report['findings']], ['high', 'low'])
                self.assertEqual(report['findings'][0]['evidence'], 'npm_…')
                self.assertEqual(report['findings'][1]['evidence'], 'npm_… (example-key?)')
                self.assertEqual(report['triage_summary']['secrets']['total'], 2)

    def test_repeated_value_is_reported_at_each_occurrence(self):
        _, report = self.report(self.FIRST + ' ' + self.FIRST)
        self.assertEqual(len(report['findings']), 2)
        self.assertEqual(report['summary']['files_with_findings'], 1)

    def test_separate_lines_keep_their_locations(self):
        _, report = self.report(self.FIRST + '\n\n' + self.SECOND)
        self.assertEqual([f['line'] for f in report['findings']], [1, 3])

    def test_global_and_per_file_caps_still_apply(self):
        for limit in ('MAX_FINDINGS', 'MAX_FINDINGS_PER_FILE'):
            with self.subTest(limit=limit), mock.patch.object(scan, limit, 1):
                _, report = self.report(self.FIRST + ' ' + self.SECOND)
                self.assertEqual(len(report['findings']), 1)
                self.assertEqual(report['summary']['secret_hits'], 1)
                self.assertTrue(report['summary']['truncated']['findings'])
