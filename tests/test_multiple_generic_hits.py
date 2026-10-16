"""Multiple generic assignments; synthetic values and offline scans only."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from test_scan import scan


class MultipleGenericHitsTests(unittest.TestCase):
    first = 'A1b2C3d4E5f6G7h8'
    second = 'J9k8L7m6N5p4Q3r2'

    def run_scan(self, text, **limits):
        with tempfile.TemporaryDirectory() as root:
            Path(root, 'settings.txt').write_text(text, encoding='utf-8')
            stdout = io.StringIO()
            with mock.patch.multiple(scan, **limits) if limits else contextlib.nullcontext():
                with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(io.StringIO()):
                    with mock.patch.object(scan, 'query_osv', side_effect=AssertionError('offline')):
                        code = scan.main(['scan.py', root, '--no-osv', '--fail-on', 'medium'])
            return code, json.loads(stdout.getvalue())

    def test_reports_each_assignment_with_location_and_redaction(self):
        code, doc = self.run_scan('\npassword = "%s"; token = "%s"\n' % (self.first, self.second))
        self.assertEqual(code, 1)
        self.assertEqual(doc['summary']['secret_hits'], 2)
        self.assertEqual([f['summary'] for f in doc['findings']],
                         ['Hardcoded password assignment', 'Hardcoded token assignment'])
        self.assertEqual([f['evidence'] for f in doc['findings']], ['A1b2…', 'J9k8…'])
        for hit in doc['findings']:
            self.assertEqual((hit['severity'], hit['file'], hit['line']),
                             ('medium', 'settings.txt', 2))
        for value in (self.first, self.second):
            self.assertNotIn(value, json.dumps(doc))

    def test_url_exclusion_is_applied_to_each_assignment(self):
        for scheme in ('http', 'https', 'ws', 'wss'):
            url = scheme + '://example.invalid/endpoint'
            for assignments in ((url, self.first), (self.first, url)):
                with self.subTest(scheme=scheme, assignments=assignments):
                    code, doc = self.run_scan('token = "%s"; token = "%s"' % assignments)
                    self.assertEqual(code, 1)
                    self.assertEqual(doc['summary']['secret_hits'], 1)
                    self.assertEqual(doc['findings'][0]['evidence'], 'A1b2…')

    def test_placeholder_hint_does_not_change_later_severity(self):
        code, doc = self.run_scan('token = "%s"; token = "%s"' % ('x' * 16, self.first))
        self.assertEqual(code, 1)
        self.assertEqual([f['severity'] for f in doc['findings']], ['medium', 'low'])
        self.assertEqual([f['evidence'] for f in doc['findings']],
                         ['A1b2…', 'xxxx… (placeholder?)'])

    def test_all_url_assignments_remain_excluded(self):
        code, doc = self.run_scan('token="https://example.invalid/a"; password="wss://example.invalid/b"')
        self.assertEqual(code, 0)
        self.assertEqual(doc['findings'], [])

    def test_same_key_assignments_keep_distinct_ids(self):
        code, doc = self.run_scan('token="%s"; token="%s"' % (self.first, self.second))
        self.assertEqual(code, 1)
        self.assertEqual([f['id'] for f in doc['findings']], ['F-001', 'F-002'])
        self.assertEqual([f['evidence'] for f in doc['findings']], ['A1b2…', 'J9k8…'])

    def test_finding_caps_still_apply_to_multiple_assignments(self):
        for limit in ('MAX_FINDINGS_PER_FILE', 'MAX_FINDINGS'):
            with self.subTest(limit=limit):
                code, doc = self.run_scan('token="%s"; token="%s"' % (self.first, self.second),
                                          **{limit: 1})
                self.assertEqual(code, 1)
                self.assertEqual(doc['summary']['secret_hits'], 1)
                self.assertTrue(doc['summary']['truncated']['findings'])
                self.assertEqual(doc['findings'][0]['evidence'], 'A1b2…')
