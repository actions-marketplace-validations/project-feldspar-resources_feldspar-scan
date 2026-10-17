"""Exclusive file-priority counts from offline synthetic findings."""
import contextlib
import hashlib
import io
import json
import tempfile
import unittest
from unittest import mock

from test_scan import scan


class FileHighestSeverityCountTests(unittest.TestCase):
    def report(self, root, entries, *options):
        def emit(root, files, add):
            for line, (category, severity, path) in enumerate(entries, 1):
                add(category, severity, path, line,
                    summary='Synthetic finding', evidence='omitted')

        output = io.StringIO()
        with mock.patch.object(scan, 'scan_secrets', side_effect=emit), \
                contextlib.redirect_stdout(output), contextlib.redirect_stderr(io.StringIO()):
            status = scan.main(['scan.py', root, '--no-osv', *options])
        return status, json.loads(output.getvalue())

    def assert_counts(self, doc, **nonzero):
        expected = dict.fromkeys(('critical', 'high', 'medium', 'low', 'unknown'), 0)
        expected.update(nonzero)
        actual = doc['summary']['files_by_highest_severity']
        self.assertEqual(actual, expected)
        self.assertEqual(sum(actual.values()), doc['summary']['files_with_findings'])

    def test_empty_scan_has_all_zero_buckets(self):
        with tempfile.TemporaryDirectory() as root:
            status, doc = self.report(root, [])
        self.assertEqual(status, 0)
        self.assert_counts(doc)

    def test_each_path_counts_once_across_categories_and_duplicate_hits(self):
        entries = [('config', 'low', 'shared.txt'),
                   ('secret', 'critical', 'shared.txt'),
                   ('secret', 'critical', 'shared.txt'),
                   ('dependency-vuln', 'high', 'one/lock.txt'),
                   ('config', 'medium', 'two/lock.txt'),
                   ('secret', 'unknown', 'low.txt'),
                   ('config', 'low', 'low.txt'),
                   ('dependency-vuln', 'unknown', 'unknown.txt')]
        with tempfile.TemporaryDirectory() as root:
            for ordered in (entries, list(reversed(entries))):
                with self.subTest(reversed=ordered != entries):
                    _, doc = self.report(root, ordered)
                    self.assert_counts(doc, critical=1, high=1, medium=1, low=1, unknown=1)
                    self.assertEqual(doc['summary']['files_by_severity']['low'], 2)

    def test_counts_only_findings_retained_by_limits(self):
        entries = [('config', 'low', 'one.txt'),
                   ('secret', 'critical', 'one.txt'),
                   ('config', 'high', 'two.txt')]
        for cap, expected in (('MAX_FINDINGS', {'low': 1}),
                              ('MAX_FINDINGS_PER_FILE', {'low': 1, 'high': 1})):
            with self.subTest(cap=cap), tempfile.TemporaryDirectory() as root, \
                    mock.patch.object(scan, cap, 1):
                _, doc = self.report(root, entries)
                self.assert_counts(doc, **expected)
                self.assertTrue(doc['summary']['truncated']['findings'])

    def test_triage_gate_and_manifest_hash_remain_independent(self):
        entries = [('secret', 'high', 'settings.txt'), ('config', 'low', 'settings.txt')]
        with tempfile.TemporaryDirectory() as root:
            status, plain = self.report(root, entries, '--fail-on', 'critical')
            gated, triaged = self.report(root, entries, '--triage', '--fail-on', 'high')
        self.assertEqual((status, gated), (0, 1))
        for doc in (plain, triaged):
            self.assert_counts(doc, high=1)
            canonical = json.dumps({k: doc[k] for k in ('findings', 'target', 'commit')},
                                   sort_keys=True, separators=(',', ':'))
            self.assertEqual(doc['manifest_hash'], hashlib.sha256(canonical.encode()).hexdigest())
        self.assertEqual(plain['findings'], triaged['findings'])
        self.assertEqual(plain['manifest_hash'], triaged['manifest_hash'])
        self.assertEqual(plain['summary']['gate'], {
            'threshold': 'critical', 'matching_findings': 0, 'passed': True})
        self.assertEqual(triaged['summary']['gate'], {
            'threshold': 'high', 'matching_findings': 1, 'passed': False})
