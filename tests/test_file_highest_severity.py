"""Per-file severity summaries using offline, synthetic detector output."""
import contextlib
import hashlib
import io
import json
import tempfile
import unittest
from unittest import mock

from test_scan import scan


class FileHighestSeverityTests(unittest.TestCase):
    def report(self, root, entries, *options):
        def emit(root, files, add):
            for line, (file, severity) in enumerate(entries, 1):
                add('secret', severity, file, line,
                    summary='Synthetic finding', evidence='omitted')

        output = io.StringIO()
        with mock.patch.object(scan, 'scan_secrets', side_effect=emit), \
                contextlib.redirect_stdout(output), contextlib.redirect_stderr(io.StringIO()):
            status = scan.main(['scan.py', root, '--no-osv', *options])
        return status, json.loads(output.getvalue())

    def test_empty_scan(self):
        with tempfile.TemporaryDirectory() as root:
            status, doc = self.report(root, [])
        self.assertEqual(status, 0)
        self.assertEqual(doc['summary']['highest_severity_by_file'], {})

    def test_worst_per_path_and_stable_path_order(self):
        entries = [('z/settings.txt', 'unknown'), ('a/settings.txt', 'medium'),
                   ('z/settings.txt', 'low'), ('a/settings.txt', 'critical'),
                   ('high.txt', 'high'), ('medium.txt', 'medium'),
                   ('unknown.txt', 'unknown')]
        expected = {'a/settings.txt': 'critical', 'high.txt': 'high',
                    'medium.txt': 'medium', 'unknown.txt': 'unknown',
                    'z/settings.txt': 'low'}
        with tempfile.TemporaryDirectory() as root:
            for ordered in (entries, list(reversed(entries))):
                with self.subTest(ordered=ordered):
                    _, doc = self.report(root, ordered)
                    actual = doc['summary']['highest_severity_by_file']
                    self.assertEqual(actual, expected)
                    self.assertEqual(list(actual), sorted(expected))
                    self.assertEqual(len(actual), doc['summary']['files_with_findings'])

    def test_caps_only_summarize_emitted_findings(self):
        entries = [('one.txt', 'medium'), ('one.txt', 'critical'), ('two.txt', 'high')]
        for cap, expected in (
                ('MAX_FINDINGS', {'one.txt': 'medium'}),
                ('MAX_FINDINGS_PER_FILE', {'one.txt': 'medium', 'two.txt': 'high'})):
            with self.subTest(cap=cap), tempfile.TemporaryDirectory() as root, \
                    mock.patch.object(scan, cap, 1):
                _, doc = self.report(root, entries)
            self.assertTrue(doc['summary']['truncated']['findings'])
            self.assertEqual(doc['summary']['highest_severity_by_file'], expected)

    def test_triage_hash_and_gate_contracts(self):
        entries = [('settings.txt', 'high'), ('settings.txt', 'low')]
        with tempfile.TemporaryDirectory() as root:
            status, plain = self.report(root, entries, '--fail-on', 'critical')
            gated, triaged = self.report(root, entries, '--triage', '--fail-on', 'high')
        self.assertEqual((status, gated), (0, 1))
        self.assertEqual(plain['summary']['highest_severity_by_file'], {'settings.txt': 'high'})
        self.assertEqual(plain['summary']['gate'], {
            'threshold': 'critical', 'matching_findings': 0, 'passed': True})
        self.assertEqual(triaged['summary']['gate'], {
            'threshold': 'high', 'matching_findings': 1, 'passed': False})
        self.assertEqual(
            {k: v for k, v in plain['summary'].items() if k != 'gate'},
            {k: v for k, v in triaged['summary'].items() if k != 'gate'})
        self.assertEqual(plain['findings'], triaged['findings'])
        self.assertEqual(plain['manifest_hash'], triaged['manifest_hash'])
        canonical = json.dumps({k: plain[k] for k in ('findings', 'target', 'commit')},
                               sort_keys=True, separators=(',', ':'))
        self.assertEqual(plain['manifest_hash'], hashlib.sha256(canonical.encode()).hexdigest())
