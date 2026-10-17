"""Opt-in omission of Git HEAD metadata; all fixtures and lookups are offline."""
import contextlib
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from test_scan import scan


class NoCommitTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name) / 'repo'
        self.root.mkdir()
        (self.root / 'compose.yml').write_text(
            chr(10).join(('services:', '  app:', '    privileged: true', '')),
            encoding='utf-8')

    def run_scan(self, *options):
        with mock.patch.object(scan, 'datetime') as clock, \
                mock.patch.object(scan, 'query_osv', side_effect=AssertionError('unexpected lookup')), \
                contextlib.redirect_stdout(io.StringIO()) as stdout, \
                contextlib.redirect_stderr(io.StringIO()) as stderr:
            clock.now.return_value.strftime.return_value = '2026-01-01T00:00:00Z'
            status = scan.main(['scan.py', str(self.root), '--no-osv', *options])
        return status, stdout.getvalue(), stderr.getvalue()

    def assert_hash_matches_report(self, report):
        canonical = json.dumps(
            {key: report[key] for key in ('findings', 'target', 'commit')},
            sort_keys=True, separators=(',', ':'))
        self.assertEqual(report['manifest_hash'],
                         hashlib.sha256(canonical.encode()).hexdigest())

    def test_skips_lookup_preserves_findings_triage_and_gate(self):
        with mock.patch.object(scan, 'git_head', return_value='a' * 40) as head:
            baseline = self.run_scan('--triage', '--fail-on=medium')
            head.assert_called_once_with(str(self.root))
        self.assertEqual(baseline[0], 1)
        expected = json.loads(baseline[1])
        self.assertEqual(expected['commit'], 'a' * 40)
        self.assertTrue(expected['findings'])
        self.assert_hash_matches_report(expected)
        with mock.patch.object(scan, 'git_head', side_effect=AssertionError('HEAD lookup')) as head:
            actual = self.run_scan('--no-commit', '--triage', '--fail-on=medium')
            head.assert_not_called()
        self.assertEqual((actual[0], actual[2]), (baseline[0], baseline[2]))
        report = json.loads(actual[1])
        self.assertIsNone(report['commit'])
        self.assert_hash_matches_report(report)
        self.assertNotEqual(report['manifest_hash'], expected['manifest_hash'])
        for key in ('commit', 'manifest_hash'):
            report.pop(key)
            expected.pop(key)
        self.assertEqual(report, expected)

    def test_repeated_flags_and_default_invocation_isolation(self):
        with mock.patch.object(scan, 'git_head', return_value=None) as head:
            baseline = self.run_scan()
            head.assert_called_once_with(str(self.root))
            head.reset_mock()
            self.assertEqual(self.run_scan('--no-commit', '--no-commit'), baseline)
            head.assert_not_called()
            self.assertEqual(self.run_scan(), baseline)
            head.assert_called_once_with(str(self.root))

    def test_empty_report_compact_sorted_stdout_and_named_file(self):
        (self.root / 'compose.yml').unlink()
        destination = self.root.parent / 'report.json'
        flags = ('--no-commit', '--compact', '--sort-keys', '--fail-on=low')
        with mock.patch.object(scan, 'git_head', side_effect=AssertionError('HEAD lookup')):
            stdout = self.run_scan(*flags, '--json=-')
            written = self.run_scan(*flags, '--json', str(destination))
        self.assertEqual((stdout[0], stdout[2]), (0, ''))
        self.assertEqual((written[0], written[1]), (0, ''))
        self.assertEqual(destination.read_text(encoding='utf-8'), stdout[1])
        self.assertEqual(len(stdout[1].splitlines()), 1)
        report = json.loads(stdout[1])
        self.assertEqual(list(report), sorted(report))
        self.assertEqual(report['findings'], [])
        self.assertIsNone(report['commit'])
        self.assert_hash_matches_report(report)

    def test_help_documents_lookup_and_clone_scope(self):
        status, text, errors = self.run_scan('--help')
        self.assertEqual((status, errors), (0, ''))
        self.assertIn('--no-commit', text)
        self.assertIn('skip Git HEAD lookup', text)
        self.assertIn('URL targets still clone', text)
