"""Explicit restoration of Git metadata lookup; all scans are offline."""
import contextlib
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from test_scan import scan


class CommitOptionTests(unittest.TestCase):
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
                mock.patch.object(scan, 'query_osv', side_effect=AssertionError('network lookup')), \
                contextlib.redirect_stdout(io.StringIO()) as stdout, \
                contextlib.redirect_stderr(io.StringIO()) as stderr:
            clock.now.return_value.strftime.return_value = '2026-01-01T00:00:00Z'
            status = scan.main(['scan.py', str(self.root), '--no-osv', *options])
        return status, stdout.getvalue(), stderr.getvalue()

    def test_last_flag_wins_and_invocations_do_not_share_state(self):
        for commit in ('a' * 40, None):
            with self.subTest(commit=commit), \
                    mock.patch.object(scan, 'git_head', return_value=commit) as head:
                expected = {True: self.run_scan(), False: self.run_scan('--no-commit')}
                for flags, enabled in (
                    (('--commit',), True),
                    (('--no-commit', '--commit'), True),
                    (('--commit', '--no-commit'), False),
                    (('--no-commit', '--commit', '--commit'), True),
                    (('--commit', '--no-commit', '--no-commit'), False),
                    ((), True),
                ):
                    with self.subTest(flags=flags):
                        head.reset_mock()
                        self.assertEqual(self.run_scan(*flags), expected[enabled])
                        if enabled:
                            head.assert_called_once_with(str(self.root))
                        else:
                            head.assert_not_called()

    def test_restored_hash_matches_report_and_preserves_findings_triage_gate(self):
        flags = ('--triage', '--fail-on=medium')
        with mock.patch.object(scan, 'git_head', return_value='b' * 40):
            default = self.run_scan(*flags)
            restored = self.run_scan('--no-commit', '--commit', *flags)
        self.assertEqual(restored, default)
        self.assertEqual(restored[0], 1)
        with mock.patch.object(scan, 'git_head', side_effect=AssertionError('HEAD lookup')):
            omitted = self.run_scan('--commit', '--no-commit', *flags)
        self.assertEqual((restored[0], restored[2]), (omitted[0], omitted[2]))
        report, other = json.loads(restored[1]), json.loads(omitted[1])
        self.assertTrue(report['findings'])
        self.assertEqual(report['commit'], 'b' * 40)
        self.assertIsNone(other['commit'])
        self.assertNotEqual(report['manifest_hash'], other['manifest_hash'])
        for doc in (report, other):
            canonical = json.dumps(
                {key: doc[key] for key in ('findings', 'target', 'commit')},
                sort_keys=True, separators=(',', ':'))
            self.assertEqual(doc['manifest_hash'], hashlib.sha256(canonical.encode()).hexdigest())
            del doc['commit'], doc['manifest_hash']
        self.assertEqual(report, other)

    def test_empty_and_populated_reports_stdout_and_file(self):
        destination = self.root.parent / 'report.json'
        for populated in (True, False):
            if not populated:
                (self.root / 'compose.yml').unlink()
            for formatting in ((), ('--compact', '--sort-keys')):
                with self.subTest(populated=populated, formatting=formatting), \
                        mock.patch.object(scan, 'git_head', return_value='c' * 40):
                    flags = (*formatting, '--triage', '--fail-on=medium')
                    expected = self.run_scan(*flags, '--json=-')
                    restored = self.run_scan('--no-commit', '--commit', *flags, '--json=-')
                    self.assertEqual(restored, expected)
                    self.assertEqual(restored[0], 1 if populated else 0)
                    baseline_file = self.run_scan(*flags, '--json', str(destination))
                    expected_bytes = destination.read_bytes()
                    actual_file = self.run_scan('--no-commit', '--commit', *flags,
                                                '--json', str(destination))
                    self.assertEqual(actual_file, baseline_file)
                    self.assertEqual(actual_file[1], '')
                    self.assertEqual(destination.read_bytes(), expected_bytes)
                    self.assertEqual(expected_bytes, restored[1].encode('utf-8'))

    def test_help_documents_default_and_precedence_without_lookup(self):
        with mock.patch.object(scan, 'git_head', side_effect=AssertionError('HEAD lookup')):
            status, text, errors = self.run_scan('--commit', '--help')
        self.assertEqual((status, errors), (0, ''))
        self.assertIn('--commit', text)
        self.assertIn('restore Git HEAD lookup (default)', text)
        self.assertIn('last commit flag wins', text)
