"""Abbreviated reports retain scan results, coverage warnings and gate behavior."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from test_scan import scan


class SummaryOnlyTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name) / 'repo'
        self.root.mkdir()
        (self.root / 'Dockerfile').write_text('FROM scratch' + chr(10), encoding='utf-8')

    def run_scan(self, *options):
        with mock.patch.object(scan, 'datetime') as clock, \
                contextlib.redirect_stdout(io.StringIO()) as stdout, \
                contextlib.redirect_stderr(io.StringIO()) as stderr:
            clock.now.return_value.strftime.return_value = '2026-01-01T00:00:00Z'
            status = scan.main(['scan.py', str(self.root), '--no-osv', *options])
        return status, stdout.getvalue(), stderr.getvalue()

    def abbreviated(self, full):
        result = dict(full)
        result.pop('findings')
        result.pop('triage', None)
        return result

    def test_only_details_are_omitted_and_default_is_unchanged(self):
        for options in ((), ('--triage',), ('--triage', '--no-triage')):
            with self.subTest(options=options):
                original = self.run_scan(*options)
                full = json.loads(original[1])
                self.assertTrue(full['findings'])
                if options == ('--triage',):
                    self.assertTrue(full['triage'])
                for flags in (('--summary-only', *options),
                              (*options, '--summary-only', '--summary-only')):
                    status, output, error = self.run_scan(*flags)
                    self.assertEqual((status, error), (original[0], original[2]))
                    self.assertEqual(json.loads(output), self.abbreviated(full))
                self.assertEqual(self.run_scan(*options), original)

    def test_passed_and_failed_gates_retain_counts_and_diagnostics(self):
        for threshold, expected_status in (('low', 1), ('critical', 0), ('none', 0)):
            with self.subTest(threshold=threshold):
                options = ('--triage', '--fail-on=' + threshold)
                full = self.run_scan(*options)
                status, output, error = self.run_scan(*options, '--summary-only')
                self.assertEqual(status, expected_status)
                self.assertEqual(error, full[2])
                self.assertEqual(json.loads(output), self.abbreviated(json.loads(full[1])))

    def test_file_and_stdout_destinations_keep_formatting(self):
        destination = self.root.parent / 'report.json'
        for options in ((), ('--compact', '--sort-keys'), ('--compact', '--pretty')):
            with self.subTest(options=options):
                full = self.run_scan('--triage', *options)
                expected = self.abbreviated(json.loads(full[1]))
                status, output, error = self.run_scan(
                    '--triage', *options, '--summary-only', '--json', '-')
                self.assertEqual((status, error), (0, ''))
                self.assertEqual(json.loads(output), expected)
                if '--sort-keys' in options:
                    self.assertEqual(output, json.dumps(
                        expected, separators=(',', ':'), sort_keys=True) + chr(10))
                else:
                    self.assertEqual(output, json.dumps(expected, indent=2) + chr(10))
                status, stdout, error = self.run_scan(
                    '--triage', *options, '--summary-only', '--json=' + str(destination))
                self.assertEqual((status, stdout), (0, ''))
                self.assertEqual(destination.read_text(encoding='utf-8'), output)
                self.assertIn('wrote %s (%d findings)' % (
                    destination, len(json.loads(full[1])['findings'])), error)

    def test_errors_and_coverage_warnings_are_preserved(self):
        (self.root / 'package-lock.json').write_text('{', encoding='utf-8')
        failing_parser = mock.Mock(side_effect=OSError('synthetic failure'))
        with mock.patch.dict(scan.DEP_HANDLERS, {'package-lock.json': failing_parser}):
            full = json.loads(self.run_scan()[1])
            self.assertTrue(full['errors'])
            self.assertTrue(full['summary']['notes'])
            status, output, error = self.run_scan('--summary-only')
        self.assertEqual((status, error), (0, ''))
        self.assertEqual(json.loads(output), self.abbreviated(full))

    def test_truncation_remains_visible(self):
        (self.root / 'docker-compose.yml').write_text(
            chr(10).join(('services:', '  app:', '    privileged: true', '')), encoding='utf-8')
        with mock.patch.object(scan, 'MAX_FINDINGS', 1):
            full = json.loads(self.run_scan()[1])
            self.assertTrue(full['summary']['truncated']['findings'])
            status, output, error = self.run_scan('--summary-only')
        self.assertEqual((status, error), (0, ''))
        self.assertEqual(json.loads(output), self.abbreviated(full))

    def test_empty_scan_still_omits_details(self):
        (self.root / 'Dockerfile').unlink()
        full = json.loads(self.run_scan('--triage')[1])
        self.assertEqual(full['findings'], [])
        status, output, error = self.run_scan('--summary-only', '--triage')
        self.assertEqual((status, error), (0, ''))
        self.assertEqual(json.loads(output), self.abbreviated(full))

    def test_help_documents_abbreviated_output(self):
        status, output, error = self.run_scan('--help')
        self.assertEqual((status, error), (0, ''))
        self.assertIn('--summary-only', output)
        self.assertIn('omit findings and per-finding triage', output)
