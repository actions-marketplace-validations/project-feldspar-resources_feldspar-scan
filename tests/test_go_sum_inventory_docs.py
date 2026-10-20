"""Pin the documented go.sum inventory scope without network or Go tooling."""
import base64
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from test_scan import scan


class GoSumInventoryDocsTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.path = self.root / 'go.sum'
        self.checksum = 'h1:' + base64.b64encode(bytes(range(32))).decode('ascii')
        self.expected = {
            ('Go', 'example.invalid/library', 'v1.0.0'): 'go.sum',
            ('Go', 'example.invalid/library', 'v2.0.0'): 'go.sum',
            ('Go', 'example.invalid/metadata-only', 'v0.3.0'): 'go.sum',
        }
        self.write_manifest(self.checksum)

    def write_manifest(self, checksum):
        rows = [
            'example.invalid/library v1.0.0',
            'example.invalid/library v1.0.0/go.mod',
            'example.invalid/library v1.0.0',
            'example.invalid/library v2.0.0',
            'example.invalid/metadata-only v0.3.0/go.mod',
        ]
        self.path.write_text(''.join(row + ' ' + checksum + chr(10) for row in rows),
                             encoding='utf-8')

    def report(self, *options):
        with mock.patch.object(scan, 'git_head', return_value=None), \
                mock.patch.object(scan, 'http_json', side_effect=AssertionError('offline')), \
                contextlib.redirect_stdout(io.StringIO()) as stdout, \
                contextlib.redirect_stderr(io.StringIO()) as stderr:
            status = scan.main(['scan.py', str(self.root), '--no-timestamp',
                                '--fail-on=low', *options])
        self.assertEqual((status, stderr.getvalue()), (0, ''))
        return json.loads(stdout.getvalue())

    def assert_inventory(self, report):
        summary = report['summary']
        self.assertEqual(summary['packages_found'], 3)
        self.assertEqual(summary['packages_by_ecosystem'], {'Go': 3})
        self.assertEqual(summary['packages_by_manifest'], {'go.sum': 3})
        self.assertEqual(summary['lockfiles_parsed'], ['go.sum'])
        self.assertEqual(summary['errors_count'], 0)
        self.assertTrue(summary['gate']['passed'])
        self.assertEqual(report['findings'], [])

    def test_inventory_merges_row_kinds_but_keeps_distinct_versions(self):
        scan.ERRORS.clear()
        scan.PARSED_LOCKFILES.clear()
        self.addCleanup(scan.ERRORS.clear)
        self.addCleanup(scan.PARSED_LOCKFILES.clear)
        self.assertEqual(scan.collect_packages(str(self.root), [str(self.path)]),
                         self.expected)
        self.assertEqual(scan.PARSED_LOCKFILES, ['go.sum'])

    def test_exact_advisory_inputs_include_metadata_only_and_old_versions(self):
        with mock.patch.object(scan, 'query_osv', return_value={}) as query:
            report = self.report('--triage')
        query.assert_called_once_with(list(self.expected))
        self.assert_inventory(report)
        self.assertTrue(report['summary']['osv_enabled'])

    def test_offline_inventory_does_not_call_advisory_service(self):
        with mock.patch.object(scan, 'query_osv', side_effect=AssertionError('offline')) as query:
            report = self.report('--no-osv')
        query.assert_not_called()
        self.assert_inventory(report)
        self.assertFalse(report['summary']['osv_enabled'])

    def test_checksum_content_is_not_validated_or_used_in_report(self):
        with mock.patch.object(scan, 'query_osv', return_value={}) as query:
            expected = self.report()
            for checksum in ('h1:' + base64.b64encode(b'x' * 32).decode('ascii'),
                             'h1:synthetic-not-base64!'):
                with self.subTest(checksum=checksum):
                    self.write_manifest(checksum)
                    self.assertEqual(self.report(), expected)
        self.assertEqual(query.call_args_list, [mock.call(list(self.expected))] * 3)
