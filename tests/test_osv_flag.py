"""Explicit OSV selection; synthetic advisories and no network access."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from test_scan import scan


class OsvFlagTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name) / 'repo'
        self.root.mkdir()
        (self.root / 'requirements.txt').write_text('demo==1.0' + chr(10), encoding='utf-8')

    def run_scan(self, *flags):
        def response(url, payload=None):
            if url == scan.OSV_BATCH:
                self.assertEqual(payload, {'queries': [{
                    'package': {'name': 'demo', 'ecosystem': 'PyPI'},
                    'version': '1.0'}]})
                return {'results': [{'vulns': [{'id': 'SYNTHETIC-507'}]}]}
            self.assertEqual(url, scan.OSV_VULN + 'SYNTHETIC-507')
            return {'summary': 'Synthetic advisory',
                    'database_specific': {'severity': 'HIGH'},
                    'affected': [{'ranges': [{'events': [{'fixed': '2.0'}]}]}]}

        with mock.patch.object(scan, 'http_json', side_effect=response) as http, \
                mock.patch.object(scan, 'git_head', return_value=None), \
                contextlib.redirect_stdout(io.StringIO()) as out, \
                contextlib.redirect_stderr(io.StringIO()) as err:
            status = scan.main(['scan.py', str(self.root), '--no-timestamp', *flags])
        return status, out.getvalue(), err.getvalue(), http.call_count

    def test_restores_default_findings_triage_and_gates(self):
        for threshold, status in (('high', 1), ('critical', 0)):
            flags = ('--triage', '--fail-on', threshold)
            baseline = self.run_scan(*flags)
            self.assertEqual(baseline[0], status)
            self.assertEqual(baseline[3], 2)
            report = json.loads(baseline[1])
            self.assertEqual(report['findings'][0]['vuln_ids'], ['SYNTHETIC-507'])
            self.assertEqual(report['findings'][0]['fixed_in'], ['2.0'])
            self.assertTrue(report['summary']['osv_enabled'])
            for selection in (('--osv',), ('--no-osv', '--osv'),
                              ('--osv', '--osv'), ('--no-osv', '--osv', '--osv')):
                with self.subTest(threshold=threshold, selection=selection):
                    self.assertEqual(self.run_scan(*flags, *selection), baseline)

    def test_final_offline_flag_prevents_all_lookups_and_keeps_inventory(self):
        flags = ('--triage', '--fail-on=high')
        baseline = self.run_scan(*flags, '--no-osv')
        self.assertEqual(baseline[0], 0)
        self.assertEqual(baseline[3], 0)
        report = json.loads(baseline[1])
        self.assertFalse(report['summary']['osv_enabled'])
        self.assertEqual(report['summary']['packages_found'], 1)
        self.assertEqual(report['findings'], [])
        for selection in (('--osv', '--no-osv'),
                          ('--no-osv', '--osv', '--no-osv')):
            with self.subTest(selection=selection):
                self.assertEqual(self.run_scan(*flags, *selection), baseline)
        self.assertEqual(self.run_scan()[3], 2)  # No state leaks across invocations.

    def test_named_output_and_formatting_match_default(self):
        flags = ('--compact', '--sort-keys', '--triage', '--fail-on=high')
        baseline = self.run_scan(*flags)
        destination = self.root.parent / 'report.json'
        result = self.run_scan(*flags, '--no-osv', '--osv', '--json', str(destination))
        self.assertEqual((result[0], result[1], result[3]), (1, '', 2))
        self.assertEqual(destination.read_text(encoding='utf-8'), baseline[1])
        self.assertIn(baseline[2], result[2])
        self.assertEqual(len(baseline[1].splitlines()), 1)

    def test_empty_inventory_and_help_make_no_lookup(self):
        (self.root / 'requirements.txt').unlink()
        for flags in (('--osv',), ('--no-osv', '--osv')):
            result = self.run_scan(*flags)
            self.assertEqual((result[0], result[3]), (0, 0))
            self.assertEqual(json.loads(result[1])['findings'], [])
            self.assertTrue(json.loads(result[1])['summary']['osv_enabled'])
        result = self.run_scan('--osv', '--help')
        self.assertEqual((result[0], result[3]), (0, 0))
        self.assertIn('--osv', result[1])
        self.assertIn('last lookup flag wins', result[1])
