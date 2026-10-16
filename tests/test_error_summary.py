"""Offline coverage for the number of recorded report errors."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from test_scan import scan


class ErrorSummaryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def run_scan(self, *args, response=None):
        output = io.StringIO()
        with mock.patch.object(scan, 'http_json', side_effect=response) as http, \
                contextlib.redirect_stdout(output), \
                contextlib.redirect_stderr(io.StringIO()):
            code = scan.main(['scan.py', str(self.root), *args])
        return code, json.loads(output.getvalue()), http.call_count

    def test_zero_for_empty_offline_and_successful_lookup(self):
        for has_packages in (False, True):
            if has_packages:
                (self.root / 'requirements.txt').write_text('demo-package==1.2.3' + chr(10))
            for offline in (False, True):
                with self.subTest(packages=has_packages, offline=offline):
                    code, doc, calls = self.run_scan(
                        *(['--no-osv'] if offline else []),
                        response=lambda *a: {'results': [{}]})
                    self.assertEqual(code, 0)
                    self.assertEqual(doc['summary']['errors_count'], 0)
                    self.assertNotIn('errors', doc)
                    self.assertEqual(calls, int(has_packages and not offline))

    def test_query_failure_and_next_scan_reset(self):
        (self.root / 'requirements.txt').write_text('demo-package==1.2.3' + chr(10))
        code, failed, calls = self.run_scan(response=OSError('synthetic outage'))
        self.assertEqual((code, calls), (0, 1))
        self.assertEqual(failed['summary']['errors_count'], 1)
        self.assertEqual(failed['errors'], ['osv querybatch: synthetic outage'])
        code, clean, calls = self.run_scan('--no-osv')
        self.assertEqual((code, calls), (0, 0))
        self.assertEqual(clean['summary']['errors_count'], 0)
        self.assertNotIn('errors', clean)
        self.assertEqual(failed['findings'], clean['findings'])
        self.assertEqual(failed['manifest_hash'], clean['manifest_hash'])

    def test_multiple_detail_errors_preserve_gate_and_triage(self):
        (self.root / 'requirements.txt').write_text('demo-package==1.2.3' + chr(10))

        def response(url, *args):
            if url == scan.OSV_BATCH:
                return {'results': [{'vulns': [{'id': 'TEST-A'}, {'id': 'TEST-B'}]}]}
            raise OSError('synthetic detail outage')

        results = []
        for args in ((), ('--triage', '--fail-on', 'low')):
            code, doc, calls = self.run_scan(*args, response=response)
            self.assertEqual((code, calls), (0, 3))
            self.assertEqual(doc['summary']['errors_count'], 2)
            self.assertEqual(doc['summary']['errors_count'], len(doc['errors']))
            self.assertCountEqual(doc['errors'], [
                'osv vuln TEST-A: synthetic detail outage',
                'osv vuln TEST-B: synthetic detail outage'])
            self.assertEqual(doc['findings'][0]['severity'], 'unknown')
            results.append(doc)
        self.assertEqual(results[0]['findings'], results[1]['findings'])
        self.assertEqual(results[0]['manifest_hash'], results[1]['manifest_hash'])

    def test_named_output_with_failed_gate(self):
        (self.root / 'requirements.txt').write_text('demo-package==1.2.3' + chr(10))
        (self.root / 'Dockerfile').write_text(chr(10).join(('FROM scratch', 'USER root', '')))
        with tempfile.TemporaryDirectory() as destination:
            report = Path(destination) / 'report.json'
            with mock.patch.object(scan, 'http_json', side_effect=OSError('synthetic outage')), \
                    contextlib.redirect_stdout(io.StringIO()) as stdout, \
                    contextlib.redirect_stderr(io.StringIO()):
                code = scan.main(['scan.py', str(self.root), '--json', str(report),
                                  '--fail-on', 'low'])
            self.assertEqual(code, 1)
            self.assertEqual(stdout.getvalue(), '')
            doc = json.loads(report.read_text())
            self.assertEqual(doc['summary']['errors_count'], 1)
            self.assertEqual(doc['summary']['errors_count'], len(doc['errors']))
            self.assertEqual(doc['summary']['config_issues'], 1)


if __name__ == '__main__':
    unittest.main()
