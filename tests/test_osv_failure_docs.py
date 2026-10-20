"""Offline examples of the README's OSV request-failure semantics."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import scan


class OsvFailureDocsTests(unittest.TestCase):
    def test_failed_batch_skips_chunk_but_continues(self):
        packages = [('PyPI', 'demo-%03d' % n, '1.0') for n in range(501)]
        with mock.patch.object(scan, 'ERRORS', []), mock.patch.object(
            scan, 'http_json', side_effect=[
                OSError('synthetic batch unavailable'),
                {'results': [{'vulns': [{'id': 'TEST-REMAINING'}]}]},
            ]
        ) as http:
            self.assertEqual(scan.query_osv(packages),
                             {packages[-1]: ['TEST-REMAINING']})
            self.assertEqual(scan.ERRORS,
                             ['osv querybatch: synthetic batch unavailable'])
        self.assertEqual(http.call_count, 2)
        first, second = [call.args[1]['queries'] for call in http.call_args_list]
        self.assertEqual(len(first), 500)
        self.assertEqual(second, [{'package': {'name': 'demo-500',
                                              'ecosystem': 'PyPI'},
                                   'version': '1.0'}])

    def report(self, http_response):
        with tempfile.TemporaryDirectory() as root:
            Path(root, 'requirements.txt').write_text(
                chr(10).join(('demo-alpha==1.0', 'demo-beta==2.0', '')),
                encoding='utf-8')
            out, err = io.StringIO(), io.StringIO()
            with mock.patch.object(scan, 'http_json', side_effect=http_response) as http, \
                    mock.patch.object(scan, 'git_head', return_value=None), \
                    contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                status = scan.main(['scan.py', root, '--triage', '--fail-on', 'low'])
            return status, json.loads(out.getvalue()), http

    def test_failed_batch_keeps_inventory_without_dependency_findings(self):
        status, report, http = self.report(OSError('synthetic batch unavailable'))
        self.assertEqual(status, 0)
        self.assertEqual(http.call_count, 1)
        self.assertEqual(report['summary']['packages_found'], 2)
        self.assertEqual(report['summary']['vulnerable_packages'], 0)
        self.assertEqual(report['findings'], [])
        self.assertEqual(report['errors'],
                         ['osv querybatch: synthetic batch unavailable'])
        self.assertEqual(report['summary']['errors_count'], 1)
        self.assertTrue(report['summary']['gate']['passed'])

    def test_failed_details_keep_known_ids_and_cache_fallback(self):
        for mixed in (False, True):
            with self.subTest(mixed=mixed):
                ids = ['TEST-FAILED'] + (['TEST-GOOD'] if mixed else [])

                def response(url, payload=None):
                    if url == scan.OSV_BATCH:
                        return {'results': [{'vulns': [{'id': i} for i in ids]}
                                            for _ in payload['queries']]}
                    if url == scan.OSV_VULN + 'TEST-FAILED':
                        raise OSError('synthetic detail unavailable')
                    if url == scan.OSV_VULN + 'TEST-GOOD':
                        return {'summary': 'Synthetic rated advisory',
                                'database_specific': {'severity': 'HIGH'},
                                'affected': [{'ranges': [{'events': [{'fixed': '3.0'}]}]}]}
                    raise AssertionError('unexpected HTTP request')

                status, report, http = self.report(response)
                self.assertEqual(status, 1 if mixed else 0)
                self.assertEqual(report['summary']['packages_found'], 2)
                self.assertEqual(report['summary']['vulnerable_packages'], 2)
                self.assertEqual(len(report['findings']), 2)
                self.assertEqual(report['errors'],
                                 ['osv vuln TEST-FAILED: synthetic detail unavailable'])
                self.assertEqual(report['summary']['errors_count'], 1)
                self.assertEqual(report['summary']['gate']['passed'], not mixed)
                for finding in report['findings']:
                    self.assertEqual(finding['vuln_ids'], sorted(ids))
                    self.assertEqual(finding['severity'], 'high' if mixed else 'unknown')
                    self.assertEqual(finding['fixed_in'], ['3.0'] if mixed else [])
                    self.assertEqual(report['triage'][finding['id']]['action'],
                                     'upgrade' if mixed else 'monitor')
                # Shared advisory details, including failures, are fetched only once
                # in this scan despite being used by two package findings.
                urls = [call.args[0] for call in http.call_args_list]
                self.assertEqual(urls.count(scan.OSV_BATCH), 1)
                for advisory in ids:
                    self.assertEqual(urls.count(scan.OSV_VULN + advisory), 1)


if __name__ == '__main__':
    unittest.main()
