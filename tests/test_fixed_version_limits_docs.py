"""Offline examples of the documented fix-metadata collection limits."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from test_scan import scan


def advisory(*versions):
    return {'affected': [{'ranges': [{'events': [
        {'fixed': version} for version in versions]}]}]}


class FixedVersionLimitsDocsTests(unittest.TestCase):
    def test_collects_across_packages_and_ranges_without_applicability_filter(self):
        payload = {'affected': [
            {'package': {'ecosystem': 'PyPI', 'name': 'sample'}, 'ranges': [
                {'type': 'ECOSYSTEM', 'events': [
                    {'introduced': '0'}, {'fixed': '2.0'},
                    {'last_affected': '8.0'}, {'limit': '9.0'}, {'fixed': ''}]},
                {'type': 'SEMVER', 'events': [{'fixed': '10.0'}]}]},
            {'package': {'ecosystem': 'npm', 'name': 'unrelated'}, 'ranges': [
                {'type': 'GIT', 'repo': 'https://example.invalid/source',
                 'events': [{'fixed': 'revision-z'}, {'fixed': '2.0'}]}]},
        ]}
        with mock.patch.object(scan, 'http_json', return_value=payload) as http:
            result = scan.vuln_details('SYNTHETIC-COLLECTION', {})
        http.assert_called_once_with(scan.OSV_VULN + 'SYNTHETIC-COLLECTION')
        self.assertEqual(result['fixed_in'], ['10.0', '2.0', 'revision-z'])

    def test_deduplicates_and_sorts_as_strings_before_ten_value_cap(self):
        payload = advisory('9.0', '8.0', '7.0', '6.0', '5.0', '4.0',
                           '3.0', '2.0', '11.0', '10.0', '1.0', '1.0')
        with mock.patch.object(scan, 'http_json', return_value=payload):
            result = scan.vuln_details('SYNTHETIC-CAPPED', {})
        self.assertEqual(result['fixed_in'], [
            '1.0', '10.0', '11.0', '2.0', '3.0', '4.0', '5.0', '6.0', '7.0', '8.0'])

    def test_report_unions_capped_lists_and_triage_reuses_the_union(self):
        payloads = {
            'SYNTHETIC-A': advisory('9.0', '8.0', '7.0', '6.0', '5.0', '4.0',
                                    '3.0', '2.0', '11.0', '10.0', '1.0'),
            'SYNTHETIC-B': advisory('2.0', '20.0', '21.0'),
        }
        def offline_http(url, data=None, **kwargs):
            if url == scan.OSV_BATCH:
                self.assertEqual(data['queries'], [{
                    'package': {'name': 'sample', 'ecosystem': 'PyPI'},
                    'version': '0.1'}])
                return {'results': [{'vulns': [{'id': key} for key in payloads]}]}
            return payloads[url.removeprefix(scan.OSV_VULN)]

        with tempfile.TemporaryDirectory() as root:
            Path(root, 'requirements.txt').write_text('sample==0.1' + chr(10))
            output = io.StringIO()
            with mock.patch.object(scan, 'http_json', side_effect=offline_http), \
                    contextlib.redirect_stdout(output), \
                    contextlib.redirect_stderr(io.StringIO()):
                status = scan.main(['scan.py', root, '--triage', '--no-commit'])
            report = json.loads(output.getvalue())
        expected = ['1.0', '10.0', '11.0', '2.0', '20.0', '21.0',
                    '3.0', '4.0', '5.0', '6.0', '7.0', '8.0']
        self.assertEqual(status, 0)
        self.assertEqual(len(report['findings']), 1)
        finding = report['findings'][0]
        self.assertEqual(finding['fixed_in'], expected)
        self.assertEqual(report['triage'][finding['id']]['action'], 'upgrade')
        self.assertEqual(report['triage'][finding['id']]['upgrade_to'], expected)
        self.assertEqual(report['summary']['dependency_findings_with_fixes'], 1)
        self.assertEqual(report.get('errors', []), [])
