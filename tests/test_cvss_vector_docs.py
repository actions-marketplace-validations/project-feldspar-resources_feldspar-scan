"""Pin documented severity coverage using synthetic offline advisory responses."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from test_scan import scan


VECTOR = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'


class CvssVectorDocumentationTests(unittest.TestCase):
    def test_readme_explains_unsupported_vectors_and_gate(self):
        readme = Path(scan.__file__).with_name('README.md').read_text()
        self.assertIn('CVSS vector strings are not evaluated', readme)
        self.assertIn('`unknown` findings do not trigger `--fail-on`', readme)

    def test_vector_only_advisory_remains_visible_but_does_not_trip_gate(self):
        advisory = {'severity': [{'type': 'CVSS_V3', 'score': VECTOR}]}
        with tempfile.TemporaryDirectory() as root:
            Path(root, 'requirements.txt').write_text('synthetic-package==1.2.3' + chr(10))
            output = io.StringIO()
            with mock.patch.object(scan, 'query_osv', return_value={
                    ('PyPI', 'synthetic-package', '1.2.3'): ['SYNTHETIC-ADVISORY']}), \
                    mock.patch.object(scan, 'http_json', return_value=advisory) as http, \
                    mock.patch.object(scan, 'git_head', return_value=None), \
                    contextlib.redirect_stdout(output), \
                    contextlib.redirect_stderr(io.StringIO()):
                status = scan.main(['scan.py', root, '--fail-on', 'low'])
        self.assertEqual(status, 0)
        http.assert_called_once_with(scan.OSV_VULN + 'SYNTHETIC-ADVISORY')
        report = json.loads(output.getvalue())
        self.assertEqual(len(report['findings']), 1)
        finding = report['findings'][0]
        self.assertEqual(finding['category'], 'dependency-vuln')
        self.assertEqual(finding['severity'], 'unknown')
        self.assertEqual(finding['vuln_ids'], ['SYNTHETIC-ADVISORY'])
        self.assertEqual(report['summary']['vulnerable_packages'], 1)
        self.assertEqual(report['summary']['by_severity']['unknown'], 1)

    def test_supported_severity_sources_still_rate_vector_advisories(self):
        cases = [
            ({'database_specific': {'severity': 'HIGH'},
              'severity': [{'score': VECTOR}, {'score': '4.0'}]}, 'high'),
            ({'severity': [{'score': VECTOR}, {'score': '9.8'}]}, 'critical'),
            ({'severity': [{'score': VECTOR}, {'score': '4.0'}]}, 'medium'),
        ]
        for advisory, expected in cases:
            with self.subTest(expected=expected), \
                    mock.patch.object(scan, 'http_json', return_value=advisory):
                self.assertEqual(scan.vuln_details('SYNTHETIC-ADVISORY', {})['severity'], expected)
