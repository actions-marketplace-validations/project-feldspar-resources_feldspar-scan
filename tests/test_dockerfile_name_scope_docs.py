"""Offline examples of Dockerfile basename selection and independent secrets."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from test_scan import scan


class DockerfileNameScopeDocsTests(unittest.TestCase):
    def report(self, relative, content):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root, relative)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content)
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(io.StringIO()), \
                    mock.patch.object(scan, 'git_head', return_value=None), \
                    mock.patch.object(scan, 'query_osv', side_effect=AssertionError('offline')):
                status = scan.main(['scan.py', root, '--no-osv', '--fail-on', 'medium'])
            return status, json.loads(stdout.getvalue())

    def test_exact_and_dotted_basenames_at_multiple_depths(self):
        content = chr(10).join(['FROM scratch', 'USER root',
                                'RUN curl https://example.invalid/install | sh', ''])
        for name in ('Dockerfile', 'Dockerfile.dev', 'Dockerfile.',
                     'services/api/Dockerfile', 'services/api/Dockerfile.release'):
            with self.subTest(name=name):
                status, report = self.report(name, content)
                self.assertEqual(status, 1)
                self.assertEqual(report['summary']['files_scanned'], 1)
                self.assertEqual(report['summary']['config_issues'], 2)
                self.assertEqual(report['summary']['secret_hits'], 0)
                self.assertEqual(
                    {(f['file'], f['line'], f['severity'], f['summary'])
                     for f in report['findings']},
                    {(name, 2, 'low', 'Dockerfile final USER explicitly runs as root'),
                     (name, 3, 'medium', 'Dockerfile RUN pipes curl output to a shell')})

    def test_other_basenames_skip_dockerfile_checks(self):
        for name in ('Containerfile', 'Containerfile.dev', 'dockerfile', 'DOCKERFILE',
                     'service.Dockerfile', 'Dockerfile-dev',
                     'services/api/dockerfile', 'Dockerfile/settings.txt'):
            with self.subTest(name=name):
                status, report = self.report(
                    name, chr(10).join(['FROM scratch', 'USER root',
                                       'RUN curl https://example.invalid/install | sh', '']))
                self.assertEqual(status, 0)
                self.assertEqual(report['summary']['files_scanned'], 1)
                self.assertEqual(report['findings'], [])
                self.assertEqual(report['summary']['gate']['matching_findings'], 0)

    def test_secret_scanning_still_checks_other_basenames(self):
        synthetic_value = 'A1b2C3d4' + 'E5f6G7h8'
        for name in ('Containerfile', 'dockerfile', 'service.Dockerfile',
                     'services/api/Containerfile'):
            with self.subTest(name=name):
                status, report = self.report(
                    name, chr(10).join(['FROM scratch',
                                       'password="' + synthetic_value + '"', '']))
                self.assertEqual(status, 1)
                self.assertEqual(report['summary']['config_issues'], 0)
                self.assertEqual(report['summary']['secret_hits'], 1)
                finding, = report['findings']
                self.assertEqual((finding['file'], finding['line'], finding['severity']),
                                 (name, 2, 'medium'))
                self.assertEqual(finding['summary'], 'Hardcoded password assignment')
                self.assertEqual(report['summary']['gate']['matching_findings'], 1)
                self.assertNotIn(synthetic_value, json.dumps(report))
