"""Offline examples of Dockerfile secret-name/value heuristic boundaries."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from test_scan import scan


class DockerSecretScopeDocsTests(unittest.TestCase):
    def findings(self, instruction):
        findings = []
        scan._scan_dockerfile(
            chr(10).join(('FROM scratch', 'USER app', instruction)),
            'Dockerfile', lambda *args, **fields: findings.append((args, fields)))
        return findings

    def test_names_match_exact_suffixes_with_optional_underscore_prefix(self):
        suffixes = ('PASSWORD', 'PASSWD', 'SECRET', 'TOKEN', 'API_KEY',
                    'PRIVATE_KEY', 'SECRET_KEY', 'SECRET_ACCESS_KEY')
        for op in ('ENV', 'ARG'):
            for suffix in suffixes:
                for name in (suffix, 'BUILD_' + suffix, 'build_' + suffix.lower()):
                    with self.subTest(op=op, name=name):
                        hits = self.findings(op + ' ' + name + '=demo')
                        self.assertEqual(len(hits), 1)
                        args, fields = hits[0]
                        self.assertEqual(args, ('config', 'high', 'Dockerfile', 3))
                        self.assertEqual(fields['summary'],
                                         'Dockerfile %s assigns secret-like variable %s' % (op, name))
                        self.assertEqual(fields['evidence'], name + '=…')
            for name in ('KEY', 'APIKEY', 'MYTOKEN', 'TOKEN_FILE', 'TOKEN_PATH',
                         'PASSWORD_HASH', 'API-TOKEN', '1_TOKEN'):
                with self.subTest(op=op, excluded=name):
                    self.assertEqual(self.findings(op + ' ' + name + '=demo'), [])

    def test_value_exemption_is_only_empty_or_whole_simple_reference(self):
        for op in ('ENV', 'ARG'):
            for value in ('', '""', '$BUILD_VALUE', '${BUILD_VALUE}', '"${BUILD_VALUE}"'):
                with self.subTest(op=op, excluded=value):
                    self.assertEqual(self.findings(op + ' API_TOKEN=' + value), [])
            for value in ('demo', 'changeme', 'xxxx', '${BUILD_VALUE:-demo}',
                          '${BUILD_VALUE}/suffix', 'prefix$BUILD_VALUE'):
                with self.subTest(op=op, retained=value):
                    hits = self.findings(op + ' API_TOKEN=' + value)
                    self.assertEqual(len(hits), 1)
                    self.assertEqual(hits[0][0][1], 'high')
                    self.assertEqual(hits[0][1]['evidence'], 'API_TOKEN=…')
        self.assertEqual(self.findings('ARG API_TOKEN'), [])

    def test_legacy_env_and_multiple_assignments_follow_same_rule(self):
        hits = self.findings('ENV API_TOKEN demo')
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0][1]['evidence'], 'API_TOKEN=…')
        self.assertEqual(self.findings('ENV API_TOKEN ${BUILD_VALUE}'), [])
        hits = self.findings('ENV API_TOKEN=demo DB_PASSWORD=changeme PUBLIC=demo')
        self.assertEqual([fields['evidence'] for _, fields in hits],
                         ['API_TOKEN=…', 'DB_PASSWORD=…'])

    def test_placeholder_config_finding_still_requires_review_and_trips_gate(self):
        with tempfile.TemporaryDirectory() as directory:
            Path(directory, 'Dockerfile').write_text(chr(10).join((
                'FROM scratch', 'USER app', 'ENV API_TOKEN=changeme',
            )), encoding='utf-8')
            with mock.patch.object(scan, 'query_osv') as query, \
                    mock.patch.object(scan, 'http_json', side_effect=AssertionError('network')), \
                    mock.patch.object(scan, 'git_head', return_value=None), \
                    contextlib.redirect_stdout(io.StringIO()) as out, \
                    contextlib.redirect_stderr(io.StringIO()):
                status = scan.main(['scan.py', directory, '--no-osv', '--triage',
                                    '--fail-on', 'high'])
                query.assert_not_called()
            report = json.loads(out.getvalue())
            self.assertEqual(status, 1)
            self.assertEqual(len(report['findings']), 1)
            finding = report['findings'][0]
            self.assertEqual(finding['category'], 'config')
            self.assertEqual(finding['severity'], 'high')
            self.assertEqual(finding['evidence'], 'API_TOKEN=…')
            self.assertEqual(report['summary']['secret_hits'], 0)
            self.assertEqual(report['triage'][finding['id']]['action'], 'review')
            self.assertEqual(report['summary']['gate'],
                             {'threshold': 'high', 'matching_findings': 1, 'passed': False})
            self.assertNotIn('changeme', out.getvalue())


if __name__ == '__main__':
    unittest.main()
