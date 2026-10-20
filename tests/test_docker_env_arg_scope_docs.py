"""Offline examples pin the documented Dockerfile ENV/ARG heuristic scope."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from test_scan import scan


class DockerEnvArgScopeDocsTests(unittest.TestCase):
    def findings(self, instructions):
        findings = []

        def add(category, severity, file, line, **fields):
            findings.append(dict(category=category, severity=severity,
                                 file=file, line=line, **fields))

        scan._scan_dockerfile(chr(10).join(('FROM scratch', 'USER app', '')) + instructions,
                              'Dockerfile', add)
        return findings

    def test_exact_name_suffixes_and_case(self):
        names = ('PASSWORD', 'PASSWD', 'SECRET', 'TOKEN', 'API_KEY',
                 'PRIVATE_KEY', 'SECRET_KEY', 'SECRET_ACCESS_KEY')
        for suffix in names:
            for name in (suffix, 'db_' + suffix.lower()):
                with self.subTest(name=name):
                    findings = self.findings('ENV ' + name + '=x' + chr(10))
                    self.assertEqual(len(findings), 1)
                    self.assertEqual(findings[0]['severity'], 'high')
                    self.assertEqual(findings[0]['summary'],
                                     'Dockerfile ENV assigns secret-like variable ' + name)
                    self.assertEqual(findings[0]['evidence'], name + '=…')
        for name in ('PASSWORD_FILE', 'MYTOKEN', 'KEY', '1_TOKEN',
                     'DB-TOKEN', 'é_TOKEN'):
            with self.subTest(name=name):
                self.assertEqual(self.findings('ENV ' + name + '=x' + chr(10)), [])

    def test_assignment_forms_and_whole_variable_exemptions(self):
        examples = (
            ('ENV TOKEN=x PASSWORD="public value"', ('TOKEN', 'PASSWORD')),
            ('ENV TOKEN public value', ('TOKEN',)),
            ('ARG TOKEN=x', ('TOKEN',)),
            ('ENV TOKEN=${OTHER:-fallback}', ('TOKEN',)),
            ('ENV TOKEN=$OTHER/suffix', ('TOKEN',)),
            ('ENV TOKEN=https://example.invalid', ('TOKEN',)),
            ('ENV TOKEN="" PASSWORD= API_KEY=\'\'', ()),
            ('ARG TOKEN', ()),
            ('ENV TOKEN=$OTHER PASSWORD="${OTHER}" API_KEY=\'$OTHER\'', ()),
        )
        for instruction, names in examples:
            with self.subTest(instruction=instruction):
                findings = self.findings(instruction + chr(10))
                self.assertEqual([f['evidence'] for f in findings],
                                 [name + '=…' for name in names])
                self.assertTrue(all(f['line'] == 3 for f in findings))
                self.assertTrue(all(f['category'] == 'config' for f in findings))

    def test_all_stages_and_continuation_start_locations(self):
        findings = self.findings(chr(10).join((
            'ENV TOKEN=x ' + chr(92), '    PASSWORD=y',
            'FROM scratch', 'USER app', 'ARG API_KEY=z', '')))
        self.assertEqual([(f['line'], f['evidence']) for f in findings],
                         [(3, 'TOKEN=…'), (3, 'PASSWORD=…'), (7, 'API_KEY=…')])

    def test_cli_config_triage_and_gate_with_no_secret_hits(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'examples').mkdir()
            (root / 'examples' / 'Dockerfile').write_text(
                chr(10).join(('FROM scratch', 'USER app', 'ENV TOKEN=x', 'ARG PASSWORD=y', '')),
                encoding='utf-8')
            for threshold, expected_exit in (('high', 1), ('critical', 0)):
                with self.subTest(threshold=threshold), \
                        mock.patch.object(scan, 'query_osv') as query, \
                        contextlib.redirect_stdout(io.StringIO()) as out, \
                        contextlib.redirect_stderr(io.StringIO()):
                    result = scan.main(['scan.py', str(root), '--no-osv',
                                        '--no-commit', '--triage',
                                        '--fail-on', threshold])
                    query.assert_not_called()
                report = json.loads(out.getvalue())
                self.assertEqual(result, expected_exit)
                self.assertEqual(report['summary']['secret_hits'], 0)
                self.assertEqual(report['summary']['config_issues'], 2)
                self.assertEqual(report['summary']['gate']['passed'], not expected_exit)
                self.assertEqual([(f['file'], f['line'], f['severity'], f['evidence'])
                                  for f in report['findings']],
                                 [('examples/Dockerfile', 3, 'high', 'TOKEN=…'),
                                  ('examples/Dockerfile', 4, 'high', 'PASSWORD=…')])
                self.assertTrue(all(t['action'] == 'review'
                                    for t in report['triage'].values()))
                self.assertEqual(report['triage_summary']['config']['needs_review'], 2)
