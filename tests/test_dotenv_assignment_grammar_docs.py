"""Pin the documented dotenv name grammar using public, non-secret values."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from test_scan import scan

LF = chr(10)


class DotenvAssignmentGrammarDocsTests(unittest.TestCase):
    def report(self, text, filename='.env', *options):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / filename
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding='utf-8')
            with mock.patch.object(scan, 'query_osv') as query, \
                    contextlib.redirect_stdout(io.StringIO()) as out, \
                    contextlib.redirect_stderr(io.StringIO()):
                status = scan.main(['scan.py', root, '--no-osv', '--no-commit',
                                    '--triage', *options])
                query.assert_not_called()
            return status, json.loads(out.getvalue())

    def test_ascii_names_whitespace_and_lowercase_export(self):
        for filename in ('.env', 'service/.env.local'):
            for assignment in ('A=8080', '_=8080', 'aB_2=8080',
                               ' \tPORT \t=8080', 'export PORT=8080',
                               '\texport\t_PORT2 =8080'):
                with self.subTest(filename=filename, assignment=assignment):
                    status, report = self.report(('# settings' + LF + '' + LF + '') + assignment + LF,
                                                 filename, '--fail-on', 'high')
                    self.assertEqual(status, 1)
                    self.assertEqual(len(report['findings']), 1)
                    finding = report['findings'][0]
                    self.assertEqual((finding['category'], finding['severity'],
                                      finding['file'], finding['line']),
                                     ('config', 'high', filename, 3))
                    self.assertEqual(finding['summary'], 'Committed .env file with assignments')
                    self.assertNotIn('8080', finding['evidence'])

    def test_nonmatching_names_do_not_hide_a_later_assignment(self):
        rejected = ('"PORT"=8080', "'PORT'=8080", 'APP.PORT=8080',
                    'APP-PORT=8080', '1PORT=8080', 'PÖRT=8080',
                    'EXPORT PORT=8080', 'exportPORT 8080', ('export' + LF + 'PORT 8080'))
        for assignment in rejected:
            with self.subTest(assignment=assignment):
                status, report = self.report(assignment + LF, '.env', '--fail-on', 'high')
                self.assertEqual((status, report['findings']), (0, []))
                status, report = self.report(assignment + ('' + LF + 'PORT=8080' + LF + ''), '.env',
                                             '--fail-on', 'high')
                self.assertEqual(status, 1)
                self.assertEqual(len(report['findings']), 1)
                self.assertEqual(report['findings'][0]['line'], assignment.count(LF) + 2)

    def test_line_check_does_not_parse_multiline_quoted_values(self):
        # A matching physical line is still a presence hit inside a quoted value.
        text = ('"MESSAGE"="first line' + LF + 'PORT=8080' + LF + 'last line"' + LF + '')
        status, report = self.report(text, '.env', '--fail-on', 'high')
        self.assertEqual(status, 1)
        self.assertEqual(len(report['findings']), 1)
        self.assertEqual(report['findings'][0]['line'], 2)
        status, report = self.report(('PORT=${PUBLIC_PORT}' + LF + ''), '.env', '--fail-on', 'critical')
        self.assertEqual(status, 0)
        self.assertEqual(len(report['findings']), 1)
        self.assertEqual(report['findings'][0]['severity'], 'high')
