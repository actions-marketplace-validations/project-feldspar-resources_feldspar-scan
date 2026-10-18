"""Pin the documented boundary between Dockerfile config and secret checks."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from test_scan import scan


class DockerLogicalLinesDocsTests(unittest.TestCase):
    def findings(self, lines):
        findings = []

        def add(category, severity, file, line, **fields):
            findings.append(dict(category=category, severity=severity,
                                 file=file, line=line, **fields))

        scan._scan_dockerfile(chr(10).join(lines) + chr(10), 'Dockerfile', add)
        return findings

    def test_continuations_skip_comments_and_use_start_line(self):
        for escape in ('\\', '`'):
            with self.subTest(escape=escape):
                findings = self.findings([
                    '# escape=' + escape, 'FROM scratch', 'USER app',
                    'ADD ' + escape, '# a comment within the continuation', '',
                    '  https://example.invalid/data /data',
                ])
                self.assertEqual(len(findings), 1)
                self.assertEqual(findings[0]['line'], 4)
                self.assertEqual(findings[0]['summary'],
                                 'Dockerfile uses ADD with a remote URL')

    def test_recognized_heredoc_bodies_are_not_instructions(self):
        for operation in ('RUN', 'COPY', 'ADD'):
            for marker in ('END', "'END'", '"END"'):
                with self.subTest(operation=operation, marker=marker):
                    findings = self.findings([
                        'FROM scratch', 'USER app',
                        operation + ' <<' + marker + ' /data',
                        'ENV TOKEN=x', 'USER root',
                        'ADD https://example.invalid/data /data', 'END',
                        'ARG PASSWORD=x',
                    ])
                    self.assertEqual([(f['line'], f['summary']) for f in findings],
                                     [(8, 'Dockerfile ARG assigns secret-like variable PASSWORD')])

    def test_tab_stripping_and_multiple_heredocs_resume_after_last_marker(self):
        findings = self.findings([
            'FROM scratch', 'USER app', 'RUN <<-FIRST <<"SECOND"',
            '\tENV TOKEN=x', '\tFIRST', 'USER root', 'SECOND',
            'ENV TOKEN=x',
        ])
        self.assertEqual([(f['line'], f['summary']) for f in findings],
                         [(8, 'Dockerfile ENV assigns secret-like variable TOKEN')])

    def test_secret_pass_still_checks_comments_and_heredoc_body(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            # Explicitly synthetic placeholders; no real credential material.
            (root / 'Dockerfile').write_text(chr(10).join([
                'FROM scratch', 'USER app',
                '# password="your_placeholder_value"', 'COPY <<END /data',
                'password="your_placeholder_value"', 'END', '',
            ]), encoding='utf-8')
            with mock.patch.object(scan, 'query_osv') as query, \
                    contextlib.redirect_stdout(io.StringIO()) as output, \
                    contextlib.redirect_stderr(io.StringIO()):
                status = scan.main(['scan.py', str(root), '--no-osv',
                                    '--no-commit', '--triage', '--fail-on', 'low'])
                query.assert_not_called()
            report = json.loads(output.getvalue())
            self.assertEqual(status, 1)
            self.assertEqual(report['summary']['config_issues'], 0)
            self.assertEqual(report['summary']['secret_hits'], 2)
            self.assertEqual([(f['category'], f['line']) for f in report['findings']],
                             [('secret', 3), ('secret', 5)])
            self.assertTrue(all(t['action'] == 'informational' and t['likely_false_positive']
                                for t in report['triage'].values()))
            self.assertFalse(report['summary']['gate']['passed'])
