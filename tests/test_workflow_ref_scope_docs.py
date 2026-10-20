"""Pin the documented literal-expression scope without evaluating workflows."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from test_scan import scan


class WorkflowRefScopeDocsTests(unittest.TestCase):
    def workflow(self, ref, event='pull_request_target', separate=False):
        lines = ['on: ' + event, 'jobs:', '  build:', '    steps:',
                 '      - uses: actions/checkout@' + 'a' * 40]
        if separate:
            lines.append('      - name: Different step')
        lines.extend(['        with:', '          ref: ' + ref])
        return chr(10).join(lines) + chr(10)

    def findings(self, text):
        findings = []
        scan.scan_workflow(text, '.github/workflows/check.yml',
                           lambda *args, **kwargs: findings.append((args, kwargs)))
        return findings

    def test_literal_expressions_allow_whitespace_quotes_and_embedded_matches(self):
        for name in ('github.event.pull_request.head.sha',
                     'github.event.pull_request.head.ref', 'github.head_ref'):
            for ref in ('${{' + name + '}}', '${{  ' + name + '  }}',
                        "'${{ " + name + " }}'", 'prefix-${{ ' + name + ' }}-suffix'):
                with self.subTest(name=name, ref=ref):
                    findings = self.findings(self.workflow(ref))
                    self.assertEqual(len(findings), 1)
                    args, details = findings[0]
                    self.assertEqual(args, ('config', 'high', '.github/workflows/check.yml', 7))
                    self.assertEqual(details['summary'], 'pull_request_target checks out PR head')
                    self.assertEqual(details['evidence'],
                                     'actions/checkout ref uses a pull request head expression')

    def test_other_expression_spellings_are_not_evaluated(self):
        for ref in ("${{ github['head_ref'] }}", '${{ env.SELECTED_REF }}',
                    "${{ github.head_ref || 'main' }}", '${{ GITHUB.head_ref }}',
                    '${{ github.event.pull_request.base.sha }}', 'main'):
            with self.subTest(ref=ref):
                self.assertEqual(self.findings(self.workflow(ref)), [])

    def test_event_and_same_step_are_required(self):
        ref = '${{ github.head_ref }}'
        self.assertEqual(self.findings(self.workflow(ref, event='pull_request')), [])
        self.assertEqual(self.findings(self.workflow(ref, separate=True)), [])

    def test_report_gate_and_triage_preserve_literal_check(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / '.github/workflows/check.yml'
            target.parent.mkdir(parents=True)
            for ref, expected in (('${{ github.head_ref }}', 1),
                                  ("${{ github['head_ref'] }}", 0)):
                target.write_text(self.workflow(ref), encoding='utf-8')
                with self.subTest(ref=ref), mock.patch.object(scan, 'query_osv') as query, \
                        contextlib.redirect_stdout(io.StringIO()) as out, \
                        contextlib.redirect_stderr(io.StringIO()):
                    status = scan.main(['scan.py', str(root), '--no-osv', '--no-commit',
                                        '--triage', '--fail-on', 'high'])
                    query.assert_not_called()
                    report = json.loads(out.getvalue())
                    self.assertEqual(status, expected)
                    self.assertEqual(len(report['findings']), expected)
                    self.assertEqual(len(report['triage']), expected)
                    if expected:
                        self.assertEqual(report['findings'][0]['line'], 7)
                        self.assertEqual(report['findings'][0]['severity'], 'high')
                        self.assertEqual(next(iter(report['triage'].values()))['action'], 'review')
