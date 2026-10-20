"""Document pin-shape checks without fetching or executing any workflow refs."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from test_scan import scan


class WorkflowPinScopeDocsTests(unittest.TestCase):
    def findings(self, reference, reusable=False):
        lines = ['on: push', 'jobs:', '  check:']
        lines += (['    uses: ' + reference] if reusable else
                  ['    steps:', '      - uses: ' + reference])
        findings = []
        scan.scan_workflow(chr(10).join(lines), '.github/workflows/check.yml',
                           lambda *args, **fields: findings.append((args, fields)))
        return findings

    def test_remote_pin_is_only_a_hexadecimal_shape_check(self):
        for reusable in (False, True):
            remote = 'owner/repo/.github/workflows/check.yml' if reusable else 'owner/repo/path'
            for ref, flagged in [('0' * 40, False), ('aB09' * 10, False),
                                 ('v1', True), ('main', True), ('a' * 39, True),
                                 ('a' * 41, True), ('g' * 40, True)]:
                with self.subTest(reusable=reusable, ref=ref):
                    findings = self.findings(remote + '@' + ref, reusable)
                    self.assertEqual(len(findings), int(flagged))
                    if flagged:
                        args, fields = findings[0]
                        self.assertEqual(args[:2], ('config', 'low'))
                        self.assertEqual(fields['summary'],
                                         'Unpinned remote GitHub Action or reusable workflow')

    def test_local_container_and_missing_ref_are_outside_pin_check(self):
        for reference in ('./local/action@main', '../local/action@main',
                          './.github/workflows/reuse.yml', 'docker://alpine:latest',
                          'docker://example.invalid/team/image@sha256:' + 'a' * 64,
                          'owner/repo'):
            with self.subTest(reference=reference):
                self.assertEqual(self.findings(reference), [])

    def test_pin_shape_does_not_suppress_pr_head_finding_or_gate(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            workflow = root / '.github/workflows/check.yml'
            workflow.parent.mkdir(parents=True)
            workflow.write_text(chr(10).join([
                'on: pull_request_target', 'jobs:', '  check:', '    steps:',
                '      - uses: actions/checkout@' + '0' * 40,
                '        with:', '          ref: ${{ github.event.pull_request.head.sha }}',
            ]), encoding='utf-8')
            with mock.patch.object(scan, 'query_osv') as query, \
                    mock.patch.object(scan, 'http_json', side_effect=AssertionError('network')), \
                    mock.patch.object(scan, 'git_head', return_value=None), \
                    mock.patch.object(scan.subprocess, 'run', side_effect=AssertionError('process')), \
                    contextlib.redirect_stdout(io.StringIO()) as out, \
                    contextlib.redirect_stderr(io.StringIO()):
                status = scan.main(['scan.py', str(root), '--no-osv', '--triage',
                                    '--fail-on', 'high'])
                query.assert_not_called()
            report = json.loads(out.getvalue())
            self.assertEqual(status, 1)
            self.assertEqual(len(report['findings']), 1)
            finding = report['findings'][0]
            self.assertEqual(finding['summary'], 'pull_request_target checks out PR head')
            self.assertEqual(finding['severity'], 'high')
            self.assertEqual(report['triage'][finding['id']]['action'], 'review')
            self.assertEqual(report['summary']['gate'],
                             {'threshold': 'high', 'matching_findings': 1, 'passed': False})
