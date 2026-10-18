"""Pin the documented declaration-only workflow checks, without running workflows."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from test_scan import scan


class WorkflowConditionsDocsTests(unittest.TestCase):
    def workflow(self, condition):
        return chr(10).join([
            'on: [pull_request, pull_request_target]',
            'jobs:',
            '  review:',
            '    if: ' + condition,
            '    permissions:',
            '      contents: write',
            '    steps:',
            '      - uses: actions/checkout@v4',
            '        if: ' + condition,
            '        with:',
            '          ref: ${{ github.event.pull_request.head.sha }}',
            '',
        ])

    def test_conditions_do_not_filter_workflow_declarations(self):
        expected = [
            ('low', 8, 'Unpinned remote GitHub Action or reusable workflow'),
            ('medium', 6, 'PR-triggered workflow requests write permissions'),
            ('high', 11, 'pull_request_target checks out PR head'),
        ]
        for condition in ('false', '${{ false }}', 'true', '${{ github.event_name == "push" }}'):
            with self.subTest(condition=condition):
                findings = []
                def add(category, severity, file, line, **fields):
                    self.assertEqual(category, 'config')
                    findings.append((severity, line, fields['summary']))
                scan.scan_workflow(self.workflow(condition), '.github/workflows/review.yml', add)
                self.assertEqual(findings, expected)

    def test_disabled_workflow_findings_reach_report_triage_and_gate(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workflow = root / '.github/workflows/review.yml'
            workflow.parent.mkdir(parents=True)
            workflow.write_text(self.workflow('${{ false }}'), encoding='utf-8')
            stdout, stderr = io.StringIO(), io.StringIO()
            with mock.patch.object(scan, 'git_head', return_value=None), \
                    mock.patch.object(scan, 'http_json', side_effect=AssertionError('network')), \
                    contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                status = scan.main(['scan.py', str(root), '--no-osv', '--triage', '--fail-on', 'high'])
            report = json.loads(stdout.getvalue())
            self.assertEqual(status, 1)
            self.assertIn('gate: findings at or above high severity', stderr.getvalue())
            self.assertEqual(report['summary']['config_issues'], 3)
            self.assertEqual(len(report['findings']), 3)
            self.assertEqual([f['severity'] for f in report['findings']], ['high', 'medium', 'low'])
            self.assertEqual({f['file'] for f in report['findings']}, {'.github/workflows/review.yml'})
            self.assertEqual(set(report['triage']), {f['id'] for f in report['findings']})
            self.assertTrue(all(t['action'] == 'review' for t in report['triage'].values()))
