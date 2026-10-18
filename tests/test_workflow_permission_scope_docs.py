"""Reproduce the documented permission-declaration scope without running CI."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from test_scan import scan


class WorkflowPermissionScopeDocsTests(unittest.TestCase):
    def findings(self, text):
        found = []
        def add(category, severity, file, line, **fields):
            found.append((category, severity, line, fields['summary']))
        scan.scan_workflow(text, '.github/workflows/check.yml', add)
        return found

    def test_job_overrides_do_not_remove_workflow_write_declaration(self):
        for permission in ('read-all', '{}', '{contents: read}'):
            with self.subTest(permission=permission):
                text = ('''on: pull_request
permissions: write-all
jobs:
'''
                        '''  check:
    permissions: ''' + permission + '''
'''
                        '''    steps:
      - run: echo checking
''')
                self.assertEqual(self.findings(text), [
                    ('config', 'medium', 2, 'PR-triggered workflow requests write permissions')])

    def test_each_write_declaration_counts_without_inheritance(self):
        text = ('''on: pull_request
permissions:
  contents: write
'''
                '''  issues: write
jobs:
  check:
'''
                '''    permissions: {contents: write, issues: write}
''')
        found = self.findings(text)
        # Each block scope is a declaration; one inline mapping is one declaration.
        self.assertEqual([f[2] for f in found], [3, 4, 7])
        self.assertTrue(all(f[0:2] == ('config', 'medium') for f in found))
        self.assertEqual(self.findings('''on: pull_request
jobs:
  check:
'''
                                       '''    steps:
      - run: echo checking
'''), [])
        self.assertEqual(self.findings('''on: pull_request
permissions: read-all
'''), [])

    def test_event_scope_does_not_imply_other_triggers_are_safe(self):
        for events, count in (('pull_request', 1), ('[push, pull_request]', 1),
                              ('pull_request_target', 0), ('push', 0),
                              ('workflow_dispatch', 0)):
            with self.subTest(events=events):
                self.assertEqual(len(self.findings('on: ' + events + '''
permissions: write-all
''')), count)

    def test_overridden_declaration_reaches_report_triage_and_gate(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workflow = root / '.github/workflows/check.yml'
            workflow.parent.mkdir(parents=True)
            workflow.write_text('''on: pull_request
permissions: write-all
jobs:
'''
                                '''  check:
    permissions: {}
'''
                                '''    steps:
      - run: echo checking
''', encoding='utf-8')
            for threshold, expected_status in (('medium', 1), ('high', 0)):
                with self.subTest(threshold=threshold):
                    stdout, stderr = io.StringIO(), io.StringIO()
                    with mock.patch.object(scan, 'git_head', return_value=None), \
                            mock.patch.object(scan, 'http_json', side_effect=AssertionError('network')), \
                            contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                        status = scan.main(['scan.py', str(root), '--no-osv', '--triage',
                                            '--fail-on', threshold])
                    report = json.loads(stdout.getvalue())
                    self.assertEqual(status, expected_status)
                    self.assertEqual(report['summary']['config_issues'], 1)
                    self.assertEqual(len(report['findings']), 1)
                    finding = report['findings'][0]
                    self.assertEqual((finding['file'], finding['line'], finding['severity']),
                                     ('.github/workflows/check.yml', 2, 'medium'))
                    self.assertEqual(report['triage'][finding['id']]['action'], 'review')
                    self.assertEqual(report['triage_summary']['config']['needs_review'], 1)
                    self.assertEqual(bool(stderr.getvalue()), bool(expected_status))
