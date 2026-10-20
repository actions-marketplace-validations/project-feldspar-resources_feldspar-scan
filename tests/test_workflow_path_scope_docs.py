"""Pin the documented scan-target-relative workflow selection boundary."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from test_scan import scan


WORKFLOW = """on: [pull_request, pull_request_target]
permissions: write-all
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
"""


class WorkflowPathScopeDocsTests(unittest.TestCase):
    def report(self, root, threshold='low'):
        with mock.patch.object(scan, 'query_osv') as query, \
                contextlib.redirect_stdout(io.StringIO()) as output, \
                contextlib.redirect_stderr(io.StringIO()):
            status = scan.main(['scan.py', str(root), '--no-osv', '--no-commit',
                                '--triage', '--fail-on', threshold])
        query.assert_not_called()
        return status, json.loads(output.getvalue())

    def write(self, root, relative, content=WORKFLOW):
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding='utf-8')

    def test_only_direct_lowercase_workflow_paths_get_all_three_checks(self):
        selected = ('.github/workflows/build.yml', '.github/workflows/build.yaml')
        excluded = (
            '.github/workflows/sub/build.yml',
            'nested/.github/workflows/build.yml',
            '.Github/workflows/build.yml', '.github/Workflows/build.yml',
            '.github/workflows/build.YML', '.github/workflows/build.YAML',
            '.github/workflows/build.yml.example', 'build.yml',
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for relative in selected + excluded:
                self.write(root, relative)
            status, report = self.report(root)
        self.assertEqual(status, 1)
        self.assertEqual(report['summary']['config_issues'], 6)
        self.assertEqual(report['summary']['secret_hits'], 0)
        self.assertEqual({f['file'] for f in report['findings']}, set(selected))
        for relative in selected:
            self.assertEqual(sorted((f['severity'], f['line'])
                                    for f in report['findings'] if f['file'] == relative),
                             [('high', 8), ('low', 6), ('medium', 2)])

    def test_changing_target_changes_workflow_selection(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.write(root, 'nested/.github/workflows/build.yml')
            for target, count in ((root, 0), (root / 'nested', 3),
                                  (root / 'nested/.github/workflows', 0)):
                with self.subTest(target=str(target)):
                    status, report = self.report(target)
                    self.assertEqual(report['summary']['config_issues'], count)
                    self.assertEqual(len(report['findings']), count)
                    self.assertEqual(status, int(count > 0))
                    self.assertEqual(report['summary']['gate']['passed'], count == 0)

    def test_unselected_workflow_still_receives_secret_scan(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            relative = 'nested/.github/workflows/build.yml'
            # Deliberately synthetic placeholder, not credential material.
            self.write(root, relative, WORKFLOW + '# password="your_placeholder_value"' + chr(10))
            status, report = self.report(root)
        self.assertEqual(status, 1)
        self.assertEqual(report['summary']['config_issues'], 0)
        self.assertEqual(report['summary']['secret_hits'], 1)
        self.assertEqual([(f['category'], f['file'], f['line']) for f in report['findings']],
                         [('secret', relative, 9)])
        self.assertFalse(report['summary']['gate']['passed'])
        self.assertTrue(all(t['likely_false_positive'] and t['action'] == 'informational'
                            for t in report['triage'].values()))
