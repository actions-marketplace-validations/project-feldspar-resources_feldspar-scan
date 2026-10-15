"""Offline regression tests for bounded GitHub workflow heuristics."""
import json
from pathlib import Path
import tempfile
import unittest

from test_scan import _collect, _run, scan


SHA = 'a' * 40
WORKFLOW = '.github/workflows/ci.yml'


class WorkflowConfigTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = self.temp.name

    def findings(self, text, path=WORKFLOW):
        target = Path(self.root, path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text)
        return _collect(self.root, scan.scan_config)

    def workflow(self, steps, event='pull_request', permissions=''):
        return ('on: ' + event + '\n' + permissions + '\njobs:\n  build:\n'
                '    runs-on: ubuntu-latest\n    steps:\n' + steps)

    def test_remote_refs_and_exact_source_lines(self):
        for ref in ('v1', 'main', 'a' * 7, 'g' * 40, '${{ inputs.version }}'):
            with self.subTest(ref=ref):
                text = self.workflow('      - uses: "vendor/tool/subdir@' + ref + '" # tag\n')
                hits = self.findings(text)
                self.assertEqual(len(hits), 1)
                hit = hits[0]
                self.assertEqual((hit['category'], hit['severity'], hit['file']),
                                 ('config', 'low', WORKFLOW))
                self.assertIn('Unpinned', hit['summary'])
                self.assertIn('uses:', text.splitlines()[hit['line'] - 1])

    def test_sha_local_and_container_actions_are_excluded(self):
        for use in ('vendor/tool@' + SHA, 'actions/checkout@' + SHA.upper(),
                    './.github/actions/local', 'docker://alpine:3',
                    'docker://alpine@sha256:' + 'a' * 64):
            with self.subTest(use=use):
                self.assertEqual(self.findings(self.workflow('      - uses: ' + use)), [])

    def test_job_reusable_workflow_is_checked(self):
        hits = self.findings('on: push\njobs:\n  build:\n'
                             "    uses: 'vendor/repo/.github/workflows/ci.yml@main'\n")
        self.assertEqual(len(hits), 1)
        self.assertIn('Unpinned', hits[0]['summary'])

    def test_write_permissions_event_forms(self):
        for event in ('pull_request', '[push, pull_request]',
                      '\n  pull_request:\n    types: [opened]',
                      '\n  - push\n  - pull_request',
                      '{pull_request: {types: [opened]}}', "'pull_request'"):
            for perms in ('permissions: write-all',
                          'permissions:\n  contents: write',
                          'permissions: {"contents": "write", checks: read}'):
                with self.subTest(event=event, perms=perms):
                    hits = self.findings(self.workflow('      - run: true\n', event, perms))
                    self.assertEqual(len(hits), 1)
                    self.assertEqual(hits[0]['severity'], 'medium')
                    self.assertIn('write permissions', hits[0]['summary'])

    def test_job_permissions_and_quoted_keys(self):
        hits = self.findings("'on': [push, pull_request]\njobs:\n  build:\n"
                             "    'permissions':\n      'contents': 'write'\n"
                             "    steps:\n      - run: true\n")
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]['line'], 5)

    def test_read_permissions_other_events_and_nonpermission_fields(self):
        for event, perms in (('push', 'permissions: write-all'),
                             ('pull_request_target', 'permissions: write-all'),
                             ('pull_request', 'permissions: read-all'),
                             ('pull_request', 'permissions: {}'),
                             ('pull_request', 'permissions:\n  contents: read'),
                             ('pull_request', 'env:\n  contents: write')):
            with self.subTest(event=event, perms=perms):
                self.assertEqual(self.findings(self.workflow('      - run: true', event, perms)), [])

    def test_checkout_head_ref_is_scoped_to_same_step(self):
        for ref in ('${{ github.event.pull_request.head.sha }}',
                    '${{github.event.pull_request.head.ref}}', '${{ github.head_ref }}'):
            with self.subTest(ref=ref):
                steps = ('      - name: Checkout\n        with:\n          ref: "' + ref + '"\n'
                         '        uses: actions/checkout@' + SHA + '\n')
                hits = self.findings(self.workflow(steps, 'pull_request_target'))
                self.assertEqual(len(hits), 1)
                self.assertEqual(hits[0]['severity'], 'high')
                self.assertIn('PR head', hits[0]['summary'])
                self.assertEqual(hits[0]['line'], 9)

    def test_checkout_does_not_combine_unrelated_fields(self):
        examples = [
            '      - uses: actions/checkout@' + SHA + '\n'
            '      - uses: vendor/tool@' + SHA + '\n'
            '        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n',
            '      - uses: actions/checkout@' + SHA + '\n'
            '        with:\n          ref: main\n'
            '        env:\n          ref: ${{ github.event.pull_request.head.sha }}\n',
            '      - uses: actions/checkout@' + SHA + '\n'
            '        with:\n          ref: ${{ github.sha }}\n',
        ]
        for steps in examples:
            with self.subTest(steps=steps):
                self.assertEqual(self.findings(self.workflow(steps, 'pull_request_target')), [])

    def test_comments_and_block_scalars_are_not_workflow_fields(self):
        text = ('# on: pull_request_target\non: push\n'
                'env:\n  EXAMPLE: >-\n    uses: vendor/tool@main\n'
                '    permissions: write-all\njobs:\n  build:\n    steps:\n'
                '      - run: |\n          uses: vendor/tool@main\n'
                '          permissions: write-all\n'
                '          on: pull_request\n'
                '      # - uses: vendor/tool@main\n'
                '      - uses: actions/checkout@' + SHA + '\n'
                '        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n')
        self.assertEqual(self.findings(text), [])

    def test_only_workflow_files_are_checked(self):
        text = self.workflow('      - uses: vendor/tool@main\n', permissions='permissions: write-all')
        for path in ('ci.yml', '.github/actions/action.yml', '.github/workflows/notes.txt',
                     '.github/workflows/examples/ci.yml'):
            with self.subTest(path=path):
                self.assertEqual(self.findings(text, path), [])
        self.assertEqual(len(self.findings(text, '.github/workflows/ci.yaml')), 2)

    def test_cli_findings_gate_and_determinism(self):
        self.findings(self.workflow('      - uses: vendor/tool@main\n'))
        rc, stdout, stderr = _run(self.root, '--no-osv', '--fail-on', 'low')
        self.assertEqual(rc, 1, stderr)
        result = json.loads(stdout)
        self.assertEqual(result['summary']['by_severity']['low'], 1)
        again = json.loads(_run(self.root, '--no-osv', '--triage')[1])
        self.assertEqual(result['manifest_hash'], again['manifest_hash'])
        self.assertEqual(result['findings'], again['findings'])
        self.assertEqual(_run(self.root, '--no-osv', '--fail-on', 'medium')[0], 0)

    def test_checkout_high_severity_gate(self):
        self.findings(self.workflow('      - uses: actions/checkout@' + SHA + '\n'
                                   '        with:\n          ref: ${{ github.head_ref }}\n',
                                   'pull_request_target'))
        rc, stdout, stderr = _run(self.root, '--no-osv', '--fail-on', 'high')
        self.assertEqual(rc, 1, stderr)
        self.assertEqual(json.loads(stdout)['summary']['by_severity']['high'], 1)


if __name__ == '__main__':
    unittest.main()
