"""Pin the documented lexical scope without running shell commands or URLs."""
import json
from pathlib import Path
import tempfile
import unittest

from test_scan import scan, _collect, _run


class DockerPipelineScopeDocsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = self.temp.name

    def write(self, command):
        Path(self.root, 'Dockerfile').write_text(
            chr(10).join(('FROM scratch', 'USER app', 'RUN ' + command, '')), encoding='utf-8')

    def test_basename_separators_and_quoted_pipe_match(self):
        for command in (
            'curl https://example.invalid/script | sh',
            '/usr/bin/curl https://example.invalid/script | /bin/bash',
            'echo ready; curl example.invalid | sh',
            'true && curl example.invalid | bash',
            'false || curl example.invalid | sh',
            "curl '|' sh",
            'curl example.invalid | sh; curl example.invalid | bash',
        ):
            with self.subTest(command=command):
                self.write(command)
                hits = _collect(self.root, scan.scan_config)
                self.assertEqual(len(hits), 1)
                self.assertEqual(hits[0]['summary'],
                                 'Dockerfile RUN pipes curl output to a shell')
                self.assertEqual(hits[0]['severity'], 'medium')
                self.assertEqual(hits[0]['line'], 3)
                self.assertEqual(hits[0]['evidence'], 'curl | shell')

    def test_wrappers_assignments_indirect_and_exec_forms_do_not_match(self):
        for command in (
            'env curl example.invalid | sh',
            'sudo curl example.invalid | sh',
            'MODE=fixture curl example.invalid | sh',
            'curl example.invalid | env sh',
            'curl example.invalid | cat | sh',
            'curl example.invalid |& bash',
            'curl example.invalid | zsh',
            'echo "curl example.invalid | sh"',
            '["sh", "-c", "curl example.invalid | sh"]',
        ):
            with self.subTest(command=command):
                self.write(command)
                self.assertEqual(_collect(self.root, scan.scan_config), [])

    def test_continuation_line_gates_and_triage(self):
        self.write('curl https://example.invalid/script ' + chr(92) + chr(10) + ' | sh')
        status, output, _ = _run(self.root, '--no-osv', '--fail-on', 'medium')
        plain = json.loads(output)
        self.assertEqual(status, 1)
        self.assertEqual(len(plain['findings']), 1)
        self.assertEqual(plain['findings'][0]['line'], 3)
        status, output, _ = _run(self.root, '--no-osv', '--fail-on', 'medium', '--triage')
        triaged = json.loads(output)
        self.assertEqual(status, 1)
        for field in ('findings', 'manifest_hash', 'summary'):
            self.assertEqual(triaged[field], plain[field])
        self.assertEqual(triaged['triage_summary']['config']['needs_review'], 1)
        self.assertEqual(_run(self.root, '--no-osv', '--fail-on', 'high')[0], 0)
