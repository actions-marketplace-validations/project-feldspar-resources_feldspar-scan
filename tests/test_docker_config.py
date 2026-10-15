"""Offline Dockerfile configuration checks; all values are synthetic fixtures."""
import json
from pathlib import Path
import tempfile
import unittest

from test_scan import scan, _collect, _run


class DockerConfigTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = self.temp.name

    def findings(self, text, name='Dockerfile'):
        Path(self.root, name).write_text(text, encoding='utf-8')
        return _collect(self.root, scan.scan_config)

    def test_remote_add_forms_and_redacted_evidence(self):
        examples = [
            'ADD https://example.invalid/archive.tar /app/',
            'add --chown=app:app local.txt https://example.invalid/archive.tar /app/',
            'ADD ["https://example.invalid/archive.tar?synthetic-private-query", "/app/"]',
            'ADD --checksum=sha256:abc \\\n                https://example.invalid/archive.tar /app/',
        ]
        for instruction in examples:
            with self.subTest(instruction=instruction):
                hits = self.findings('FROM alpine:3.20\nUSER app\n' + instruction + '\n')
                self.assertEqual(len(hits), 1)
                self.assertEqual(hits[0]['line'], 3)
                self.assertEqual(hits[0]['severity'], 'low')
                self.assertIn('remote URL', hits[0]['summary'])
                self.assertNotIn('example.invalid', hits[0]['evidence'])

    def test_curl_pipe_to_shell(self):
        for command in ('curl -fsSL https://example.invalid/install | sh',
                        '/usr/bin/curl https://example.invalid/install | /bin/bash -s',
                        'echo ready && curl -s https://example.invalid/install | bash',
                        'curl -s https://example.invalid/install \\\n                          | sh'):
            with self.subTest(command=command):
                hits = self.findings('USER app\nRUN ' + command + '\n')
                self.assertEqual(len(hits), 1)
                self.assertEqual(hits[0]['line'], 2)
                self.assertEqual(hits[0]['severity'], 'medium')
                self.assertIn('curl', hits[0]['summary'])
                self.assertNotIn('example.invalid', hits[0]['evidence'])

    def test_curl_examples_and_nonexecution_are_ignored(self):
        for instruction in (
            'RUN echo "curl https://example.invalid/install | sh"',
            'RUN curl https://example.invalid/file > /tmp/file',
            'RUN curl https://example.invalid/data | jq .',
            'RUN echo curl | sh',
            'RUN curl https://example.invalid/file && echo done | sh',
            'RUN true # curl https://example.invalid/install | sh',
            'RUN ["echo", "curl https://example.invalid/install | sh"]',
            '# RUN curl https://example.invalid/install | sh',
        ):
            with self.subTest(instruction=instruction):
                self.assertEqual(self.findings('USER app\n' + instruction + '\n'), [])

    def test_secret_assignments_and_evidence(self):
        for instruction, names in (
            ('ENV API_TOKEN=synthetic-value OTHER=value DB_PASSWORD="dummy value"',
             ['API_TOKEN', 'DB_PASSWORD']),
            ('ENV secret synthetic-value', ['secret']),
            ('ARG AWS_SECRET_ACCESS_KEY=synthetic-value', ['AWS_SECRET_ACCESS_KEY']),
            ('ENV API_KEY=synthetic-value \\\n                 PRIVATE_KEY=synthetic-value', ['API_KEY', 'PRIVATE_KEY']),
        ):
            with self.subTest(instruction=instruction):
                hits = self.findings('USER app\n' + instruction + '\n')
                self.assertEqual(len(hits), len(names))
                for hit, name in zip(hits, names):
                    self.assertEqual(hit['line'], 2)
                    self.assertEqual(hit['severity'], 'high')
                    self.assertIn(name, hit['summary'])
                    self.assertEqual(hit['evidence'], name + '=…')
                self.assertNotIn('synthetic-value', json.dumps(hits))
                self.assertNotIn('dummy value', json.dumps(hits))

    def test_empty_unset_referenced_and_nonsecret_names(self):
        text = ('USER app\nARG API_TOKEN\nARG API_TOKEN=\nENV PASSWORD=""\n'
                'ENV TOKEN=$TOKEN API_KEY=${API_KEY}\n'
                'ENV SECRET_FILE=/run/secrets/key TOKENIZER=word PUBLIC_KEY=abc\n'
                '# ENV PASSWORD=synthetic-value\n')
        self.assertEqual(self.findings(text), [])

    def test_latest_explicit_default_and_stages(self):
        text = ('FROM --platform=$BUILDPLATFORM alpine:latest AS build\n'
                'FROM registry.example.invalid:5000/team/image\n'
                'FROM build AS final\nUSER app\n')
        hits = self.findings(text)
        self.assertEqual([h['line'] for h in hits], [1, 2])
        self.assertTrue(all(h['severity'] == 'low' for h in hits))
        self.assertTrue(all('latest' in h['summary'] for h in hits))

    def test_pinned_scratch_variables_and_local_add_are_ignored(self):
        text = ('FROM alpine:3.20 AS build\n'
                'FROM alpine:latest@sha256:' + 'a' * 64 + '\n'
                'FROM scratch\nFROM ${BASE_IMAGE}\nFROM build\nUSER app\n'
                'ADD local.tar /app/\nADD ["local.tar", "/app/"]\n'
                '# FROM alpine:latest\nCOPY https://example.invalid/file /app/\n')
        self.assertEqual(self.findings(text), [])

    def test_heredoc_body_is_not_parsed_as_instructions(self):
        text = ('FROM alpine:3.20\nUSER app\nCOPY <<EOF /app/example\n'
                'FROM alpine:latest\nENV PASSWORD=synthetic-value\n'
                'RUN curl https://example.invalid/install | sh\nEOF\n'
                'FROM alpine:latest\nUSER app\n')
        hits = self.findings(text)
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]['line'], 8)

    def test_suffix_continuation_comments_and_source_line(self):
        hits = self.findings('USER app\nENV API_TOKEN=synthetic-value \\\n'
                             '# ignored comment\n    OTHER=value\n', 'Dockerfile.dev')
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]['file'], 'Dockerfile.dev')
        self.assertEqual(hits[0]['line'], 2)

    def test_non_dockerfile_and_malformed_input(self):
        self.assertEqual(self.findings('FROM alpine:latest\nENV PASSWORD=abc\n', 'notes.txt'), [])
        hits = self.findings('USER app\nENV PASSWORD="unterminated\nADD [broken\nFROM\n')
        self.assertEqual(hits, [])

    def test_escape_directive_and_heredoc_tab_delimiter(self):
        text = ('# escape=`\nUSER app\nENV API_TOKEN=synthetic-value `\n'
                '    DB_PASSWORD=synthetic-value\nCOPY <<-EOF /example\n'
                '\tFROM alpine:latest\n\tEOF\nFROM alpine:latest\nUSER app\n')
        hits = self.findings(text)
        self.assertEqual([hit['line'] for hit in hits], [3, 3, 8])

    def test_missing_user_does_not_count_heredoc_or_comments(self):
        hits = self.findings('FROM alpine:3.20\n# USER app\nCOPY <<EOF /example\nUSER app\nEOF\n')
        self.assertEqual(len(hits), 1)
        self.assertIn('no USER', hits[0]['summary'])

    def test_secret_reference_with_default_is_still_reported(self):
        hits = self.findings('USER app\nENV API_TOKEN=${TOKEN:-synthetic-value}\n')
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]['evidence'], 'API_TOKEN=…')

    def test_cli_gate_determinism_and_redaction(self):
        self.findings('FROM alpine:3.20\nUSER app\nENV API_TOKEN=synthetic-value\n')
        rc, stdout, stderr = _run(self.root, '--no-osv', '--fail-on', 'high')
        self.assertEqual(rc, 1, stderr)
        data = json.loads(stdout)
        self.assertEqual(data['summary']['by_severity']['high'], 1)
        self.assertNotIn('synthetic-value', stdout)
        again = json.loads(_run(self.root, '--no-osv', '--triage')[1])
        self.assertEqual(data['findings'], again['findings'])
        self.assertEqual(data['manifest_hash'], again['manifest_hash'])
        self.assertEqual(_run(self.root, '--no-osv', '--fail-on', 'critical')[0], 0)


if __name__ == '__main__':
    unittest.main()
