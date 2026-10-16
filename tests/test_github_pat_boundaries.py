"""Fine-grained PAT heuristic boundaries, using synthetic non-live values."""
import string
import tempfile
import unittest
from pathlib import Path

from test_scan import _collect, scan


class GitHubPatBoundaryTests(unittest.TestCase):
    value = 'github_pat_' + 'aB3_dE6fG9' * 8

    def findings(self, text):
        with tempfile.TemporaryDirectory() as root:
            Path(root, 'settings.txt').write_text(text, encoding='utf-8')
            return _collect(root, scan.scan_secrets)

    def test_standalone_contexts_preserve_metadata_and_redaction(self):
        for template in ('{}', 'value="{}"', "value='{}'", 'Bearer {}',
                         '({})', '[{}]', '{}.', '/{}', '-{}'):
            with self.subTest(template=template):
                hits = self.findings('heading\n' + template.format(self.value))
                self.assertEqual(len(hits), 1)
                hit = hits[0]
                self.assertEqual(hit['category'], 'secret')
                self.assertEqual(hit['summary'], 'GitHub fine-grained PAT detected')
                self.assertEqual(hit['severity'], 'high')
                self.assertEqual(hit['file'], 'settings.txt')
                self.assertEqual(hit['line'], 2)
                self.assertEqual(hit['evidence'], 'gith…')
                self.assertNotIn(self.value, str(hits))

    def test_identifier_prefixes_are_not_partial_tokens(self):
        for char in string.ascii_letters + string.digits + '_':
            with self.subTest(char=char):
                self.assertEqual(self.findings(char + self.value), [])

    def test_existing_minimum_and_variable_length_are_preserved(self):
        for suffix in ('aB3_dE6fG9' * 8, 'aB3_dE6fG9' * 10 + '_'):
            with self.subTest(length=len(suffix)):
                self.assertEqual(len(self.findings('github_pat_' + suffix)), 1)
        self.assertEqual(self.findings(self.value[:-1]), [])
        self.assertEqual(self.findings(self.value[:40] + '\n' + self.value[40:]), [])

    def test_standalone_token_after_embedded_candidate_is_found(self):
        hits = self.findings('prefix_' + self.value + ' ' + self.value)
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]['severity'], 'high')
        self.assertEqual(hits[0]['evidence'], 'gith…')

    def test_example_and_form_hints_are_preserved(self):
        for text, hint in (('github_pat_' + 'x' * 80, 'example-key?'),
                           ('placeholder="' + self.value + '"', 'form-placeholder?')):
            with self.subTest(hint=hint):
                hits = self.findings(text)
                self.assertEqual(len(hits), 1)
                self.assertEqual(hits[0]['severity'], 'low')
                self.assertEqual(hits[0]['evidence'], 'gith… (' + hint + ')')
