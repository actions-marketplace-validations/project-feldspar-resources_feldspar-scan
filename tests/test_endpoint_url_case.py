"""Generic endpoint exclusions use synthetic URLs and never make requests."""
import contextlib
import io
import tempfile
import unittest
from pathlib import Path

from test_scan import _collect, scan


class EndpointURLCaseTests(unittest.TestCase):
    literal = 'aB3dE6fG9hJ2kL5mN8pQ'

    def findings(self, text):
        with tempfile.TemporaryDirectory() as root:
            Path(root, 'settings.txt').write_text(text, encoding='utf-8')
            return _collect(root, scan.scan_secrets)

    def test_supported_scheme_case_variants_are_not_generic_secrets(self):
        for scheme in ('http', 'https', 'ws', 'wss',
                       'HTTP', 'HTTPS', 'WS', 'WSS',
                       'hTtP', 'HtTpS', 'wS', 'WsS'):
            for name in ('api_key', 'secret', 'password', 'passwd', 'token'):
                with self.subTest(scheme=scheme, name=name):
                    self.assertEqual(self.findings(
                        f'{name} = "{scheme}://service.invalid/endpoint"'), [])

    def test_later_literal_on_same_line_preserves_metadata_and_redaction(self):
        hits = self.findings(
            'heading' + chr(10) + 'token = "HTTPS://service.invalid/endpoint"; '
            f'password = "{self.literal}"')
        self.assertEqual(hits, [{
            'category': 'secret', 'severity': 'medium',
            'file': 'settings.txt', 'line': 2,
            'summary': 'Hardcoded password assignment',
            'evidence': scan.redact(self.literal),
        }])
        self.assertNotIn(self.literal, str(hits))

    def test_literal_and_unsupported_url_shapes_still_report(self):
        for value in (self.literal, 'ftp://service.invalid/endpoint',
                      'prefixHTTPS://service.invalid/endpoint',
                      'HTTPS:/service.invalid/endpoint'):
            with self.subTest(value=value):
                hits = self.findings(f'token = "{value}"')
                self.assertEqual(len(hits), 1)
                self.assertEqual(hits[0]['summary'], 'Hardcoded token assignment')
                self.assertEqual(hits[0]['severity'], 'medium')
                self.assertEqual(hits[0]['evidence'], scan.redact(value))

    def test_provider_pattern_inside_url_still_reports(self):
        value = 'ghp_' + ('aB3dE6fG9' * 4)
        hits = self.findings(f'token = "HTTPS://service.invalid/?key={value}"')
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]['summary'], 'GitHub token detected')
        self.assertEqual(hits[0]['severity'], 'high')
        self.assertEqual(hits[0]['evidence'], scan.redact(value))
        self.assertNotIn(value, str(hits))

    def test_help_explains_scope_of_url_exclusion(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(scan.main(['scan.py', '--help']), 0)
        help_text = output.getvalue()
        self.assertIn('http://, https://, ws:// or wss://', help_text)
        self.assertIn('(case-insensitive)', help_text)
        self.assertIn('provider-token patterns inside URLs still report', help_text)
