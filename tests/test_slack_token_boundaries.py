"""Pin Slack detector boundaries with synthetic, non-live values."""
import string
import tempfile
import unittest
from pathlib import Path

from test_scan import _collect, scan


class SlackTokenBoundaryTests(unittest.TestCase):
    body = "1234567890-AbCdEf123456"

    def findings(self, text):
        with tempfile.TemporaryDirectory() as root:
            Path(root, "settings.txt").write_text(text, encoding="utf-8")
            return _collect(root, scan.scan_secrets)

    def test_standalone_prefixes_and_contexts_preserve_metadata(self):
        for prefix in ("xoxb-", "xoxa-", "xoxp-", "xoxr-", "xoxs-"):
            value = prefix + self.body
            for template in ("{}", 'value="{}"', '{{"value":"{}"}}',
                             "Bearer {}", "({})", "[{}]", "{}.",
                             "https://invalid.example/?value={}&next=1"):
                with self.subTest(prefix=prefix, template=template):
                    hits = self.findings("heading\n" + template.format(value))
                    self.assertEqual(len(hits), 1)
                    hit = hits[0]
                    self.assertEqual(hit["summary"], "Slack token detected")
                    self.assertEqual(hit["severity"], "high")
                    self.assertEqual(hit["category"], "secret")
                    self.assertEqual(hit["file"], "settings.txt")
                    self.assertEqual(hit["line"], 2)
                    self.assertEqual(hit["evidence"], scan.redact(value))
                    self.assertNotIn(value, str(hits))

    def test_identifier_prefixes_are_not_partial_tokens(self):
        for char in string.ascii_letters + string.digits + "_-":
            with self.subTest(char=char):
                self.assertEqual(self.findings(char + "xoxb-" + self.body), [])

    def test_underscore_suffix_does_not_match_or_backtrack(self):
        for suffix in ("_", "_backup", "_123"):
            with self.subTest(suffix=suffix):
                self.assertEqual(self.findings("xoxb-" + self.body + suffix), [])

    def test_variable_length_body_is_matched_in_full(self):
        rx = next(rx for pid, rx, _, _ in scan.SECRET_PATTERNS if pid == "slack-token")
        for body in ("aB3dE6gH9j", self.body, self.body + "-More123"):
            value = "xoxb-" + body
            with self.subTest(body=body):
                self.assertEqual(rx.search('"' + value + '"').group(0), value)
                self.assertEqual(len(self.findings(value)), 1)
        self.assertEqual(self.findings("xoxb-aB3dE6gH9"), [])

    def test_standalone_value_after_embedded_candidate_is_found(self):
        value = "xoxp-" + self.body
        hits = self.findings("prefix_xoxb-" + self.body + " " + value)
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["evidence"], scan.redact(value))

    def test_masked_example_remains_low_severity(self):
        value = "xoxb-" + "x" * 24
        hits = self.findings(value)
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["severity"], "low")
        self.assertEqual(hits[0]["evidence"], scan.redact(value) + " (example-key?)")
