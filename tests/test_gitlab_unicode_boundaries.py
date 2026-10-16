"""GitLab detector boundaries using synthetic values; no provider calls."""
import tempfile
import unittest
from pathlib import Path

from test_scan import _collect, scan


class GitLabUnicodeBoundaryTests(unittest.TestCase):
    value = "glpat-" + "aB3dE6fG9_-qR2sT5uV8"

    def findings(self, text):
        with tempfile.TemporaryDirectory() as root:
            Path(root, "settings.txt").write_text(text, encoding="utf-8")
            return _collect(root, scan.scan_secrets)

    def test_unicode_identifier_neighbors_exclude_partial_matches(self):
        for char in ("é", "密", "Ж", "١", "９"):
            for text in (char + self.value, self.value + char):
                with self.subTest(text=text):
                    self.assertEqual(self.findings(text), [])

    def test_standalone_tokens_preserve_metadata_and_redaction(self):
        for template in ("{}", 'value="{}"', "Bearer {}", "({})", "{}.", "密: {}", "{} — fin"):
            with self.subTest(template=template):
                hits = self.findings(("heading" + chr(10)) + template.format(self.value))
                self.assertEqual(len(hits), 1)
                self.assertEqual(hits[0], dict(
                    category="secret", severity="high", file="settings.txt", line=2,
                    summary="GitLab personal access token detected",
                    evidence=scan.redact(self.value)))
                self.assertNotIn(self.value, str(hits))

    def test_ascii_boundaries_and_exact_length_are_preserved(self):
        for char in ("a", "Z", "0", "_", "-"):
            for text in (char + self.value, self.value + char):
                with self.subTest(text=text):
                    self.assertEqual(self.findings(text), [])
        for size in (19, 20, 21):
            with self.subTest(size=size):
                value = "glpat-" + ("aB3dE6fG9_" * 3)[:size]
                self.assertEqual(len(self.findings(value)), int(size == 20))

    def test_later_token_and_existing_severity_hints_are_preserved(self):
        for embedded in ("密" + self.value, self.value + "é"):
            with self.subTest(embedded=embedded):
                hits = self.findings(embedded + ' value="' + self.value + '"')
                self.assertEqual(len(hits), 1)
                self.assertEqual(hits[0]["severity"], "high")
        for text, hint in (("glpat-" + "x" * 20, "example-key?"),
                           ('placeholder="' + self.value + '"', "form-placeholder?")):
            with self.subTest(hint=hint):
                hits = self.findings(text)
                self.assertEqual(len(hits), 1)
                self.assertEqual(hits[0]["severity"], "low")
                self.assertIn("(" + hint + ")", hits[0]["evidence"])
