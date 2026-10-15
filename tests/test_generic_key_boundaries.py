"""Generic assignment-name boundaries; all values are synthetic, never live."""
import string
import tempfile
import unittest
from pathlib import Path

from test_scan import _collect, scan


class GenericKeyBoundaryTests(unittest.TestCase):
    value = "Ab3Cd6Ef9Gh2Jk5M"

    def findings(self, text):
        with tempfile.TemporaryDirectory() as root:
            Path(root, "settings.txt").write_text(text, encoding="utf-8")
            return _collect(root, scan.scan_secrets)

    def test_exact_and_separated_names_keep_metadata_and_redaction(self):
        for name in ("api_key", "API-KEY", "apikey", "secret", "password",
                     "passwd", "token", "DB_PASSWORD", "access_token", "app-secret"):
            for separator in ("=", ":"):
                with self.subTest(name=name, separator=separator):
                    hits = self.findings(f'heading\n{name} {separator} "{self.value}"')
                    self.assertEqual(len(hits), 1)
                    hit = hits[0]
                    self.assertEqual(hit["category"], "secret")
                    self.assertEqual(hit["severity"], "medium")
                    self.assertEqual(hit["file"], "settings.txt")
                    self.assertEqual(hit["line"], 2)
                    self.assertEqual(hit["evidence"], scan.redact(self.value))
                    self.assertNotIn(self.value, str(hits))

    def test_alphanumeric_prefixes_do_not_make_secret_names(self):
        for char in string.ascii_letters + string.digits:
            for name in ("api_key", "api-key", "apikey", "secret", "password", "passwd", "token"):
                with self.subTest(char=char, name=name):
                    self.assertEqual(self.findings(f'{char}{name}="{self.value}"'), [])

    def test_longer_nonsecret_names_are_not_suffix_matches(self):
        for name in ("notsecret", "mytoken", "resetpassword", "notpasswd", "myapikey"):
            with self.subTest(name=name):
                self.assertEqual(self.findings(f'{name}="{self.value}"'), [])

    def test_valid_assignment_after_rejected_suffix_is_found(self):
        hits = self.findings(f'notsecret="{self.value}"; token="{self.value}"')
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["summary"], "Hardcoded token assignment")

    def test_existing_placeholder_hint_is_preserved(self):
        hits = self.findings('access_token="your_placeholder_value"')
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["severity"], "low")
        self.assertIn("(placeholder?)", hits[0]["evidence"])
