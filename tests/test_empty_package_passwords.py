"""Blank package passwords are not credentials; all values are synthetic."""
import json
from pathlib import Path
import tempfile
import unittest

from test_scan import _collect, scan


class EmptyPackagePasswordTests(unittest.TestCase):
    def findings(self, name, text):
        with tempfile.TemporaryDirectory() as root:
            Path(root, name).write_text(text, encoding="utf-8")
            return _collect(root, scan.scan_config)

    def test_empty_passwords_are_not_credentials(self):
        for name in (".npmrc", ".pypirc"):
            for key in ("password", "PASSWORD", "Password"):
                for delimiter in ("=", ":"):
                    for whitespace in ("", " ", "\t "):
                        with self.subTest(name=name, key=key, delimiter=delimiter,
                                          whitespace=whitespace):
                            self.assertEqual(self.findings(
                                name, "  " + key + " " + delimiter + whitespace), [])

    def test_later_credentials_keep_location_severity_and_redaction(self):
        value = "synthetic-value-123456789"
        for name in (".npmrc", ".pypirc"):
            for entry in ("password = " + value, "PASSWORD: " + value,
                          "//registry.invalid/:_authToken=" + value):
                with self.subTest(name=name, entry=entry):
                    text = chr(10).join(("password=", "password:\t", entry))
                    hits = self.findings(name, text)
                    self.assertEqual(len(hits), 1)
                    hit = hits[0]
                    self.assertEqual(hit["line"], 3)
                    self.assertEqual(hit["file"], name)
                    self.assertEqual(hit["category"], "config")
                    self.assertEqual(hit["severity"], "high")
                    self.assertEqual(hit["summary"], "Credential committed in " + name)
                    self.assertEqual(hit["evidence"], scan.redact(entry))
                    self.assertNotIn(value, json.dumps(hits))

    def test_nonempty_values_are_preserved_conservatively(self):
        for name in (".npmrc", ".pypirc"):
            for delimiter in ("=", ":"):
                for value in ("synthetic123", "0", "''", '""', "# comment",
                              "; comment", "${PACKAGE_PASSWORD}"):
                    with self.subTest(name=name, delimiter=delimiter, value=value):
                        self.assertEqual(len(self.findings(
                            name, "password" + delimiter + " " + value)), 1)

    def test_unrelated_auth_token_detection_is_unchanged(self):
        for name in (".npmrc", ".pypirc"):
            with self.subTest(name=name):
                hits = self.findings(name, "_authToken=")
                self.assertEqual(len(hits), 1)
                self.assertEqual(hits[0]["severity"], "high")
