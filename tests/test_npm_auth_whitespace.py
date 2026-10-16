"""Horizontal spacing in package config; only synthetic credential values."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from test_scan import scan


class PackageAuthWhitespaceTests(unittest.TestCase):
    value = "synthetic-package-value-123456789"

    def collect(self, name, text):
        findings = []

        def add(category, severity, file, line, **details):
            findings.append(dict(category=category, severity=severity, file=file,
                                 line=line, **details))

        with tempfile.TemporaryDirectory() as root:
            path = Path(root, name)
            path.write_text(text, encoding="utf-8")
            scan.scan_config(root, [str(path)], add)
        return findings

    def test_horizontal_spacing_preserves_metadata_and_redaction(self):
        for name in (".npmrc", ".pypirc"):
            for key in ("_authToken", "//registry.invalid/:_authToken"):
                for space in ("", " ", "\t", " \t "):
                    with self.subTest(name=name, key=key, space=space):
                        entry = key + space + "= " + self.value
                        hits = self.collect(name, "# config\x0a\x0a  " + entry + "\x0a")
                        self.assertEqual(len(hits), 1)
                        self.assertEqual(hits[0], dict(
                            category="config", severity="high", file=name, line=3,
                            summary="Credential committed in " + name,
                            evidence=scan.redact(entry)))
                        self.assertNotIn(self.value, json.dumps(hits))

    def test_comments_stay_ignored_and_later_assignment_is_found(self):
        for name in (".npmrc", ".pypirc"):
            text = ("  # _authToken = " + self.value + "\x0a"
                    "\t; _authToken\t= " + self.value + "\x0a")
            self.assertEqual(self.collect(name, text), [])
            hits = self.collect(name, text + "_authToken = " + self.value + "\x0a"
                                "password = another-synthetic-value\x0a")
            self.assertEqual(len(hits), 1)
            self.assertEqual(hits[0]["line"], 3)

    def test_spacing_does_not_expand_other_syntax_or_filenames(self):
        for text in ("_authToken: " + self.value,
                     "_authtoken = " + self.value,
                     "_authToken\x0a= " + self.value,
                     "_authToken\v= " + self.value,
                     "_authToken suffix = " + self.value):
            with self.subTest(text=text):
                self.assertEqual(self.collect(".npmrc", text), [])
        self.assertEqual(self.collect("notes.txt", "_authToken = " + self.value), [])

    def test_offline_cli_reports_and_gates_spaced_assignment(self):
        with tempfile.TemporaryDirectory() as root:
            Path(root, ".npmrc").write_text(
                "//registry.invalid/:_authToken\t = " + self.value + "\x0a",
                encoding="utf-8")
            stdout, stderr = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr), \
                    mock.patch.object(scan, "query_osv") as query:
                status = scan.main(["scan.py", root, "--no-osv", "--triage",
                                    "--fail-on", "high"])
            query.assert_not_called()
            self.assertEqual(status, 1)
            doc = json.loads(stdout.getvalue())
            self.assertEqual(doc["summary"]["config_issues"], 1)
            self.assertEqual(doc["summary"]["secret_hits"], 0)
            self.assertEqual(doc["findings"][0]["file"], ".npmrc")
            self.assertEqual(doc["findings"][0]["line"], 1)
            self.assertIn("gate: findings at or above high severity", stderr.getvalue())
            self.assertNotIn(self.value, stdout.getvalue())
