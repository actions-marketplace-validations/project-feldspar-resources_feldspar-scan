"""Package configuration comment handling; all credential fixtures are synthetic."""
import json
from pathlib import Path
import tempfile
import unittest

from test_scan import scan


class PackageConfigCommentTests(unittest.TestCase):
    def collect(self, name, text, scanner=None):
        findings = []

        def add(category, severity, file, line, **details):
            findings.append(dict(category=category, severity=severity, file=file,
                                 line=line, **details))

        with tempfile.TemporaryDirectory() as root:
            path = Path(root, name)
            path.write_text(text, encoding="utf-8")
            (scanner or scan.scan_config)(root, [str(path)], add)
        return findings

    def test_comment_only_entries_do_not_report_active_credentials(self):
        for name in (".npmrc", ".pypirc"):
            for marker in ("#", ";", "  #", "\t;"):
                for entry in ("//registry.invalid/:_authToken=synthetic-value",
                              "password = synthetic-value", "password: synthetic-value"):
                    with self.subTest(name=name, marker=marker, entry=entry):
                        self.assertEqual(self.collect(name, marker + " " + entry), [])

    def test_active_entries_after_comments_keep_severity_line_and_redaction(self):
        value = "synthetic-value-123456789"
        for name in (".npmrc", ".pypirc"):
            for entry in ("//registry.invalid/:_authToken=" + value,
                          "password = " + value, "password: " + value):
                for suffix in ("", " # comment", " ; comment"):
                    with self.subTest(name=name, entry=entry, suffix=suffix):
                        text = f"""# {entry}
; {entry}

  {entry}{suffix}
"""
                        findings = self.collect(name, text)
                        self.assertEqual(len(findings), 1)
                        finding = findings[0]
                        self.assertEqual(finding["category"], "config")
                        self.assertEqual(finding["severity"], "high")
                        self.assertEqual(finding["file"], name)
                        self.assertEqual(finding["line"], 4)
                        self.assertEqual(finding["summary"], "Credential committed in " + name)
                        self.assertEqual(finding["evidence"], scan.redact(entry + suffix))
                        self.assertNotIn(value, json.dumps(findings))

    def test_provider_shaped_secrets_in_comments_remain_detectable(self):
        value = "npm_" + "aB3dE6gH9jK2" * 3
        for name in (".npmrc", ".pypirc"):
            for marker in ("#", ";"):
                with self.subTest(name=name, marker=marker):
                    text = marker + " //registry.invalid/:_authToken=" + value
                    self.assertEqual(self.collect(name, text), [])
                    findings = self.collect(name, text, scan.scan_secrets)
                    self.assertEqual(len(findings), 1)
                    self.assertEqual(findings[0]["summary"], "npm access token detected")
                    self.assertEqual(findings[0]["severity"], "high")
                    self.assertEqual(findings[0]["line"], 1)
                    self.assertNotIn(value, json.dumps(findings))
