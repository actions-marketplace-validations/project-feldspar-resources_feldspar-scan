"""Cross-bundle npm guard coverage; values are synthetic and tests are offline."""
import tempfile
import unittest
from pathlib import Path
from test_scan import _collect, scan


class NpmConsolidationTests(unittest.TestCase):
    def findings(self, text, name=".npmrc"):
        with tempfile.TemporaryDirectory() as root:
            Path(root, name).write_text(text, encoding="utf-8")
            return _collect(root, scan.scan_config)

    def test_spaced_references_keep_shipped_npm_guard_and_later_literal(self):
        for key in ("_authToken", "//registry.invalid:4873/team/:_authToken"):
            for space in (" ", "\t", " \t "):
                with self.subTest(key=key, space=space):
                    ref = key + space + "= ${NPM_TOKEN}"
                    self.assertEqual(self.findings(ref), [])
                    hits = self.findings(ref + chr(10) + "password = synthetic-value-12345")
                    self.assertEqual(len(hits), 1)
                    self.assertEqual(hits[0]["line"], 2)
                    self.assertEqual(hits[0]["severity"], "high")
                    self.assertEqual(len(self.findings(ref, ".pypirc")), 1)
                    self.assertEqual(len(self.findings(ref + "-literal")), 1)

    def test_spaced_tokens_keep_blank_password_guard_and_first_hit(self):
        for name in (".npmrc", ".pypirc"):
            with self.subTest(name=name):
                text = "password = " + chr(10) + "_authToken = synthetic-value-12345"
                hits = self.findings(text, name)
                self.assertEqual(len(hits), 1)
                self.assertEqual(hits[0]["line"], 2)
                self.assertEqual(hits[0]["severity"], "high")
                self.assertEqual(hits, self.findings(text + chr(10) + text, name))

    def test_npmrc_markers_are_anchored_while_pypirc_substring_is_preserved(self):
        for name in (".npmrc", ".pypirc"):
            for prefix in ("other_authToken", "message=_authToken", "registry=x # _authToken"):
                with self.subTest(name=name, prefix=prefix):
                    value = "synthetic-value-12345"
                    self.assertEqual(len(self.findings(prefix + "=" + value, name)), 0 if name == ".npmrc" else 1)
                    self.assertEqual(self.findings(prefix + " = " + value, name), [])
                    hits = self.findings(prefix + " = " + value + chr(10)
                                         + "_authToken = " + value, name)
                    self.assertEqual(len(hits), 1)
                    self.assertEqual(hits[0]["line"], 2)
