"""Placeholder context tests using synthetic credential-shaped values."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest

from test_scan import scan


TOKEN = "npm_" + "aB3dE6f9" * 4 + "aB3d"
VALUE = "A1b2C3d4E5f6G7h8"


class PlaceholderValueContextTests(unittest.TestCase):
    def report(self, text, threshold):
        with tempfile.TemporaryDirectory() as root:
            Path(root, "settings.txt").write_text(text, encoding="utf-8")
            out, err = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                code = scan.main(["scan.py", root, "--no-osv", "--triage",
                                  "--fail-on", threshold])
            return code, json.loads(out.getvalue())

    def test_closed_placeholder_does_not_downgrade_later_provider_hit(self):
        for prefix in ('placeholder="" ', "placeholder='label' ",
                       'placeholder={label} ', 'placeholder="text"; '):
            with self.subTest(prefix=prefix):
                code, report = self.report(prefix + TOKEN, "high")
                self.assertEqual(code, 1)
                self.assertEqual(len(report["findings"]), 1)
                hit = report["findings"][0]
                self.assertEqual(hit["severity"], "high")
                self.assertEqual(hit["evidence"], "npm_…")
                self.assertEqual(report["triage"][hit["id"]]["action"], "review")
                self.assertNotIn(TOKEN, json.dumps(report))

    def test_closed_placeholder_does_not_downgrade_later_generic_hit(self):
        for prefix in ('placeholder="" ', "placeholder='label' ",
                       'placeholder={label} '):
            with self.subTest(prefix=prefix):
                code, report = self.report(prefix + 'token="' + VALUE + '"', "medium")
                self.assertEqual(code, 1)
                self.assertEqual(len(report["findings"]), 1)
                hit = report["findings"][0]
                self.assertEqual(hit["severity"], "medium")
                self.assertEqual(hit["evidence"], "A1b2…")
                self.assertFalse(report["triage"][hit["id"]]["likely_false_positive"])
                self.assertNotIn(VALUE, json.dumps(report))

    def test_open_placeholder_still_hints_provider_hit(self):
        for opening, closing in (('"', '"'), ("'", "'"), ('{', '}')):
            with self.subTest(opening=opening):
                code, report = self.report('placeholder=' + opening + TOKEN + closing, "high")
                self.assertEqual(code, 0)
                hit, = report["findings"]
                self.assertEqual(hit["severity"], "low")
                self.assertEqual(hit["evidence"], "npm_… (form-placeholder?)")
                self.assertTrue(report["triage"][hit["id"]]["likely_false_positive"])

    def test_open_placeholder_still_hints_generic_hit(self):
        code, report = self.report("placeholder='token=\"" + VALUE + "\"'", "medium")
        self.assertEqual(code, 0)
        hit, = report["findings"]
        self.assertEqual(hit["severity"], "low")
        self.assertEqual(hit["evidence"], "A1b2… (form-placeholder?)")

    def test_later_open_placeholder_is_used_after_closed_one(self):
        code, report = self.report('placeholder="" placeholder="' + TOKEN + '"', "high")
        self.assertEqual(code, 0)
        hit, = report["findings"]
        self.assertEqual(hit["severity"], "low")
        self.assertEqual(hit["evidence"], "npm_… (form-placeholder?)")
