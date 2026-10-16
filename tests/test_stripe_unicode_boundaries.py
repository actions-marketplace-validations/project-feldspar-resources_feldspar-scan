"""Stripe boundary regressions; all token-shaped values are synthetic."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest

from test_scan import _collect, scan


TOKENS = [("sk_live_" + "aB3dE6fG9" * 4, "Stripe live secret key detected", "critical"),
          ("rk_live_" + "aB3dE6fG9" * 4, "Stripe live restricted key detected", "high")]


class StripeUnicodeBoundaryTests(unittest.TestCase):
    def findings(self, text):
        with tempfile.TemporaryDirectory() as root:
            Path(root, "settings.txt").write_text(text, encoding="utf-8")
            return _collect(root, scan.scan_secrets)

    def test_unicode_word_neighbors_reject_embedded_fragments(self):
        for value, _, severity in TOKENS:
            for char in ("é", "Ω", "中", "١", "²", "９"):
                for text in (char + value, value + char, char + value + char):
                    with self.subTest(prefix=value[:4], char=char, text_length=len(text)):
                        self.assertEqual(self.findings(text), [])

    def test_unicode_punctuation_and_whitespace_preserve_standalone_hits(self):
        for value, summary, severity in TOKENS:
            for left, right in (("“", "”"), ("—", "。"), ("\u00a0", "\u2003")):
                with self.subTest(prefix=value[:4], left=left):
                    hit, = self.findings("heading" + chr(10) + left + value + right)
                    self.assertEqual(hit["summary"], summary)
                    self.assertEqual(hit["category"], "secret")
                    self.assertEqual(hit["severity"], severity)
                    self.assertEqual(hit["file"], "settings.txt")
                    self.assertEqual(hit["line"], 2)
                    self.assertEqual(hit["evidence"], scan.redact(value))
                    self.assertNotIn(value, json.dumps(hit))

    def test_later_standalone_token_and_mask_hints_are_preserved(self):
        for value, summary, severity in TOKENS:
            with self.subTest(summary=summary, prefix=value[:4]):
                hit, = self.findings("é" + value + " " + value + "中 " + value)
                self.assertEqual(hit["summary"], summary)
                self.assertEqual(hit["severity"], severity)
                self.assertEqual(hit["evidence"], scan.redact(value))
        for value in ("sk_live_" + "x" * 24, "rk_live_" + "x" * 24):
            hit, = self.findings("“" + value + "”")
            self.assertEqual(hit["severity"], "low")
            self.assertIn("(example-key?)", hit["evidence"])

    def test_cli_gate_and_triage_follow_retained_standalone_hit(self):
        for value, _, severity in TOKENS:
            with self.subTest(prefix=value[:4]), tempfile.TemporaryDirectory() as root:
                path = Path(root, "settings.txt")
                for suffix, expected_status, expected_count in (("", 0, 0), (" " + value, 1, 1)):
                    path.write_text("é" + value + " " + value + "中" + suffix, encoding="utf-8")
                    out, err = io.StringIO(), io.StringIO()
                    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                        status = scan.main(["scan.py", root, "--no-osv", "--triage",
                                            "--fail-on", "high"])
                    report = json.loads(out.getvalue())
                    self.assertEqual(status, expected_status)
                    self.assertEqual(len(report["findings"]), expected_count)
                    self.assertEqual(report["summary"]["secret_hits"], expected_count)
                    self.assertEqual(report["triage_summary"]["secrets"]["needs_review"], expected_count)
                    if expected_count:
                        hit, = report["findings"]
                        self.assertEqual(report["triage"][hit["id"]]["action"], "review")
                    self.assertNotIn(value, out.getvalue())
