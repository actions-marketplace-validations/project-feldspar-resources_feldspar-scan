"""Documented decoding coverage, using synthetic tokens and offline scans."""
import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from test_scan import scan


class TextEncodingCoverageTests(unittest.TestCase):
    token = "ghp_" + "aB3dE6" * 6

    def report(self, raw):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root, "settings.txt")
            path.write_bytes(raw)
            decoded = scan.read_text(path)
            stdout, stderr = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                rc = scan.main(["scan.py", root, "--no-osv", "--fail-on", "high"])
            return decoded, rc, json.loads(stdout.getvalue())

    def test_utf8_and_latin1_keep_ascii_token_detection(self):
        text = "caf\u00e9" + chr(10) + self.token + chr(10)
        for encoding in ("utf-8", "latin-1"):
            with self.subTest(encoding=encoding):
                decoded, rc, doc = self.report(text.encode(encoding))
                self.assertEqual(decoded, text)
                self.assertEqual(rc, 1)
                self.assertEqual(doc["summary"]["files_scanned"], 1)
                self.assertEqual(doc["summary"]["secret_hits"], 1)
                hit, = doc["findings"]
                self.assertEqual(hit["summary"], "GitHub token detected")
                self.assertEqual(hit["severity"], "high")
                self.assertEqual(hit["file"], "settings.txt")
                self.assertEqual(hit["line"], 2)
                self.assertEqual(hit["evidence"], "ghp_\u2026")
                self.assertNotIn(self.token, json.dumps(doc))

    def test_nul_anywhere_skips_whole_file_including_prior_token(self):
        value = self.token.encode("ascii")
        for raw in (bytes((0, 10)) + value, value + bytes((10, 0))):
            with self.subTest(raw=raw):
                decoded, rc, doc = self.report(raw)
                self.assertIsNone(decoded)
                self.assertEqual(rc, 0)
                self.assertEqual(doc["summary"]["files_scanned"], 1)
                self.assertEqual(doc["summary"]["secret_hits"], 0)
                self.assertEqual(doc["findings"], [])

    def test_utf16_and_utf32_are_not_transcoded(self):
        for encoding in ("utf-16", "utf-16-le", "utf-16-be",
                         "utf-32", "utf-32-le", "utf-32-be"):
            with self.subTest(encoding=encoding):
                raw = self.token.encode(encoding)
                self.assertIn(b"\x00", raw)
                decoded, rc, doc = self.report(raw)
                self.assertIsNone(decoded)
                self.assertEqual(rc, 0)
                self.assertEqual(doc["summary"]["files_scanned"], 1)
                self.assertEqual(doc["summary"]["secret_hits"], 0)
                self.assertEqual(doc["findings"], [])
