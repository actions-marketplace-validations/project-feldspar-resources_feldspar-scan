"""Pin the documented filename-based secret coverage limit, offline."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


SCANNER = Path(__file__).resolve().parents[1] / "scan.py"
# Synthetic values, never issued by a credential provider.
VALUE = "Synthetic7Credential9Value"
TOKEN = "ghp_" + "Ab3d" * 9
CONTENT = '''const password = "%s";
const credential = "%s";
''' % (VALUE, TOKEN)
COMPACT_CONTENT = "".join(CONTENT.splitlines())


class MinifiedFilenameTests(unittest.TestCase):
    def scan_file(self, filename, content):
        with tempfile.TemporaryDirectory(prefix="fds-minified-name-") as root:
            Path(root, filename).write_text(content, encoding="utf-8")
            result = subprocess.run(
                [sys.executable, str(SCANNER), root, "--no-osv",
                 "--fail-on", "medium"],
                capture_output=True, text=True, timeout=10)
        self.assertIn(result.returncode, (0, 1), result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report["summary"]["files_scanned"], 1)
        self.assertEqual(report["summary"]["truncated"],
                         {"files": False, "findings": False})
        self.assertNotIn(VALUE, result.stdout)
        self.assertNotIn(TOKEN, result.stdout)
        return result, report

    def test_exact_suffix_skips_readable_and_compact_content(self):
        for filename in ("bundle.min.js", ".min.js"):
            for content in (CONTENT, COMPACT_CONTENT):
                with self.subTest(filename=filename, content=content):
                    result, report = self.scan_file(filename, content)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(result.stderr, "")
                    self.assertEqual(report["findings"], [])
                    self.assertEqual(report["summary"]["secret_hits"], 0)

    def test_similar_names_and_compact_plain_js_remain_scanned(self):
        for filename in ("bundle.js", "bundle.MIN.JS", "bundle.Min.js",
                         "bundle.min.JS", "bundle.min.js.map", "bundle.min.jsx"):
            with self.subTest(filename=filename):
                result, report = self.scan_file(filename, COMPACT_CONTENT)
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertIn("gate: findings at or above medium severity", result.stderr)
                self.assertEqual(report["summary"]["secret_hits"], 2)
                self.assertEqual(
                    [(f["category"], f["severity"], f["file"], f["line"], f["evidence"])
                     for f in report["findings"]],
                    [("secret", "high", filename, 1, "ghp_…"),
                     ("secret", "medium", filename, 1, "Synt…")])


if __name__ == "__main__":
    unittest.main()
