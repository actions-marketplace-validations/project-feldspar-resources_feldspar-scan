"""Pin the documented distinction between dotenv presence and secret findings."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest

import scan


class DotenvPresenceDocumentationTests(unittest.TestCase):
    def run_scan(self, files, *options):
        with tempfile.TemporaryDirectory() as directory:
            for name, content in files.items():
                path = Path(directory) / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content, encoding="utf-8")
            stdout, stderr = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                code = scan.main(["scan.py", directory, "--no-osv", *options])
            return code, json.loads(stdout.getvalue())

    def test_empty_and_public_values_trigger_high_gate_without_secret_hits(self):
        for assignment in ("EMPTY=", "PORT=8080", "export PORT=8080"):
            for options in ((), ("--triage",)):
                with self.subTest(assignment=assignment, options=options):
                    code, doc = self.run_scan({".env": assignment + chr(10)},
                                              "--fail-on", "high", *options)
                    self.assertEqual(code, 1)
                    self.assertEqual(doc["summary"]["secret_hits"], 0)
                    self.assertEqual(doc["summary"]["config_issues"], 1)
                    self.assertEqual(doc["findings"][0]["severity"], "high")
                    self.assertEqual(doc["summary"]["gate"]["matching_findings"], 1)

    def test_only_first_assignment_per_file_is_reported_at_its_line(self):
        code, doc = self.run_scan({
            ".env": chr(10).join(("# COMMENT=ignored", "", "PORT=8080", "EMPTY=", "")),
            "nested/.env.local": chr(10).join(("# heading", "export EMPTY=", "PORT=8080", "")),
        })
        self.assertEqual(code, 0)
        self.assertEqual(doc["summary"]["secret_hits"], 0)
        self.assertEqual(doc["summary"]["config_issues"], 2)
        self.assertEqual(doc["summary"]["config_lines"], 2)
        self.assertEqual({(f["file"], f["line"], f["category"])
                          for f in doc["findings"]},
                         {(".env", 3, "config"), ("nested/.env.local", 2, "config")})

    def test_blank_comments_and_bare_names_do_not_trigger_presence_check(self):
        code, doc = self.run_scan({".env": chr(10).join(("", "# PORT=8080", "  # EMPTY=", "PORT", ""))},
                                  "--fail-on", "high")
        self.assertEqual(code, 0)
        self.assertEqual(doc["findings"], [])
        self.assertTrue(doc["summary"]["gate"]["passed"])


if __name__ == "__main__":
    unittest.main()
