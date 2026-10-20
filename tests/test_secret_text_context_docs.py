"""Document text-context behavior with synthetic, never usable credentials."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

_spec = importlib.util.spec_from_file_location(
    "scan_text_context_docs", Path(__file__).resolve().parents[1] / "scan.py")
scan = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(scan)

# Deliberately constructed detector fixtures, not issued credentials.
PROVIDER = "ghp_" + "A1b2C3d4E5f6" * 3
GENERIC = "A1b2C3d4E5f6G7h8"
NL = chr(10)


class SecretTextContextDocsTests(unittest.TestCase):
    def collect(self, rel, text):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root, rel)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")
            findings = []

            def add(category, severity, file, line, **details):
                findings.append(dict(category=category, severity=severity,
                                     file=file, line=line, **details))

            scan.scan_secrets(root, [str(path)], add)
            return findings

    def test_comments_literals_and_fences_preserve_provider_matches(self):
        cases = [
            ("src/code.py", "# " + PROVIDER + NL, 1),
            ("src/code.js", "// " + PROVIDER + NL, 1),
            ("src/code.js", "/* " + PROVIDER + " */" + NL, 1),
            ("src/code.py", 'text = "' + PROVIDER + '"' + NL, 1),
            ("guide.md", "```text" + NL + PROVIDER + NL + "```" + NL, 2),
            ("guide.md", "<!-- " + PROVIDER + " -->" + NL, 1),
        ]
        for rel, text, line in cases:
            with self.subTest(rel=rel, context=text[:4]):
                hits = self.collect(rel, text)
                self.assertEqual(len(hits), 1)
                hit = hits[0]
                self.assertEqual((hit["file"], hit["line"]), (rel, line))
                self.assertEqual(hit["category"], "secret")
                self.assertEqual(hit["severity"], "high")
                self.assertEqual(hit["evidence"], "ghp_…")
                self.assertNotIn(PROVIDER, json.dumps(hits))

    def test_generic_assignments_are_also_text_matches(self):
        assignment = 'api_key="' + GENERIC + '"'
        for text, line in [
            ("# " + assignment + NL, 1),
            ("// " + assignment + NL, 1),
            ("text = '" + assignment + "'" + NL, 1),
            ("```python" + NL + assignment + NL + "```" + NL, 2),
        ]:
            with self.subTest(context=text[:4]):
                hits = self.collect("guide.md", text)
                self.assertEqual(len(hits), 1)
                self.assertEqual(hits[0]["line"], line)
                self.assertEqual(hits[0]["summary"], "Hardcoded api_key assignment")
                self.assertEqual(hits[0]["severity"], "medium")
                self.assertEqual(hits[0]["evidence"], "A1b2…")
                self.assertNotIn(GENERIC, json.dumps(hits))

    def test_comment_findings_still_gate_and_use_path_triage(self):
        with tempfile.TemporaryDirectory() as root:
            for rel in ("src/code.py", "tests/code.py"):
                path = Path(root, rel)
                path.parent.mkdir(parents=True)
                path.write_text("# " + PROVIDER + NL, encoding="utf-8")
            stdout, stderr = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr), \
                    mock.patch.object(scan, "query_osv", side_effect=AssertionError("offline")):
                result = scan.main(["scan.py", root, "--no-osv", "--no-commit",
                                    "--triage", "--fail-on", "high"])
            self.assertEqual(result, 1)
            report = json.loads(stdout.getvalue())
            self.assertEqual(report["summary"]["secret_hits"], 2)
            self.assertEqual(report["summary"]["gate"], {
                "threshold": "high", "matching_findings": 2, "passed": False})
            actions = {f["file"]: report["triage"][f["id"]]["action"]
                       for f in report["findings"]}
            self.assertEqual(actions, {"src/code.py": "review", "tests/code.py": "informational"})
            self.assertNotIn(PROVIDER, stdout.getvalue() + stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
