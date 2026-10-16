"""CLI JSON destinations, exercised offline with disposable directories."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


SCANNER = Path(__file__).resolve().parents[1] / "scan.py"


class JsonDestinationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="fds-json-destination-")
        self.addCleanup(temporary.cleanup)
        self.cwd = Path(temporary.name)
        self.repo = self.cwd / "repo"
        self.repo.mkdir()
        (self.repo / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")

    def run_scan(self, *args):
        return subprocess.run(
            [sys.executable, str(SCANNER), str(self.repo), "--no-osv", *args],
            cwd=self.cwd, capture_output=True, text=True, timeout=10)

    def test_dash_matches_implicit_stdout_with_and_without_triage(self):
        # A pre-existing literal '-' must not be overwritten by stdout mode.
        literal = self.cwd / "-"
        literal.write_text("keep me\n", encoding="utf-8")
        for options in ((), ("--triage",)):
            with self.subTest(options=options):
                implicit = self.run_scan(*options)
                explicit = self.run_scan(*options, "--json", "-")
                self.assertEqual(implicit.returncode, 0, implicit.stderr)
                self.assertEqual(explicit.returncode, 0, explicit.stderr)
                expected = json.loads(implicit.stdout)
                actual = json.loads(explicit.stdout)
                expected.pop("scanned_at")
                actual.pop("scanned_at")
                self.assertEqual(actual, expected)
                self.assertEqual(explicit.stderr, "")
                self.assertEqual(literal.read_text(encoding="utf-8"), "keep me\n")

    def test_dash_emits_report_when_severity_gate_fails(self):
        result = self.run_scan("--json", "-", "--fail-on", "low")
        self.assertEqual(result.returncode, 1, result.stderr)
        report = json.loads(result.stdout)
        self.assertTrue(report["findings"])
        self.assertIn("gate: findings at or above low severity", result.stderr)
        self.assertNotIn("wrote", result.stderr)
        self.assertFalse((self.cwd / "-").exists())

    def test_named_file_and_explicit_literal_dash_still_write_files(self):
        for destination in ("report.json", "./-"):
            with self.subTest(destination=destination):
                result = self.run_scan("--json", destination)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout, "")
                report = json.loads((self.cwd / destination).read_text())
                self.assertTrue(report["findings"])
                self.assertIn("wrote " + destination, result.stderr)


if __name__ == "__main__":
    unittest.main()
