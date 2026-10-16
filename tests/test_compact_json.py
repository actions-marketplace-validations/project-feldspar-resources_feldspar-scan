"""Compact reports preserve the offline CLI's data and exit behavior."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


SCANNER = Path(__file__).resolve().parents[1] / "scan.py"


class CompactJsonTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="fds-compact-")
        self.addCleanup(temporary.cleanup)
        self.cwd = Path(temporary.name)
        self.repo = self.cwd / "repo"
        self.repo.mkdir()
        (self.repo / "Dockerfile").write_text("FROM scratch" + chr(10), encoding="utf-8")

    def run_scan(self, *args):
        return subprocess.run(
            [sys.executable, str(SCANNER), str(self.repo), "--no-osv", *args],
            cwd=self.cwd, capture_output=True, text=True, timeout=10)

    def assert_compact(self, text):
        report = json.loads(text)
        self.assertEqual(text, json.dumps(report, separators=(",", ":")) + chr(10))
        self.assertEqual(len(text.splitlines()), 1)
        return report

    def test_stdout_preserves_report_with_and_without_triage(self):
        literal = self.cwd / "-"
        literal.write_text("untouched" + chr(10), encoding="utf-8")
        for triage in ((), ("--triage",)):
            pretty = self.run_scan(*triage)
            self.assertEqual(pretty.returncode, 0, pretty.stderr)
            expected = json.loads(pretty.stdout)
            self.assertEqual(pretty.stdout, json.dumps(expected, indent=2) + chr(10))
            expected.pop("scanned_at")
            for destination in ((), ("--json", "-")):
                with self.subTest(triage=triage, destination=destination):
                    result = self.run_scan(*triage, "--compact", *destination)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(result.stderr, "")
                    actual = self.assert_compact(result.stdout)
                    actual.pop("scanned_at")
                    self.assertEqual(actual, expected)
        self.assertEqual(literal.read_text(), "untouched" + chr(10))

    def test_named_file_preserves_report_and_diagnostics(self):
        pretty = self.run_scan("--triage")
        self.assertEqual(pretty.returncode, 0, pretty.stderr)
        expected = json.loads(pretty.stdout)
        expected.pop("scanned_at")
        for name in ("report.json", "./-"):
            with self.subTest(name=name):
                result = self.run_scan("--json", name, "--compact", "--triage")
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout, "")
                actual = self.assert_compact((self.cwd / name).read_text())
                actual.pop("scanned_at")
                self.assertEqual(actual, expected)
                self.assertIn("wrote " + name, result.stderr)

    def test_failed_gate_still_emits_complete_compact_report(self):
        for destination in ((), ("--json", "gated.json")):
            with self.subTest(destination=destination):
                result = self.run_scan("--compact", "--fail-on", "low", *destination)
                self.assertEqual(result.returncode, 1, result.stderr)
                text = ((self.cwd / "gated.json").read_text()
                        if destination else result.stdout)
                report = self.assert_compact(text)
                self.assertTrue(report["findings"])
                self.assertIn("gate: findings at or above low severity", result.stderr)

    def test_empty_scan_and_help(self):
        (self.repo / "Dockerfile").unlink()
        result = self.run_scan("--compact")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.assert_compact(result.stdout)["findings"], [])
        help_result = subprocess.run(
            [sys.executable, str(SCANNER), "--help"],
            capture_output=True, text=True, timeout=10)
        self.assertEqual(help_result.returncode, 0)
        self.assertIn("--compact", help_result.stdout)
        self.assertIn("one line", help_result.stdout)
