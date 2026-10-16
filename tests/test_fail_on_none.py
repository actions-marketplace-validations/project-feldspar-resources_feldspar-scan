"""Explicitly disabling the CLI gate preserves reports and other exit codes."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


SCANNER = Path(__file__).resolve().parents[1] / "scan.py"


class FailOnNoneTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="fds-fail-on-none-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.repo = self.root / "repo"
        self.repo.mkdir()
        (self.repo / ".env").write_text("MODE=development\n", encoding="utf-8")

    def run_scan(self, *args, target=None):
        return subprocess.run(
            [sys.executable, str(SCANNER), str(target or self.repo), "--no-osv", *args],
            cwd=self.root, capture_output=True, text=True, timeout=10)

    def test_none_preserves_default_report_with_and_without_triage(self):
        for options in ((), ("--triage",)):
            with self.subTest(options=options):
                default = self.run_scan(*options)
                disabled = self.run_scan(*options, "--fail-on", "none")
                self.assertEqual(default.returncode, 0, default.stderr)
                self.assertEqual(disabled.returncode, 0, disabled.stderr)
                self.assertEqual(disabled.stderr, "")
                expected, actual = map(json.loads, (default.stdout, disabled.stdout))
                self.assertGreater(actual["summary"]["by_severity"]["high"], 0)
                expected.pop("scanned_at")
                actual.pop("scanned_at")
                self.assertEqual(actual, expected)

    def test_none_is_case_insensitive_and_writes_json_file(self):
        output = self.root / "report.json"
        result = self.run_scan("--fail-on", "NoNe", "--json", str(output))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "")
        self.assertGreater(json.loads(output.read_text())["summary"]["config_issues"], 0)

    def test_last_gate_option_wins(self):
        for thresholds, status in ((("high", "none"), 0), (("none", "high"), 1)):
            with self.subTest(thresholds=thresholds):
                result = self.run_scan("--fail-on", thresholds[0], "--fail-on", thresholds[1])
                self.assertEqual(result.returncode, status, result.stderr)
                self.assertGreater(len(json.loads(result.stdout)["findings"]), 0)
                self.assertEqual("gate:" in result.stderr, status == 1)

    def test_existing_thresholds_still_apply(self):
        for severity, status in (("critical", 0), ("high", 1), ("medium", 1), ("low", 1)):
            with self.subTest(severity=severity):
                result = self.run_scan("--fail-on", severity)
                self.assertEqual(result.returncode, status, result.stderr)

    def test_none_does_not_suppress_argument_or_path_errors(self):
        for options in (("--fail-on", "none", "--bogus"),
                        ("--fail-on", "none", "--fail-on", "typo"),
                        ("--fail-on", "none", "--fail-on")):
            with self.subTest(options=options):
                result = self.run_scan(*options)
                self.assertEqual(result.returncode, 2)
                self.assertEqual(result.stdout, "")
        result = self.run_scan("--fail-on", "none", target=self.root / "missing")
        self.assertEqual(result.returncode, 2)
        self.assertIn("not a directory", result.stderr)


if __name__ == "__main__":
    unittest.main()
