"""Inline JSON destinations preserve the existing output contract, offline."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


SCANNER = Path(__file__).resolve().parents[1] / "scan.py"


class JsonEqualsTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="fds-json-equals-")
        self.addCleanup(temporary.cleanup)
        self.cwd = Path(temporary.name)
        self.repo = self.cwd / "repo"
        self.repo.mkdir()
        (self.repo / "Dockerfile").write_text("FROM scratch" + chr(10), encoding="utf-8")

    def run_scan(self, *args):
        return subprocess.run(
            [sys.executable, str(SCANNER), str(self.repo), "--no-osv", *args],
            cwd=self.cwd, capture_output=True, text=True, timeout=10)

    def report(self, text):
        report = json.loads(text)
        report.pop("scanned_at")
        return report

    def test_stdout_equivalence_including_format_triage_and_gate(self):
        (self.cwd / "-").write_text("unchanged", encoding="utf-8")
        for options in ((), ("--compact", "--triage", "--fail-on", "low")):
            with self.subTest(options=options):
                expected = self.run_scan("--json", "-", *options)
                actual = self.run_scan("--json=-", *options)
                self.assertEqual(actual.returncode, 1 if options else 0, actual.stderr)
                self.assertEqual(actual.stderr, expected.stderr)
                self.assertEqual(self.report(actual.stdout), self.report(expected.stdout))
                self.assertEqual(len(actual.stdout.splitlines()), len(expected.stdout.splitlines()))
        self.assertEqual((self.cwd / "-").read_text(), "unchanged")

    def test_file_destinations_preserve_spaces_equals_and_leading_dash(self):
        expected = self.report(self.run_scan().stdout)
        for name in ("report.json", "report space=a=b.json", "--report.json", "./-"):
            with self.subTest(name=name):
                actual = self.run_scan("--json=" + name)
                self.assertEqual(actual.returncode, 0, actual.stderr)
                self.assertEqual(actual.stdout, "")
                self.assertIn("wrote " + name, actual.stderr)
                self.assertEqual(self.report((self.cwd / name).read_text()), expected)

    def test_last_destination_wins_across_both_forms(self):
        for options in (("--json=unused.json", "--json", "-"),
                        ("--json", "unused.json", "--json=-")):
            with self.subTest(options=options):
                actual = self.run_scan(*options)
                self.assertEqual(actual.returncode, 0, actual.stderr)
                self.assertTrue(self.report(actual.stdout)["findings"])
                self.assertFalse((self.cwd / "unused.json").exists())

    def test_empty_inline_path_rejected_before_any_scan_or_clone(self):
        spec = importlib.util.spec_from_file_location("json_equals_scan", SCANNER)
        scan = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(scan)
        for target in (str(self.repo), "https://example.invalid/repo.git"):
            with self.subTest(target=target), mock.patch.object(scan, "walk") as walk, \
                    mock.patch.object(scan.subprocess, "run") as run, \
                    contextlib.redirect_stdout(io.StringIO()) as stdout, \
                    contextlib.redirect_stderr(io.StringIO()) as stderr:
                result = scan.main(["scan.py", target, "--json=", "--no-osv"])
                self.assertEqual(result, 2)
                self.assertEqual(stdout.getvalue(), "")
                self.assertEqual(stderr.getvalue(), "--json requires a non-empty path" + chr(10))
                walk.assert_not_called()
                run.assert_not_called()

    def test_help_documents_inline_form(self):
        result = self.run_scan("--help")
        self.assertEqual(result.returncode, 0)
        self.assertIn("--json=PATH", result.stdout)
