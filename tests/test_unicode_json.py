"""Opt-in Unicode serialization preserves report content and JSON escaping."""
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


SCANNER = Path(__file__).resolve().parents[1] / "scan.py"


class UnicodeJsonTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="fds-unicode-")
        self.addCleanup(temporary.cleanup)
        self.cwd = Path(temporary.name)
        self.repo = self.cwd / "repo"
        self.repo.mkdir()
        # Synthetic config findings only; exercise BMP, non-BMP and JSON escapes.
        self.relative = 'café-東京-🚀/quote"tab\tline' + chr(10) + '/Dockerfile'
        path = self.repo / self.relative
        path.parent.mkdir(parents=True)
        path.write_text("FROM scratch" + chr(10), encoding="utf-8")

    def run_scan(self, *args, env=None):
        return subprocess.run(
            [sys.executable, str(SCANNER), str(self.repo), "--no-osv", *args],
            cwd=self.cwd, capture_output=True, text=True, encoding="utf-8",
            env=env or dict(os.environ, PYTHONIOENCODING="utf-8"), timeout=10)

    def assert_report(self, text, unicode, compact):
        report = json.loads(text)
        options = {"separators": (",", ":")} if compact else {"indent": 2}
        self.assertEqual(text, json.dumps(report, ensure_ascii=not unicode, **options) + chr(10))
        self.assertEqual(report["findings"][0]["file"], self.relative)
        self.assertIn('quote\\"tab\\tline' + chr(92) + 'n', text)
        self.assertEqual("café-東京-🚀" in text, unicode)
        if compact:
            self.assertEqual(len(text.splitlines()), 1)
        report.pop("scanned_at")
        return report

    def test_stdout_preserves_default_data_with_compact_triage_and_gates(self):
        for compact in (False, True):
            for triage in (False, True):
                for threshold, status in (("critical", 0), ("low", 1)):
                    args = (["--compact"] if compact else [])
                    args += ["--triage"] if triage else []
                    args += ["--fail-on", threshold]
                    with self.subTest(compact=compact, triage=triage, threshold=threshold):
                        baseline = self.run_scan(*args)
                        self.assertEqual(baseline.returncode, status, baseline.stderr)
                        expected = self.assert_report(baseline.stdout, False, compact)
                        for destination in ((), ("--json", "-"), ("--json=-",)):
                            result = self.run_scan(*args, "--unicode-json", *destination)
                            self.assertEqual(result.returncode, status, result.stderr)
                            self.assertEqual(result.stderr, baseline.stderr)
                            self.assertEqual(self.assert_report(result.stdout, True, compact), expected)

    def test_named_files_are_utf8_even_with_ascii_stdout(self):
        env = dict(os.environ, PYTHONUTF8="1", PYTHONIOENCODING="ascii")
        for compact in (False, True):
            args = ["--compact"] if compact else []
            for destination in (("--json", "report.json"), ("--json=report.json",)):
                with self.subTest(compact=compact, destination=destination):
                    expected = self.run_scan(*args)
                    result = self.run_scan(*args, "--unicode-json", *destination, env=env)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(result.stdout, "")
                    self.assertIn("wrote report.json", result.stderr)
                    self.assertEqual(
                        self.assert_report((self.cwd / "report.json").read_text(encoding="utf-8"),
                                           True, compact),
                        self.assert_report(expected.stdout, False, compact))

    @unittest.skipUnless(os.name == "posix", "byte filenames require POSIX")
    def test_undecodable_filenames_and_ascii_locale_preserve_json(self):
        raw_directory = os.fsencode(self.repo) + b"/raw-\xff"
        os.mkdir(raw_directory)
        with open(raw_directory + b"/Dockerfile", "wb") as fh:
            # Synthetic config value; the finding evidence includes a Unicode ellipsis.
            fh.write(b"FROM scratch" + bytes([10]) + b"ENV TOKEN=x" + bytes([10]))
        for utf8 in ("0", "1"):
            env = dict(os.environ, LC_ALL="C", PYTHONUTF8=utf8,
                       PYTHONCOERCECLOCALE="0", PYTHONIOENCODING="utf-8")
            with self.subTest(utf8=utf8):
                baseline = self.run_scan(env=env)
                self.assertEqual(baseline.returncode, 0, baseline.stderr)
                expected = json.loads(baseline.stdout)
                expected.pop("scanned_at")
                for destination in ((), ("--json", "bytes.json")):
                    result = self.run_scan("--unicode-json", *destination, env=env)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    text = ((self.cwd / "bytes.json").read_text(encoding="utf-8")
                            if destination else result.stdout)
                    actual = json.loads(text)
                    actual.pop("scanned_at")
                    self.assertEqual(actual, expected)
                    self.assertIn(r"raw-\udcff", text)
                    self.assertIn("TOKEN=…", text)

    def test_repetition_and_same_process_invocation_isolation(self):
        spec = importlib.util.spec_from_file_location("scan_unicode_test", SCANNER)
        scanner = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(scanner)
        for flags in (("--unicode-json", "--unicode-json"), ()):
            with self.subTest(flags=flags):
                output = io.StringIO()
                with contextlib.redirect_stdout(output):
                    status = scanner.main(["scan.py", str(self.repo), "--no-osv", *flags])
                self.assertEqual(status, 0)
                self.assert_report(output.getvalue(), bool(flags), False)

    def test_empty_scan_and_help(self):
        (self.repo / self.relative).unlink()
        result = self.run_scan("--unicode-json", "--compact")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["findings"], [])
        help_result = self.run_scan("--help")
        self.assertEqual(help_result.returncode, 0, help_result.stderr)
        self.assertIn("--unicode-json", help_result.stdout)
        self.assertIn("UTF-8", help_result.stdout)
