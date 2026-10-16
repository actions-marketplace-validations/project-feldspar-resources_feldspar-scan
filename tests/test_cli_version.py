"""Standalone version output must not start a scan or write a report."""
from contextlib import ExitStack, redirect_stderr, redirect_stdout
import io
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from test_scan import scan


class CliVersionTests(unittest.TestCase):
    def test_version_returns_success_without_scan_side_effects(self):
        stdout, stderr = io.StringIO(), io.StringIO()
        with ExitStack() as stack:
            for target in ("walk", "read_text", "collect_packages", "query_osv",
                           "scan_secrets", "scan_config", "git_head"):
                stack.enter_context(patch.object(
                    scan, target, side_effect=AssertionError(target)))
            for obj, name in ((scan.subprocess, "run"),
                              (scan.tempfile, "mkdtemp"), (scan.os.path, "isdir")):
                stack.enter_context(patch.object(
                    obj, name, side_effect=AssertionError(name)))
            stack.enter_context(patch("builtins.open", side_effect=AssertionError("open")))
            stack.enter_context(redirect_stdout(stdout))
            stack.enter_context(redirect_stderr(stderr))
            self.assertEqual(scan.main(["scan.py", "--version"]), 0)
        self.assertEqual(stdout.getvalue(), f"{scan.SCANNER} {scan.VERSION}" + chr(10))
        self.assertEqual(stderr.getvalue(), "")

    def test_cli_version_does_not_create_files(self):
        with tempfile.TemporaryDirectory() as root:
            result = subprocess.run(
                [sys.executable, scan.__file__, "--version"], cwd=root,
                capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, f"{scan.SCANNER} {scan.VERSION}" + chr(10))
            self.assertEqual(result.stderr, "")
            self.assertEqual(list(Path(root).iterdir()), [])

    def test_help_documents_standalone_version_invocation(self):
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            self.assertEqual(scan.main(["scan.py", "--help"]), 0)
        self.assertIn("scan.py --version", stdout.getvalue())
