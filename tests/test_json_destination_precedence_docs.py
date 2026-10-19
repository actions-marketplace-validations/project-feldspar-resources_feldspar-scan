"""Documented destination precedence uses synthetic offline config findings."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from test_scan import scan


class JsonDestinationPrecedenceDocsTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="fds-destination-")
        self.addCleanup(temp.cleanup)
        self.directory = Path(temp.name)
        self.repo = self.directory / "repo"
        self.repo.mkdir()
        (self.repo / "Dockerfile").write_text("FROM scratch" + chr(10), encoding="utf-8")
        self.earlier = self.directory / "earlier.json"
        self.earlier.write_text("preserve me" + chr(10), encoding="utf-8")
        self.missing = self.directory / "absent" / "unused.json"
        self.final = self.directory / "final.json"

    def invoke(self, *flags):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err), \
                mock.patch.object(scan, "query_osv", side_effect=AssertionError("network")), \
                mock.patch.object(scan, "git_head", return_value=None):
            status = scan.main(["scan.py", str(self.repo), "--no-osv",
                                "--no-timestamp", "--triage", "--fail-on", "low", *flags])
        return status, out.getvalue(), err.getvalue()

    def assert_earlier_untouched(self):
        self.assertEqual(self.earlier.read_text(encoding="utf-8"), "preserve me" + chr(10))
        self.assertFalse(self.missing.parent.exists())

    def test_last_file_wins_across_both_spellings(self):
        baseline_status, baseline, baseline_err = self.invoke()
        self.assertEqual(baseline_status, 1)
        self.assertTrue(json.loads(baseline)["triage"])
        for final_flags in (("--json", str(self.final)), ("--json=" + str(self.final),)):
            with self.subTest(final_flags=final_flags):
                status, out, err = self.invoke(
                    "--json", str(self.earlier), "--json=" + str(self.missing),
                    "--json=-", *final_flags)
                self.assertEqual(status, baseline_status)
                self.assertEqual(out, "")
                self.assertEqual(self.final.read_text(encoding="utf-8"), baseline)
                self.assertEqual(err, "wrote %s (1 findings)" % self.final + chr(10) + baseline_err)
                self.assert_earlier_untouched()

    def test_last_stdout_wins_across_both_spellings(self):
        baseline = self.invoke("--compact")
        for final_flags in (("--json", "-"), ("--json=-",)):
            with self.subTest(final_flags=final_flags):
                result = self.invoke("--compact", "--json=" + str(self.earlier),
                                     "--json", str(self.missing), *final_flags)
                self.assertEqual(result, baseline)
                self.assert_earlier_untouched()

    def test_invalid_earlier_destination_is_not_overridden(self):
        with mock.patch.object(scan, "walk", side_effect=AssertionError("scan started")):
            status, out, err = self.invoke("--json=", "--json", str(self.final))
        self.assertEqual(status, 2)
        self.assertEqual(out, "")
        self.assertEqual(err, "--json requires a non-empty path" + chr(10))
        self.assertFalse(self.final.exists())
        self.assert_earlier_untouched()

    def test_missing_final_value_does_not_write_earlier_file(self):
        with mock.patch.object(scan, "walk", side_effect=AssertionError("scan started")):
            status, out, err = self.invoke("--json", str(self.earlier), "--json")
        self.assertEqual(status, 2)
        self.assertEqual(out, "")
        self.assertEqual(err, "unknown arg: --json" + chr(10))
        self.assert_earlier_untouched()
