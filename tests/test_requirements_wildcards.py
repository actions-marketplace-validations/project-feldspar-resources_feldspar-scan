"""Wildcard requirements must not be inventoried as exact versions."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from test_hardening import load


class RequirementsWildcardTests(unittest.TestCase):
    def test_wildcard_versions_are_skipped_without_losing_exact_pins(self):
        scan = load("requirements_wildcards", "scan.py")
        for version in ("1.*", "1.2.*", "1*", "1.*.3", '"1.2.*"', "'1.*'"):
            for suffix in ("", " # comment", '; python_version >= "3"'):
                with self.subTest(version=version, suffix=suffix):
                    text = chr(10).join([
                        "before==1.0", "wildcard[extra]==" + version + suffix,
                        "after==2.0rc1", "local==3.0+build.1"])
                    self.assertEqual(scan.parse_requirements(text), [
                        ("PyPI", "before", "1.0"),
                        ("PyPI", "after", "2.0rc1"),
                        ("PyPI", "local", "3.0+build.1"),
                    ])

    def test_only_exact_versions_reach_advisory_lookup(self):
        scan = load("requirements_wildcards_report", "scan.py")
        with tempfile.TemporaryDirectory() as root:
            Path(root, "requirements.txt").write_text(
                chr(10).join(["wildcard==1.*", "exact==1.2.3", ""]), encoding="utf-8")
            Path(root, "requirements-dev.txt").write_text(
                "other[extra]==2.4.*; python_version >= '3'" + chr(10), encoding="utf-8")
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout), mock.patch.object(
                    scan, "git_head", return_value=None), mock.patch.object(
                    scan, "query_osv", return_value={}) as query:
                status = scan.main(["scan.py", root])
            self.assertEqual(status, 0)
            query.assert_called_once_with([("PyPI", "exact", "1.2.3")])
            report = json.loads(stdout.getvalue())
            self.assertEqual(report["summary"]["packages_found"], 1)
            self.assertEqual(report["summary"]["lockfiles_parsed"], [
                "requirements-dev.txt", "requirements.txt"])
            self.assertNotIn("errors", report)
