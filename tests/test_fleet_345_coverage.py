"""Regression coverage extracted without editing baseline test files."""
import os
import tempfile
import unittest
from unittest import mock

from test_hardening import load


class InputHandlingCoverageTests(unittest.TestCase):
    def test_parser_failure_preserves_other_manifests_and_records_error(self):
        for error_type in (ValueError, RuntimeError, RecursionError):
            with self.subTest(error_type=error_type.__name__):
                scan = load("hardening_scan_parser_failure", "scan.py")
                with tempfile.TemporaryDirectory() as root:
                    contents = {
                        "requirements-before.txt": "before-demo==1.2.3\x0a",
                        "nested/package-lock.json": "{}\x0a",
                        "requirements-after.txt": "after-demo==4.5.6\x0a",
                    }
                    files = []
                    for relative, text in contents.items():
                        path = os.path.join(root, relative)
                        os.makedirs(os.path.dirname(path), exist_ok=True)
                        with open(path, "w", encoding="utf-8") as fh:
                            fh.write(text)
                        files.append(path)
                    parser = mock.Mock(side_effect=error_type("fixture parser failure"))
                    with mock.patch.dict(scan.DEP_HANDLERS, {"package-lock.json": parser}):
                        packages = scan.collect_packages(root, files)
                    parser.assert_called_once_with("{}\x0a")
                    self.assertEqual(packages, {
                        ("PyPI", "before-demo", "1.2.3"): "requirements-before.txt",
                        ("PyPI", "after-demo", "4.5.6"): "requirements-after.txt",
                    })
                    self.assertEqual(scan.PARSED_LOCKFILES, [
                        "requirements-before.txt", "requirements-after.txt",
                    ])
                    self.assertEqual(scan.ERRORS, [
                        "parse %s: fixture parser failure" %
                        os.path.join("nested", "package-lock.json"),
                    ])
