"""Pin the documented secret-scan filename exclusions with synthetic text."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from test_scan import _collect, scan


class SecretLockfileScopeTests(unittest.TestCase):
    candidate = "AKIA" + "A1B2C3D4E5F6G7H8"

    def test_named_lockfiles_and_go_mod_skip_secret_content(self):
        filenames = ("package-lock.json", "yarn.lock", "pnpm-lock.yaml",
                     "poetry.lock", "uv.lock", "Cargo.lock", "Gemfile.lock",
                     "go.sum", "go.mod", "composer.lock")
        for name in filenames:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as root:
                folder = Path(root, "nested")
                folder.mkdir()
                (folder / name).write_text(self.candidate, encoding="utf-8")
                self.assertEqual(_collect(root, scan.scan_secrets), [])

    def test_other_lockfiles_and_manifests_still_receive_secret_scan(self):
        for name in ("custom.lock", "requirements.txt", "package.json", "pyproject.toml"):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as root:
                Path(root, name).write_text(self.candidate, encoding="utf-8")
                hits = _collect(root, scan.scan_secrets)
                self.assertEqual(len(hits), 1)
                self.assertEqual(hits[0]["file"], name)
                self.assertEqual(hits[0]["line"], 1)
                self.assertEqual(hits[0]["severity"], "high")
                self.assertEqual(hits[0]["summary"], "AWS access key ID detected")
                self.assertEqual(hits[0]["evidence"], "AKIA…")
                self.assertNotIn(self.candidate, str(hits))

    def test_secret_exclusion_does_not_prevent_dependency_inventory(self):
        with tempfile.TemporaryDirectory() as root:
            Path(root, "package-lock.json").write_text(json.dumps({
                "packages": {"node_modules/demo": {"version": "1.2.3"}},
                "synthetic_note": self.candidate,
            }), encoding="utf-8")
            stdout = io.StringIO()
            with mock.patch.object(scan, "query_osv", side_effect=AssertionError("offline")), \
                    contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(io.StringIO()):
                status = scan.main(["scan.py", root, "--no-osv", "--fail-on", "high"])
            report = json.loads(stdout.getvalue())
            self.assertEqual(status, 0)
            self.assertEqual(report["summary"]["packages_found"], 1)
            self.assertEqual(report["summary"]["lockfiles_parsed"], ["package-lock.json"])
            self.assertEqual(report["summary"]["files_scanned"], 1)
            self.assertEqual(report["findings"], [])
            self.assertNotIn(self.candidate, stdout.getvalue())
