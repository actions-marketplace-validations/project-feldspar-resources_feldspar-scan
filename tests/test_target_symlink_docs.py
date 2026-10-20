"""Document the distinction between a selected directory alias and child links."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


SCANNER = Path(__file__).resolve().parents[1] / "scan.py"


class TargetSymlinkDocumentationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="fds-target-alias-")
        self.addCleanup(temporary.cleanup)
        self.cwd = Path(temporary.name)
        self.real = self.cwd / "real"
        self.real.mkdir()
        self.alias = self.cwd / "alias"
        self.alias.symlink_to(self.real, target_is_directory=True)

    def report(self, target):
        result = subprocess.run(
            [sys.executable, str(SCANNER), target, "--no-osv", "--no-commit",
             "--no-timestamp", "--triage", "--fail-on", "low"],
            cwd=self.cwd, capture_output=True, text=True, timeout=10)
        self.assertIn(result.returncode, (0, 1), result.stderr)
        return result.returncode, json.loads(result.stdout)

    def test_selected_directory_alias_preserves_findings_and_relative_paths(self):
        nested = self.real / "app"
        nested.mkdir()
        (nested / "Dockerfile").write_text("FROM scratch" + chr(10), encoding="utf-8")
        direct_status, direct = self.report("./real")
        alias_status, alias = self.report("./alias")
        self.assertEqual((direct_status, alias_status), (1, 1))
        self.assertEqual(alias["target"], "./alias")
        self.assertEqual(direct["target"], "./real")
        self.assertEqual(len(alias["findings"]), 1)
        self.assertEqual(alias["findings"][0]["file"], "app/Dockerfile")
        self.assertEqual(alias["findings"][0]["category"], "config")
        self.assertEqual(alias["summary"]["files_scanned"], 1)
        self.assertEqual(alias["summary"]["skipped_non_regular"], 0)
        self.assertFalse(alias["summary"]["gate"]["passed"])
        for key in ("findings", "summary", "triage", "triage_summary"):
            self.assertEqual(alias[key], direct[key], key)
        # Target spelling is part of the documented manifest_hash input.
        self.assertNotEqual(alias["manifest_hash"], direct["manifest_hash"])

    def test_child_links_are_skipped_even_through_a_selected_alias(self):
        outside = self.cwd / "outside"
        outside.mkdir()
        (outside / "Dockerfile").write_text("FROM scratch" + chr(10), encoding="utf-8")
        (self.real / "plain.txt").write_text("ordinary text" + chr(10), encoding="utf-8")
        (self.real / "linked-dir").symlink_to(outside, target_is_directory=True)
        (self.real / "Dockerfile").symlink_to(outside / "Dockerfile")
        status, report = self.report("./alias")
        self.assertEqual(status, 0)
        self.assertEqual(report["findings"], [])
        self.assertEqual(report["summary"]["files_scanned"], 1)
        self.assertEqual(report["summary"]["skipped_non_regular"], 2)
        self.assertTrue(report["summary"]["gate"]["passed"])
        # Selecting that directory link explicitly changes the traversal root.
        status, selected = self.report("./alias/linked-dir")
        self.assertEqual(status, 1)
        self.assertEqual(selected["target"], "./alias/linked-dir")
        self.assertEqual(selected["summary"]["files_scanned"], 1)
        self.assertEqual(selected["summary"]["skipped_non_regular"], 0)
        self.assertEqual([f["file"] for f in selected["findings"]], ["Dockerfile"])

    def test_empty_selected_alias_is_not_itself_a_file_or_skip(self):
        status, report = self.report(str(self.alias))
        self.assertEqual(status, 0)
        self.assertEqual(report["target"], str(self.alias))
        self.assertEqual(report["findings"], [])
        self.assertEqual(report["summary"]["files_scanned"], 0)
        self.assertEqual(report["summary"]["skipped_non_regular"], 0)
        self.assertEqual(report["summary"]["truncated"],
                         {"files": False, "findings": False})


if __name__ == "__main__":
    unittest.main()
