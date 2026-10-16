"""Action summary states dependency coverage limits visible in the JSON report."""
import json
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import action_run


class ActionCoverageTests(unittest.TestCase):
    def render(self, *, osv, notes):
        with tempfile.TemporaryDirectory() as tmp:
            report = Path(tmp, "report.json")
            summary = Path(tmp, "summary.md")
            data = {
                "findings": [],
                "summary": {
                    "files_scanned": 1,
                    "packages_found": 0,
                    "vulnerable_packages": 0,
                    "by_severity": {},
                    "lockfiles_parsed": [],
                },
            }
            if notes:
                data["summary"]["notes"] = ["No supported dependency manifest was parsed"]
            report.write_text(json.dumps(data))
            env = {
                "FDS_OUTPUT": str(report),
                "FDS_OSV": "true" if osv else "false",
                "GITHUB_STEP_SUMMARY": str(summary),
            }
            with patch.dict(os.environ, env, clear=True), patch.object(
                action_run.subprocess, "run", return_value=SimpleNamespace(returncode=0)
            ):
                self.assertEqual(action_run.main(), 0)
            return summary.read_text()

    def test_skipped_osv_and_missing_manifest_are_visible(self):
        rendered = self.render(osv=False, notes=True)
        self.assertIn("Dependency advisory lookup skipped", rendered)
        self.assertIn("Dependency coverage incomplete", rendered)
        self.assertIn("summary.notes", rendered)

    def test_complete_online_scan_has_no_coverage_warning(self):
        rendered = self.render(osv=True, notes=False)
        self.assertNotIn("Dependency advisory lookup skipped", rendered)
        self.assertNotIn("Dependency coverage incomplete", rendered)

    def test_offline_scan_with_manifest_only_reports_skipped_lookup(self):
        rendered = self.render(osv=False, notes=False)
        self.assertIn("Dependency advisory lookup skipped", rendered)
        self.assertNotIn("Dependency coverage incomplete", rendered)


if __name__ == "__main__":
    unittest.main()
