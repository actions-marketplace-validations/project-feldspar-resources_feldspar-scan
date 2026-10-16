import json
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import action_run


class ActionSummaryTests(unittest.TestCase):
    def test_report_fields_cannot_create_summary_markup_or_rows(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = Path(tmp, "report.json")
            summary = Path(tmp, "summary.md")
            outputs = Path(tmp, "outputs.txt")
            report.write_text(json.dumps({
                "findings": [{
                    "id": "F-001", "severity": "high", "category": "dependency-vuln",
                    "file": "bad|name\n| forged | row |", "line": 3,
                    "summary": "<img src=x> [click](https://example.invalid) | `code`",
                }],
                "summary": {"by_severity": {"high": 1}},
                "triage": {"F-001": {"action": "upgrade", "upgrade_to": ["1.0|2.0"]}},
                "triage_summary": {"headline": "<script>bad</script>"},
            }))
            env = {"FDS_OUTPUT": str(report), "FDS_TRIAGE": "true",
                   "GITHUB_OUTPUT": str(outputs), "GITHUB_STEP_SUMMARY": str(summary)}
            with patch.dict(os.environ, env), patch.object(
                action_run.subprocess, "run", return_value=SimpleNamespace(returncode=0)
            ):
                self.assertEqual(action_run.main(), 0)

            rendered = summary.read_text()
            self.assertNotIn("<img", rendered)
            self.assertNotIn("<script>", rendered)
            self.assertNotIn("[click](", rendered)
            self.assertNotIn("| forged | row |", rendered)
            self.assertIn("&lt;img", rendered)
            self.assertIn("&#124;", rendered)
            self.assertIn("&#96;code&#96;", rendered)
            self.assertEqual(len([line for line in rendered.splitlines() if line.startswith("|")]), 3)
            self.assertIn("findings=1", outputs.read_text())


if __name__ == "__main__":
    unittest.main()
