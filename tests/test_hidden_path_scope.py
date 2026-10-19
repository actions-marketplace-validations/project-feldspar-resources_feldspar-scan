"""Leading-dot paths remain eligible, subject to the usual exclusions."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


SCANNER = Path(__file__).resolve().parents[1] / "scan.py"


class HiddenPathScopeTests(unittest.TestCase):
    def scan(self, files):
        with tempfile.TemporaryDirectory(prefix="fds-hidden-") as directory:
            root = Path(directory)
            for relative, content in files.items():
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content, encoding="utf-8")
            result = subprocess.run(
                [sys.executable, str(SCANNER), str(root), "--no-osv",
                 "--no-commit", "--fail-on", "high"],
                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 1, result.stderr)
        report = json.loads(result.stdout)
        self.assertNotIn("errors", report)
        self.assertFalse(report["summary"]["osv_enabled"])
        return report

    def test_hidden_files_and_directories_receive_secret_checks(self):
        # Fabricated pattern fixture, never a real credential.
        value = "AKIA" + "Q7" * 8
        report = self.scan({
            ".settings": value + chr(10),
            ".config/.settings": value + chr(10),
            ".git/.settings": value + chr(10),
            ".venv/.settings": value + chr(10),
            ".config/diagram.svg": value + chr(10),
        })
        self.assertEqual(report["summary"]["files_scanned"], 3)
        self.assertEqual(
            [(f["file"], f["category"], f["severity"]) for f in report["findings"]],
            [(".config/.settings", "secret", "high"),
             (".settings", "secret", "high")])
        self.assertNotIn(value, json.dumps(report))

    def test_hidden_directory_retains_config_checks_and_dependency_inventory(self):
        report = self.scan({
            ".config/.env": "APP_MODE=development" + chr(10),
            ".config/requirements.txt": "demo-package==1.2.3" + chr(10),
            ".venv/requirements.txt": "excluded-package==9.9.9" + chr(10),
        })
        self.assertEqual(report["summary"]["files_scanned"], 2)
        self.assertEqual(report["summary"]["packages_found"], 1)
        self.assertEqual(report["summary"]["packages_by_manifest"],
                         {".config/requirements.txt": 1})
        self.assertEqual(report["summary"]["lockfiles_parsed"],
                         [".config/requirements.txt"])
        self.assertEqual(
            [(f["file"], f["category"], f["severity"]) for f in report["findings"]],
            [(".config/.env", "config", "high")])


if __name__ == "__main__":
    unittest.main()
