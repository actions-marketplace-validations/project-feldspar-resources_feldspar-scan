"""Changed manifest types must be rejected at the read boundary without blocking."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


SCANNER = Path(__file__).resolve().parents[1]
COLLECT = """
import json
import scan
import sys
root, *files = sys.argv[1:]
packages = scan.collect_packages(root, files)
print(json.dumps({
    'packages': [list(key) + [path] for key, path in packages.items()],
    'parsed': scan.PARSED_LOCKFILES,
    'errors': scan.ERRORS,
}))
"""


class ManifestReplacementTests(unittest.TestCase):
    def check_replacement(self, replacement):
        from test_hardening import load
        scan = load("replacement_discovery_scan", "scan.py")
        with tempfile.TemporaryDirectory() as outer:
            root = Path(outer, "repo")
            root.mkdir()
            changed = root / "requirements-a.txt"
            healthy = root / "requirements-b.txt"
            changed.write_text("old-demo==1.0.0", encoding="utf-8")
            healthy.write_text("kept-demo==2.0.0", encoding="utf-8")
            files = list(scan.walk(str(root)))
            self.assertEqual(files, [str(changed), str(healthy)])
            changed.unlink()
            if replacement == "fifo":
                os.mkfifo(changed)  # No writer: a blocking open would hang.
            else:
                target = Path(outer, "outside.txt")
                target.write_text("outside-demo==3.0.0", encoding="utf-8")
                changed.symlink_to(target)
            result = subprocess.run(
                [sys.executable, "-c", COLLECT, str(root), *files],
                cwd=SCANNER, capture_output=True, text=True, timeout=5)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(result.stdout), {
                "packages": [["PyPI", "kept-demo", "2.0.0", "requirements-b.txt"]],
                "parsed": ["requirements-b.txt"],
                "errors": [],
            })

    @unittest.skipUnless(hasattr(os, "mkfifo") and hasattr(os, "O_NONBLOCK"),
                         "requires FIFO and nonblocking-open support")
    def test_fifo_replacement_is_skipped_without_waiting_for_writer(self):
        self.check_replacement("fifo")

    @unittest.skipUnless(hasattr(os, "symlink") and hasattr(os, "O_NOFOLLOW"),
                         "requires no-follow open support")
    def test_symlink_replacement_does_not_import_target_dependencies(self):
        self.check_replacement("symlink")
