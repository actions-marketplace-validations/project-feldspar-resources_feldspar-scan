"""Go inventory must stay inside require directives and recover after bad rows."""
from pathlib import Path
import tempfile
import unittest

from test_hardening import load


MANIFEST = """module example.com/app

require ( // direct dependencies
    example.com/first v1.2.3
) // end first block

exclude (
    example.com/excluded v9.0.0
)
replace (
    example.com/old v1.0.0 => example.com/new v2.0.0
)
retract (
    v0.1.0
)
// require example.com/commented v3.0.0

require (
    example.com/incomplete
    example.com/bare-version v
    example.com/extra v4.0.0 unexpected
    example.com/second v2.3.4 // indirect
)
require example.com/last v3.4.5
"""

EXPECTED = [
    ("Go", "example.com/first", "v1.2.3"),
    ("Go", "example.com/second", "v2.3.4"),
    ("Go", "example.com/last", "v3.4.5"),
]


class GoBlockIsolationTests(unittest.TestCase):
    def test_blocks_comments_and_incomplete_rows_preserve_only_requirements(self):
        scan = load("go_block_isolation_scan", "scan.py")
        for newline in (chr(10), chr(13) + chr(10)):
            with self.subTest(newline=newline):
                self.assertEqual(scan.parse_go_mod(newline.join(MANIFEST.splitlines())),
                                 EXPECTED)

    def test_collection_keeps_valid_neighbors_and_manifest_attribution(self):
        scan = load("go_block_collection_scan", "scan.py")
        with tempfile.TemporaryDirectory() as root:
            manifest = Path(root, "go.mod")
            manifest.write_text(MANIFEST, encoding="utf-8")
            self.assertEqual(scan.collect_packages(root, [str(manifest)]),
                             {package: "go.mod" for package in EXPECTED})
        self.assertEqual(scan.PARSED_LOCKFILES, ["go.mod"])
        self.assertEqual(scan.ERRORS, [])
