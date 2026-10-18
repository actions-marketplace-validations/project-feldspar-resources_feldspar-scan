"""Blank Gemfile.lock versions must not become dependency coordinates."""
from pathlib import Path
import tempfile
import unittest

from test_hardening import load


class GemfileEmptyVersionTests(unittest.TestCase):
    def test_blank_versions_preserve_valid_neighbors(self):
        scan = load("gemfile_empty_versions", "scan.py")
        for version in ("", " ", "   ", "\t", " \t "):
            with self.subTest(version=version):
                text = chr(10).join((
                    "GEM", "  specs:", "    before (1.2.3)",
                    "    incomplete (%s)" % version,
                    "      nested-constraint (>= 1.0)",
                    "    after (2.3.4-java)",
                ))
                self.assertEqual(scan.parse_gemfile_lock(text), [
                    ("RubyGems", "before", "1.2.3"),
                    ("RubyGems", "after", "2.3.4-java"),
                ])

    def test_collection_omits_blank_version_and_keeps_manifest_attribution(self):
        scan = load("gemfile_empty_version_collection", "scan.py")
        with tempfile.TemporaryDirectory() as tmp:
            lockfile = Path(tmp, "Gemfile.lock")
            lockfile.write_text(
                chr(10).join(("GEM", "  specs:", "    incomplete ( \t )",
                              "    complete (1.2.3)", "")),
                encoding="utf-8")
            self.assertEqual(scan.collect_packages(tmp, [str(lockfile)]), {
                ("RubyGems", "complete", "1.2.3"): "Gemfile.lock",
            })
            self.assertEqual(scan.PARSED_LOCKFILES, ["Gemfile.lock"])
            self.assertEqual(scan.ERRORS, [])


if __name__ == "__main__":
    unittest.main()
