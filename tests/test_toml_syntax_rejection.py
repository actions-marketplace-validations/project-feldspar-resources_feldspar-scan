"""Malformed TOML must not leak a partial inventory or abort other manifests."""
import os
import tempfile
import unittest
from unittest import mock

from test_scan import scan


@unittest.skipUnless(scan.tomllib, "requires stdlib TOML decoder")
class TomlSyntaxRejectionTests(unittest.TestCase):
    FORMATS = (("poetry.lock", "PyPI"), ("uv.lock", "PyPI"),
               ("Cargo.lock", "crates.io"))
    VALID = '''[[package]]
name="demo"
version="1.2.3"
'''
    INVALID_SUFFIXES = {
        "duplicate key": 'version="2.0.0"',
        "invalid escape": r'note="bad\q"',
        "invalid unicode escape": r'note="\uD800"',
        "invalid date": 'released=2026-02-30',
    }

    def test_invalid_suffix_discards_complete_package_prefix(self):
        for filename, _ in self.FORMATS:
            for case, suffix in self.INVALID_SUFFIXES.items():
                with self.subTest(filename=filename, case=case):
                    self.assertEqual(scan.DEP_HANDLERS[filename](self.VALID + suffix), [])

    def test_valid_metadata_preserves_package(self):
        text = self.VALID + r'''note="escaped\\path"
released=2026-02-28
'''
        for filename, ecosystem in self.FORMATS:
            with self.subTest(filename=filename):
                self.assertEqual(scan.DEP_HANDLERS[filename](text),
                                 [(ecosystem, "demo", "1.2.3")])

    def test_invalid_manifest_does_not_hide_following_valid_manifest(self):
        for filename, ecosystem in self.FORMATS:
            for case, suffix in self.INVALID_SUFFIXES.items():
                with self.subTest(filename=filename, case=case), \
                     tempfile.TemporaryDirectory() as root, \
                     mock.patch.object(scan, "ERRORS", []), \
                     mock.patch.object(scan, "PARSED_LOCKFILES", []):
                    paths = []
                    for directory, content in (("broken", self.VALID + suffix),
                                               ("valid", self.VALID)):
                        folder = os.path.join(root, directory)
                        os.mkdir(folder)
                        path = os.path.join(folder, filename)
                        with open(path, "w", encoding="utf-8") as fh:
                            fh.write(content)
                        paths.append(path)
                    self.assertEqual(scan.collect_packages(root, paths), {
                        (ecosystem, "demo", "1.2.3"): os.path.join("valid", filename),
                    })
                    self.assertEqual(scan.ERRORS, [])
