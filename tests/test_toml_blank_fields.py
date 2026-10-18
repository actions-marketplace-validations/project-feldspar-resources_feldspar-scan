"""Blank TOML package fields must not enter the dependency inventory."""
import os
import tempfile
import unittest
from unittest import mock

from test_hardening import load


class TomlBlankFieldTests(unittest.TestCase):
    def test_blank_fields_preserve_valid_neighbors_in_both_parsers(self):
        scan = load("toml_blank_fields", "scan.py")
        parsers = [None] + ([scan.tomllib] if scan.tomllib else [])
        for parser in parsers:
            for field in ("name", "version"):
                for blank in ("", " ", "\t", " \t "):
                    with self.subTest(parser=parser, field=field, blank=blank):
                        fields = {"name": "incomplete", "version": "1.0"}
                        fields[field] = blank
                        text = chr(10).join([
                            '[[package]]', 'name="before"', 'version="1.2.3"',
                            '[[package]]', 'name="%s"' % fields["name"],
                            'version="%s"' % fields["version"],
                            '[[package]]', 'name="after"', 'version="2.0.0-rc.1"',
                        ])
                        with mock.patch.object(scan, "tomllib", parser):
                            self.assertEqual(scan.parse_toml_packages(text, "PyPI"), [
                                ("PyPI", "before", "1.2.3"),
                                ("PyPI", "after", "2.0.0-rc.1"),
                            ])

    def test_collection_skips_blank_fields_for_all_toml_lockfiles(self):
        scan = load("toml_blank_field_collection", "scan.py")
        text = chr(10).join([
            '[[package]]', 'name=" "', 'version="1.0"',
            '[[package]]', 'name="incomplete"', 'version="\t"',
            '[[package]]', 'name="demo"', 'version="1.2.3"',
        ])
        for filename, ecosystem in (("poetry.lock", "PyPI"), ("uv.lock", "PyPI"),
                                    ("Cargo.lock", "crates.io")):
            with self.subTest(filename=filename), tempfile.TemporaryDirectory() as root:
                path = os.path.join(root, filename)
                with open(path, "w", encoding="utf-8") as fh:
                    fh.write(text)
                scan.ERRORS.clear()
                scan.PARSED_LOCKFILES.clear()
                self.assertEqual(scan.collect_packages(root, [path]), {
                    (ecosystem, "demo", "1.2.3"): filename,
                })
                self.assertEqual(scan.PARSED_LOCKFILES, [filename])
                self.assertEqual(scan.ERRORS, [])


if __name__ == "__main__":
    unittest.main()
