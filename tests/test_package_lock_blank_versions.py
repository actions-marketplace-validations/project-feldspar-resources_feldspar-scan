"""Malformed blank versions must not become package inventory entries."""

import json
import unittest

import scan


class PackageLockBlankVersionTests(unittest.TestCase):
    BLANK_VERSIONS = ("", " ", chr(9) + chr(13) + chr(10), "\u00a0\u2003")

    def test_modern_records_skip_blank_versions_and_keep_valid_neighbors(self):
        for blank in self.BLANK_VERSIONS:
            with self.subTest(version=repr(blank)):
                data = {"packages": {
                    "node_modules/before": {"version": "1.2.3"},
                    "node_modules/blank": {"version": blank},
                    "node_modules/@scope/after": {"version": "2.0.0-beta.1"},
                }}
                self.assertEqual(scan.parse_package_lock(json.dumps(data)), [
                    ("npm", "before", "1.2.3"),
                    ("npm", "@scope/after", "2.0.0-beta.1"),
                ])

    def test_legacy_blank_parent_keeps_valid_nested_dependencies(self):
        for blank in self.BLANK_VERSIONS:
            with self.subTest(version=repr(blank)):
                data = {"dependencies": {
                    "blank-parent": {"version": blank, "dependencies": {
                        "child": {"version": "1.2.3"},
                        "blank-child": {"version": blank},
                    }},
                    "sibling": {"version": "2.0.0"},
                }}
                self.assertEqual(scan.parse_package_lock(json.dumps(data)), [
                    ("npm", "child", "1.2.3"),
                    ("npm", "sibling", "2.0.0"),
                ])

    def test_blank_modern_inventory_does_not_suppress_legacy_fallback(self):
        for blank in self.BLANK_VERSIONS:
            with self.subTest(version=repr(blank)):
                data = {
                    "packages": {"node_modules/blank": {"version": blank}},
                    "dependencies": {"legacy": {"version": "3.4.5"}},
                }
                self.assertEqual(scan.parse_package_lock(json.dumps(data)),
                                 [("npm", "legacy", "3.4.5")])
