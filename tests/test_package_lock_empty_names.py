"""Malformed empty dependency names must not hide valid legacy entries."""
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
import scan


class PackageLockEmptyNameTests(unittest.TestCase):
    def test_empty_legacy_names_preserve_descendants_and_siblings(self):
        dependencies = {
            "": {"version": "1.0.0", "dependencies": {
                "child": {"version": "2.0.0"},
                "": {"version": "3.0.0", "dependencies": {
                    "@scope/grandchild": {"version": "4.0.0"},
                }},
                "nested-sibling": {"version": "5.0.0"},
            }},
            "sibling": {"version": "6.0.0"},
        }
        for packages in (None, {}, {"": {"version": "7.0.0"}}):
            with self.subTest(packages=packages):
                text = json.dumps({"packages": packages, "dependencies": dependencies})
                self.assertEqual(scan.parse_package_lock(text), [
                    ("npm", "child", "2.0.0"),
                    ("npm", "@scope/grandchild", "4.0.0"),
                    ("npm", "nested-sibling", "5.0.0"),
                    ("npm", "sibling", "6.0.0"),
                ])

    def test_only_empty_legacy_name_produces_no_package(self):
        text = json.dumps({"dependencies": {"": {"version": "1.0.0"}}})
        self.assertEqual(scan.parse_package_lock(text), [])


if __name__ == "__main__":
    unittest.main()
