"""Original PRO-357 methods, isolated to preserve baseline test files."""
import json
import unittest
from test_scan import scan

class NestedPackageLockCoverageTests(unittest.TestCase):
    def test_package_lock_malformed_child_maps_preserve_parent_and_siblings(self):
        for malformed in (None, False, 7, "broken", [], ["broken"]):
            with self.subTest(dependencies=malformed):
                data = {"dependencies": {
                    "parent": {"version": "1.0.0", "dependencies": {
                        "broken": None,
                        "child": {"version": "2.0.0", "dependencies": malformed},
                        "nested-sibling": {"version": "3.0.0"},
                    }},
                    "sibling": {"version": "4.0.0"},
                }}
                self.assertEqual(scan.parse_package_lock(json.dumps(data)), [
                    ("npm", "parent", "1.0.0"),
                    ("npm", "child", "2.0.0"),
                    ("npm", "nested-sibling", "3.0.0"),
                    ("npm", "sibling", "4.0.0"),
                ])

    def test_package_lock_invalid_parent_version_preserves_valid_descendants(self):
        for version in (None, False, 7, "", [], {}):
            with self.subTest(version=version):
                data = {"dependencies": {
                    "parent": {"version": version, "dependencies": {
                        "child": {"version": "2.0.0"},
                    }},
                    "sibling": {"version": "3.0.0"},
                }}
                self.assertEqual(scan.parse_package_lock(json.dumps(data)), [
                    ("npm", "child", "2.0.0"), ("npm", "sibling", "3.0.0"),
                ])
