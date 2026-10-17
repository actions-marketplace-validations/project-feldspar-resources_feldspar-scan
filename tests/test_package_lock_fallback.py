"""Pin recovery and precedence for package-lock's two inventory sections."""
import json
import unittest

from test_scan import scan


class PackageLockFallbackTests(unittest.TestCase):
    def test_unusable_packages_section_preserves_legacy_inventory(self):
        sections = [None, False, 7, "broken", [], ["broken"], {},
                    {"": {"version": "9.0.0"}},
                    {"workspace/demo": {"version": "9.0.0"}},
                    {"node_modules/": {"version": "9.0.0"}}]
        for meta in (None, False, 7, "broken", [], {}, {"version": ""},
                     {"version": True}, {"version": ["9.0.0"]}):
            sections.append({"node_modules/broken": meta})
        for packages in sections:
            with self.subTest(packages=packages):
                data = {"packages": packages, "dependencies": {
                    "parent": {"version": "1.0.0", "dependencies": {
                        "child": {"version": "2.0.0"}}},
                    "sibling": {"version": "3.0.0"},
                }}
                self.assertEqual(scan.parse_package_lock(json.dumps(data)), [
                    ("npm", "parent", "1.0.0"),
                    ("npm", "child", "2.0.0"),
                    ("npm", "sibling", "3.0.0"),
                ])

    def test_usable_modern_inventory_does_not_merge_legacy_versions(self):
        data = {"packages": {
            "": {"version": "9.0.0"},
            "node_modules/broken": None,
            "node_modules/demo": {"version": "2.0.0"},
        }, "dependencies": {
            "demo": {"version": "1.0.0"},
            "broken": {"version": "3.0.0"},
            "legacy-only": {"version": "4.0.0"},
        }}
        self.assertEqual(scan.parse_package_lock(json.dumps(data)),
                         [("npm", "demo", "2.0.0")])
