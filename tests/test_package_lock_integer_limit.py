"""JSON integer conversion failures must not leak partial package inventories."""
import json
from pathlib import Path
import sys
import tempfile
import unittest

from test_hardening import load


@unittest.skipUnless(hasattr(sys, "set_int_max_str_digits"),
                     "Python has no configurable integer conversion limit")
class PackageLockIntegerLimitTests(unittest.TestCase):
    def setUp(self):
        previous = sys.get_int_max_str_digits()
        self.addCleanup(sys.set_int_max_str_digits, previous)
        self.limit = sys.int_info.str_digits_check_threshold
        sys.set_int_max_str_digits(self.limit)
        self.scan = load("package_lock_integer_limit_scan", "scan.py")

    def lockfile(self, schema, metadata):
        package = {"version": "1.2.3"}
        key = "node_modules/demo" if schema == "packages" else "demo"
        text = json.dumps({schema: {key: package}})
        return text[:-1] + ', "metadata": ' + metadata + '}'

    def test_integer_limit_rejects_whole_file_but_not_digit_strings(self):
        for schema in ("packages", "dependencies"):
            with self.subTest(schema=schema):
                at_limit = self.lockfile(schema, "9" * self.limit)
                over_limit = self.lockfile(schema, "9" * (self.limit + 1))
                quoted = self.lockfile(schema, json.dumps("9" * (self.limit + 1)))
                expected = [("npm", "demo", "1.2.3")]
                # Exercise a real decoder failure, independent of scanner mocks.
                with self.assertRaises(ValueError):
                    json.loads(over_limit)
                self.assertEqual(self.scan.parse_package_lock(at_limit), expected)
                self.assertEqual(self.scan.parse_package_lock(over_limit), [])
                self.assertEqual(self.scan.parse_package_lock(quoted), expected)

    def test_collection_continues_after_integer_limit_rejection(self):
        with tempfile.TemporaryDirectory() as root:
            bad = Path(root, "package-lock.json")
            good = Path(root, "requirements.txt")
            bad.write_text(self.lockfile("packages", "9" * (self.limit + 1)),
                           encoding="utf-8")
            good.write_text("neighbor==2.3.4", encoding="utf-8")
            self.assertEqual(
                self.scan.collect_packages(root, [str(bad), str(good)]),
                {("PyPI", "neighbor", "2.3.4"): "requirements.txt"})
            self.assertEqual(self.scan.ERRORS, [])
            self.assertEqual(self.scan.PARSED_LOCKFILES,
                             ["package-lock.json", "requirements.txt"])
