"""Manifest size limits must skip whole files, never parse a prefix."""
import os
import tempfile
import unittest

from test_hardening import load


class ManifestSizeBoundaryTests(unittest.TestCase):
    def test_collection_enforces_inclusive_eight_mib_limit(self):
        limit = 8 * 1024 * 1024
        prefix = b"""first-demo==1.2.3
#"""
        suffix = b"""
last-demo==4.5.6
"""
        for size in (1024 * 1024 + 1, limit - 1, limit, limit + 1):
            with self.subTest(size=size), tempfile.TemporaryDirectory() as root:
                scan = load("manifest_size_scan", "scan.py")
                large = os.path.join(root, "requirements-large.txt")
                neighbor = os.path.join(root, "requirements-neighbor.txt")
                with open(large, "wb") as fh:
                    fh.write(prefix)
                    fh.write(b"x" * (size - len(prefix) - len(suffix)))
                    fh.write(suffix)
                with open(neighbor, "wb") as fh:
                    fh.write(b"""neighbor-demo==7.8.9
""")
                expected = {
                    ("PyPI", "neighbor-demo", "7.8.9"): "requirements-neighbor.txt"}
                parsed = ["requirements-neighbor.txt"]
                if size <= limit:
                    expected.update({
                        ("PyPI", "first-demo", "1.2.3"): "requirements-large.txt",
                        ("PyPI", "last-demo", "4.5.6"): "requirements-large.txt"})
                    parsed.insert(0, "requirements-large.txt")
                self.assertEqual(scan.collect_packages(root, [large, neighbor]), expected)
                self.assertEqual(scan.PARSED_LOCKFILES, parsed)
                self.assertEqual(scan.ERRORS, [])
