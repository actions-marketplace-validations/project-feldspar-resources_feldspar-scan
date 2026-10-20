"""Keep pnpm package inventory when the section header has a YAML comment."""
import os
import tempfile
import unittest

from test_hardening import load


class PnpmHeaderCommentTests(unittest.TestCase):
    def test_commented_headers_preserve_packages_and_section_boundary(self):
        scan = load("pnpm_header_comments_scan", "scan.py")
        for header in ("packages: # resolved packages", "packages:\t# packages",
                       "packages:  #", "packages:"):
            with self.subTest(header=header):
                text = f"""{header}
  demo@1.2.3:
  '@scope/pkg@2.0.0':
snapshots:
  outside@3.0.0:
"""
                self.assertEqual(scan.parse_pnpm_lock(text), [
                    ("npm", "demo", "1.2.3"),
                    ("npm", "@scope/pkg", "2.0.0"),
                ])

    def test_noncomment_header_values_do_not_open_packages(self):
        scan = load("pnpm_header_values_scan", "scan.py")
        for header in ("packages: invalid # comment", "packages: {} # comment",
                       "packages:#not-separated", "packagesExtra: # comment"):
            with self.subTest(header=header):
                self.assertEqual(scan.parse_pnpm_lock(
                    f"""{header}
  ignored@1.0.0:
"""), [])

    def test_collection_attributes_commented_header_packages(self):
        scan = load("pnpm_header_collection_scan", "scan.py")
        with tempfile.TemporaryDirectory() as root:
            path = os.path.join(root, "pnpm-lock.yaml")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write("""lockfileVersion: '9.0'
packages: # registry packages
  demo@1.2.3:
snapshots:
  outside@3.0.0:
""")
            self.assertEqual(scan.collect_packages(root, list(scan.walk(root))), {
                ("npm", "demo", "1.2.3"): "pnpm-lock.yaml",
            })
        self.assertEqual(scan.PARSED_LOCKFILES, ["pnpm-lock.yaml"])
        self.assertEqual(scan.ERRORS, [])
