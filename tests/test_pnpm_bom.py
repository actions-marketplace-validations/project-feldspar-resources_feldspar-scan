"""A leading UTF-8 signature must not hide pnpm's packages section."""
from pathlib import Path
import tempfile
import unittest

from test_hardening import load


class PnpmBomTests(unittest.TestCase):
    def test_bom_preserves_inventory_and_section_boundaries(self):
        scan = load("pnpm_bom_parser", "scan.py")
        for newline in (chr(10), chr(13) + chr(10)):
            for header in ("packages:", "packages: # resolved"):
                text = newline.join((
                    header, "  demo@1.2.3:", "  '@scope/pkg@2.0.0':",
                    "snapshots:", "  outside@3.0.0:", "",
                ))
                for signature in ("", "\ufeff"):
                    with self.subTest(newline=newline, header=header,
                                      signature=signature):
                        self.assertEqual(scan.parse_pnpm_lock(signature + text), [
                            ("npm", "demo", "1.2.3"),
                            ("npm", "@scope/pkg", "2.0.0"),
                        ])

    def test_embedded_signature_is_not_removed(self):
        scan = load("pnpm_bom_embedded", "scan.py")
        text = """lockfileVersion: '9.0'
\ufeffpackages:
  ignored@1.0.0:
"""
        self.assertEqual(scan.parse_pnpm_lock(text), [])

    def test_collection_reads_bom_bytes_and_attributes_packages(self):
        scan = load("pnpm_bom_collection", "scan.py")
        with tempfile.TemporaryDirectory() as root:
            path = Path(root, "pnpm-lock.yaml")
            path.write_bytes(
                b"""\xef\xbb\xbfpackages:
  demo@1.2.3:
snapshots:
  outside@3.0.0:
"""
            )
            self.assertEqual(scan.collect_packages(root, list(scan.walk(root))), {
                ("npm", "demo", "1.2.3"): "pnpm-lock.yaml",
            })
        self.assertEqual(scan.PARSED_LOCKFILES, ["pnpm-lock.yaml"])
        self.assertEqual(scan.ERRORS, [])
