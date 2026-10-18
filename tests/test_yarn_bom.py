"""A UTF-8 signature must not change Yarn package identities."""
from pathlib import Path
import tempfile
import unittest

from test_hardening import load


class YarnBomTests(unittest.TestCase):
    def test_leading_bom_preserves_first_descriptor_and_neighbors(self):
        scan = load("yarn_bom_parser", "scan.py")
        for header in (
                'first@^1.0:', '"first@^1.0":',
                '"first@npm:^1.0":', '"@scope/first@npm:^1.0":',
                '"first@^1.0", "first@~1.0":'):
            for newline in (chr(10), chr(13) + chr(10)):
                with self.subTest(header=header, newline=repr(newline)):
                    name = "@scope/first" if "@scope/" in header else "first"
                    text = newline.join([
                        header, '  version "1.0.2"',
                        'second@^2.0:', '  version "2.0.3"', ''])
                    expected = [("npm", name, "1.0.2"), ("npm", "second", "2.0.3")]
                    self.assertEqual(scan.parse_yarn_lock(text), expected)
                    self.assertEqual(scan.parse_yarn_lock(chr(0xfeff) + text), expected)

    def test_bom_encoded_file_retains_collection_attribution(self):
        scan = load("yarn_bom_collection", "scan.py")
        text = chr(10).join(['"@scope/first@npm:^1.0":', '  version: 1.0.2', ''])
        with tempfile.TemporaryDirectory() as root:
            path = Path(root, "yarn.lock")
            path.write_text(text, encoding="utf-8-sig")
            self.assertEqual(scan.collect_packages(root, [str(path)]), {
                ("npm", "@scope/first", "1.0.2"): "yarn.lock",
            })
            self.assertEqual(scan.PARSED_LOCKFILES, ["yarn.lock"])
            self.assertEqual(scan.ERRORS, [])

    def test_bom_before_comment_metadata_or_empty_file_is_harmless(self):
        scan = load("yarn_bom_preamble", "scan.py")
        for preamble in ('', '# yarn lockfile v1', '__metadata:' + chr(10) + '  version: 8'):
            with self.subTest(preamble=preamble):
                self.assertEqual(scan.parse_yarn_lock(chr(0xfeff) + preamble), [])
                text = chr(10).join([
                    preamble, '"first@npm:^1.0":', '  version: 1.0.2', ''])
                self.assertEqual(scan.parse_yarn_lock(chr(0xfeff) + text), [
                    ("npm", "first", "1.0.2"),
                ])
