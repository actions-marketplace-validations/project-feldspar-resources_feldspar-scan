"""A UTF-8 signature must not alter requirements package names or options."""
from pathlib import Path
import tempfile
import unittest

from test_hardening import load


class RequirementsBOMTests(unittest.TestCase):
    def test_leading_bom_preserves_first_pin_and_later_lines(self):
        scan = load("requirements_bom_pins", "scan.py")
        for first in ("demo==1.2.3", "demo[extra]==1.2.3", "  demo==1.2.3"):
            with self.subTest(first=first):
                text = chr(10).join((first, "later-demo==4.5.6"))
                expected = [("PyPI", "demo", "1.2.3"),
                            ("PyPI", "later-demo", "4.5.6")]
                self.assertEqual(scan.parse_requirements(text), expected)
                self.assertEqual(scan.parse_requirements(chr(0xfeff) + text), expected)

    def test_leading_bom_does_not_turn_options_into_packages(self):
        scan = load("requirements_bom_options", "scan.py")
        for first in ("-r requirements==9.9", "--constraint=constraints==9.9",
                      "  --editable=local-project==9.9", "# comment-demo==9.9", ""):
            with self.subTest(first=first):
                text = chr(0xfeff) + chr(10).join((first, "kept-demo==1.2.3"))
                self.assertEqual(scan.parse_requirements(text),
                                 [("PyPI", "kept-demo", "1.2.3")])
        self.assertEqual(scan.parse_requirements(chr(0xfeff)), [])

    def test_bom_files_deduplicate_with_plain_requirements(self):
        scan = load("requirements_bom_collection", "scan.py")
        with tempfile.TemporaryDirectory() as root:
            names = ("requirements.txt", "requirements-dev.txt")
            for name in names:
                Path(root, name).write_bytes("demo==1.2.3".encode("utf-8-sig"))
            plain = Path(root, "requirements-plain.txt")
            plain.write_text("demo==1.2.3", encoding="utf-8")
            files = [str(Path(root, name)) for name in names] + [str(plain)]
            self.assertEqual(scan.collect_packages(root, files), {
                ("PyPI", "demo", "1.2.3"): "requirements.txt"})
            self.assertEqual(scan.PARSED_LOCKFILES, [*names, plain.name])
            self.assertEqual(scan.ERRORS, [])
