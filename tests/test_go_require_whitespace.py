"""Regression coverage for whitespace in single-line go.mod requirements."""
import unittest

from test_scan import scan


class GoRequireWhitespaceTests(unittest.TestCase):
    def test_single_require_whitespace(self):
        for separator in (" ", "\t", "\t ", " \t"):
            with self.subTest(separator=separator):
                text = f"""module example.com/app
require{separator}example.com/direct\tv1.2.3
require{separator}example.com/indirect v2.3.4 // indirect
"""
                self.assertEqual(scan.parse_go_mod(text),
                                 [("Go", "example.com/direct", "v1.2.3"),
                                  ("Go", "example.com/indirect", "v2.3.4")])

    def test_tabbed_require_skips_incomplete_and_extra_fields(self):
        text = """require\texample.com/missing-version
require\texample.com/extra v1.2.3 unexpected
requirement\texample.com/wrong-directive v1.2.3
exclude\texample.com/excluded v1.2.3
require\texample.com/good\tv2.3.4 // indirect
"""
        self.assertEqual(scan.parse_go_mod(text),
                         [("Go", "example.com/good", "v2.3.4")])
