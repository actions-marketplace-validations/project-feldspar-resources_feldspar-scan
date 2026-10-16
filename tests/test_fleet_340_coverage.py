"""Regression coverage extracted without editing baseline test files."""
import os
import tempfile
import unittest
from unittest import mock

from test_hardening import load


class InputHandlingCoverageTests(unittest.TestCase):
    def test_read_text_preserves_utf8_and_falls_back_for_invalid_sequences(self):
        scan = load("hardening_scan_encoding", "scan.py")
        cases = [
            (b"", ""),
            (b"caf\xc3\xa9 \xf0\x9f\x8c\x8d\x0a", "caf\u00e9 \U0001f30d\x0a"),
            (b"caf\xe9\x0a", "caf\u00e9\x0a"),
            (b"truncated \xe2\x82", "truncated \u00e2\u0082"),
        ]
        with tempfile.TemporaryDirectory() as root:
            path = os.path.join(root, "input.txt")
            for raw, expected in cases:
                with self.subTest(raw=raw):
                    with open(path, "wb") as fh:
                        fh.write(raw)
                    self.assertEqual(scan.read_text(path), expected)

    def test_read_text_skips_nul_at_any_position(self):
        scan = load("hardening_scan_nul", "scan.py")
        with tempfile.TemporaryDirectory() as root:
            path = os.path.join(root, "input.txt")
            for raw in (b"\x00demo", b"de\x00mo", b"demo\x00", b"\xff\x00"):
                with self.subTest(raw=raw):
                    with open(path, "wb") as fh:
                        fh.write(raw)
                    self.assertIsNone(scan.read_text(path))

    def test_collect_packages_skips_binary_and_keeps_latin1_manifest(self):
        scan = load("hardening_scan_manifest_encoding", "scan.py")
        with tempfile.TemporaryDirectory() as root:
            binary = os.path.join(root, "requirements-binary.txt")
            latin1 = os.path.join(root, "requirements-latin1.txt")
            with open(binary, "wb") as fh:
                fh.write(b"ignored-demo==9.9\x0a\x00")
            with open(latin1, "wb") as fh:
                fh.write(b"# caf\xe9\x0akept-demo==1.2.3\x0a")
            self.assertEqual(scan.collect_packages(root, [binary, latin1]), {
                ("PyPI", "kept-demo", "1.2.3"): "requirements-latin1.txt"})
            self.assertEqual(scan.PARSED_LOCKFILES, ["requirements-latin1.txt"])
            self.assertEqual(scan.ERRORS, [])
