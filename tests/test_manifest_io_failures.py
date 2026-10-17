"""File changes and metadata I/O errors must not abort manifest collection."""
import errno
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from test_hardening import load


class ManifestIOFailureTests(unittest.TestCase):
    def test_changed_manifest_is_skipped_after_discovery(self):
        for replacement in ("missing", "directory"):
            with self.subTest(replacement=replacement), tempfile.TemporaryDirectory() as root:
                scan = load("manifest_io_scan", "scan.py")
                changed = Path(root, "requirements-a.txt")
                healthy = Path(root, "requirements-b.txt")
                changed.write_text("lost-demo==1.2.3")
                healthy.write_text("kept-demo==4.5.6")
                files = list(scan.walk(root))
                self.assertEqual(files, [str(changed), str(healthy)])
                changed.unlink()
                if replacement == "directory":
                    changed.mkdir()
                self.assertIsNone(scan.read_text(str(changed)))
                self.assertEqual(scan.collect_packages(root, files), {
                    ("PyPI", "kept-demo", "4.5.6"): "requirements-b.txt"})
                self.assertEqual(scan.PARSED_LOCKFILES, ["requirements-b.txt"])
                self.assertEqual(scan.ERRORS, [])

    def test_metadata_error_closes_opened_descriptor(self):
        scan = load("manifest_stat_error_scan", "scan.py")
        with tempfile.TemporaryDirectory() as root:
            path = Path(root, "requirements.txt")
            path.write_text("demo==1.2.3")
            descriptors = []

            def fail_stat(fd):
                descriptors.append(fd)
                raise OSError(errno.EIO, "synthetic metadata read failure")

            with mock.patch.object(scan.os, "fstat", side_effect=fail_stat):
                self.assertIsNone(scan.read_text(str(path)))
            self.assertEqual(len(descriptors), 1)
            with self.assertRaises(OSError) as caught:
                os.fstat(descriptors[0])
            self.assertEqual(caught.exception.errno, errno.EBADF)
            self.assertEqual(scan.read_text(str(path)), "demo==1.2.3")
