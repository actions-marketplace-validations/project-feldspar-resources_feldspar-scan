"""Content read failures must close files and leave healthy manifests usable."""
from contextlib import contextmanager
import errno
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from test_hardening import load


class ManifestReadErrorTests(unittest.TestCase):
    @contextmanager
    def fail_first_read(self, scan):
        real_fdopen = scan.os.fdopen
        failed_files = []

        @contextmanager
        def fdopen(fd, *args, **kwargs):
            with real_fdopen(fd, *args, **kwargs) as fh:
                if not failed_files:
                    failed_files.append(fh)
                    reader = mock.Mock(wraps=fh)
                    reader.read.side_effect = OSError(errno.EIO, "synthetic content read failure")
                    yield reader
                else:
                    yield fh

        with mock.patch.object(scan.os, "fdopen", side_effect=fdopen):
            yield failed_files

    def test_content_error_skips_file_and_closes_descriptor(self):
        scan = load("manifest_content_error", "scan.py")
        with tempfile.TemporaryDirectory() as root:
            path = Path(root, "requirements.txt")
            path.write_text("demo==1.2.3", encoding="utf-8")
            with self.fail_first_read(scan) as failed_files:
                self.assertIsNone(scan.read_text(str(path)))
            self.assertEqual(len(failed_files), 1)
            self.assertTrue(failed_files[0].closed)
            self.assertEqual(scan.read_text(str(path)), "demo==1.2.3")

    def test_content_error_preserves_later_manifest_inventory(self):
        scan = load("manifest_content_recovery", "scan.py")
        with tempfile.TemporaryDirectory() as root:
            damaged = Path(root, "requirements-a.txt")
            healthy = Path(root, "requirements-b.txt")
            damaged.write_text("lost-demo==1.2.3", encoding="utf-8")
            healthy.write_text("kept-demo==4.5.6", encoding="utf-8")
            with self.fail_first_read(scan) as failed_files:
                self.assertEqual(scan.collect_packages(root, [str(damaged), str(healthy)]), {
                    ("PyPI", "kept-demo", "4.5.6"): "requirements-b.txt"})
            self.assertEqual(len(failed_files), 1)
            self.assertTrue(failed_files[0].closed)
            self.assertEqual(scan.PARSED_LOCKFILES, ["requirements-b.txt"])
            self.assertEqual(scan.ERRORS, [])
