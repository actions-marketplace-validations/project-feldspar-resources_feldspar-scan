"""Reject oversized inputs without consuming their whole contents."""
from contextlib import contextmanager
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from test_hardening import load


class ReadTextBoundsTests(unittest.TestCase):
    @contextmanager
    def observe_reads(self, scan, budget):
        real_fdopen = scan.os.fdopen
        sizes = []

        @contextmanager
        def fdopen(fd, *args, **kwargs):
            with real_fdopen(fd, *args, **kwargs) as fh:
                def read(size=-1):
                    self.assertGreater(size, 0, "Content reads must be bounded")
                    sizes.append(size)
                    self.assertLessEqual(sum(sizes), budget)
                    return fh.read(size)

                yield SimpleNamespace(fileno=fh.fileno, read=read)

        with mock.patch.object(scan.os, "fdopen", side_effect=fdopen):
            yield sizes

    def test_oversized_metadata_skips_content_read(self):
        scan = load("read_bounds_metadata_scan", "scan.py")
        with tempfile.TemporaryDirectory() as root:
            path = Path(root, "requirements.txt")
            path.write_bytes(b"x" * 17)
            with self.observe_reads(scan, budget=0) as sizes:
                self.assertIsNone(scan.read_text(path, limit=16))
            self.assertEqual(sizes, [])

    def test_stale_size_still_bounds_reads_and_rejects_growth(self):
        scan = load("read_bounds_growth_scan", "scan.py")
        limit = 16
        with tempfile.TemporaryDirectory() as root:
            path = Path(root, "requirements.txt")
            for size in (limit, limit + 1, limit * 100):
                with self.subTest(size=size):
                    path.write_bytes(b"x" * size)
                    stale = SimpleNamespace(st_mode=path.stat().st_mode, st_size=limit)
                    with mock.patch.object(scan.os, "fstat", return_value=stale), \
                         self.observe_reads(scan, budget=limit + 1) as sizes:
                        result = scan.read_text(path, limit=limit)
                    self.assertTrue(sizes, "Accepted metadata must lead to a content read")
                    if size == limit:
                        self.assertEqual(result, "x" * limit)
                    else:
                        self.assertIsNone(result)


if __name__ == "__main__":
    unittest.main()
