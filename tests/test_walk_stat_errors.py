"""Traversal continues when an entry cannot be statted after enumeration."""
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from test_hardening import load


class WalkStatErrorTests(unittest.TestCase):
    def test_file_stat_errors_preserve_healthy_files_and_cap(self):
        scan = load("walk_file_stat_errors", "scan.py")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for name in ("a-missing.txt", "b-denied.txt", "c-good.txt", "d-good.txt"):
                (root / name).write_text("content", encoding="utf-8")
            real_lstat = os.lstat

            def lstat(path, *args, **kwargs):
                if Path(path).name == "a-missing.txt":
                    raise FileNotFoundError("entry disappeared")
                if Path(path).name == "b-denied.txt":
                    raise PermissionError("entry inaccessible")
                return real_lstat(path, *args, **kwargs)

            for cap, expected in ((None, ["c-good.txt", "d-good.txt"]),
                                  (1, ["c-good.txt"])):
                for count_skips in (False, True):
                    with self.subTest(cap=cap, count_skips=count_skips):
                        skipped = {"non_regular": 0} if count_skips else None
                        with mock.patch.object(scan.os, "lstat", side_effect=lstat):
                            paths = list(scan.walk(str(root), skipped, max_files=cap))
                        self.assertEqual([Path(p).name for p in paths], expected)
                        if count_skips:
                            self.assertEqual(skipped, {"non_regular": 2})

    def test_directory_stat_errors_prune_only_failed_subtrees(self):
        scan = load("walk_directory_stat_errors", "scan.py")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for name in ("a-missing", "b-denied", "c-good"):
                (root / name).mkdir()
                (root / name / "requirements.txt").write_text(
                    "demo==1.0", encoding="utf-8")
            (root / "root.txt").write_text("content", encoding="utf-8")
            real_lstat = os.lstat

            def lstat(path, *args, **kwargs):
                if Path(path) == root / "a-missing":
                    raise FileNotFoundError("directory disappeared")
                if Path(path) == root / "b-denied":
                    raise PermissionError("directory inaccessible")
                return real_lstat(path, *args, **kwargs)

            for count_skips in (False, True):
                with self.subTest(count_skips=count_skips):
                    skipped = {"non_regular": 0} if count_skips else None
                    with mock.patch.object(scan.os, "lstat", side_effect=lstat):
                        paths = list(scan.walk(str(root), skipped))
                    self.assertEqual(
                        [Path(p).relative_to(root).as_posix() for p in paths],
                        ["root.txt", "c-good/requirements.txt"])
                    if count_skips:
                        self.assertEqual(skipped, {"non_regular": 2})
