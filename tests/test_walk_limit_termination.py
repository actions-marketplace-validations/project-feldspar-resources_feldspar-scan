"""The regular-file allowance must terminate traversal, not just trim its output."""
import os
import stat
import unittest
from types import SimpleNamespace
from unittest import mock

from test_hardening import load


class WalkLimitTerminationTests(unittest.TestCase):
    def check_limit(self, prefix):
        scan = load("walk_limit_scan", "scan.py")
        root = "synthetic-root"
        visited = []

        def directories(walk_root):
            self.assertEqual(walk_root, root)
            # Deliberately unsorted: the skipped prefix must precede b.txt.
            yield root, [], ["z.txt", "b.txt"] + prefix
            self.fail("walker requested another directory after reaching its limit")

        def lstat(path):
            name = os.path.basename(path)
            visited.append(name)
            if name == "a-missing.txt":
                raise FileNotFoundError(path)
            if name == "a-link.txt":
                return SimpleNamespace(st_mode=stat.S_IFLNK)
            if name != "b.txt":
                self.fail("walker inspected an entry after reaching its limit")
            return SimpleNamespace(st_mode=stat.S_IFREG)

        skipped = {"non_regular": 0}
        with mock.patch.object(scan.os, "walk", side_effect=directories), mock.patch.object(
                scan.os, "lstat", side_effect=lstat):
            result = list(scan.walk(root, skipped, max_files=1))
        self.assertEqual(result, [os.path.join(root, "b.txt")])
        self.assertEqual(visited, sorted(prefix) + ["b.txt"])
        self.assertEqual(skipped, {"non_regular": len(prefix)})

    def test_limit_stops_before_later_entries_and_directories(self):
        self.check_limit([])

    def test_skipped_entries_do_not_consume_regular_file_allowance(self):
        self.check_limit(["a-missing.txt", "a-link.txt"])
