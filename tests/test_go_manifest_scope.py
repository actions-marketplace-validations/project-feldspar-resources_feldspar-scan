"""Pin directory-local Go manifest precedence, including empty build lists."""
import os
import tempfile
import unittest

from test_hardening import load


class GoManifestScopeTests(unittest.TestCase):
    def collect(self, contents, reverse=False):
        scan = load("go_manifest_scope_scan", "scan.py")
        with tempfile.TemporaryDirectory() as root:
            for rel, text in contents.items():
                path = os.path.join(root, rel)
                os.makedirs(os.path.dirname(path), exist_ok=True)
                with open(path, "w", encoding="utf-8") as fh:
                    fh.write(text)
            files = sorted(scan.walk(root), reverse=reverse)
            packages = scan.collect_packages(root, files)
        self.assertEqual(scan.ERRORS, [])
        return packages, sorted(scan.PARSED_LOCKFILES)

    def test_parent_go_mod_does_not_suppress_child_or_sibling_go_sum(self):
        contents = {
            "app/go.mod": """require example.com/current v2.0.0
""",
            "app/go.sum": """example.com/obsolete v1.0.0 h1:fixture=
""",
            "app/child/go.sum": """example.com/child v3.0.0 h1:fixture=
""",
            "other/go.sum": """example.com/other v4.0.0 h1:fixture=
""",
        }
        expected = {
            ("Go", "example.com/current", "v2.0.0"): "app/go.mod",
            ("Go", "example.com/child", "v3.0.0"): "app/child/go.sum",
            ("Go", "example.com/other", "v4.0.0"): "other/go.sum",
        }
        for reverse in (False, True):
            with self.subTest(reverse=reverse):
                self.assertEqual(self.collect(contents, reverse), (
                    expected, ["app/child/go.sum", "app/go.mod", "other/go.sum"]))

    def test_child_go_mod_does_not_suppress_parent_go_sum(self):
        contents = {
            "go.sum": """example.com/parent v1.0.0 h1:fixture=
""",
            "child/go.mod": """require example.com/current v2.0.0
""",
            "child/go.sum": """example.com/obsolete v0.1.0 h1:fixture=
""",
        }
        expected = {
            ("Go", "example.com/parent", "v1.0.0"): "go.sum",
            ("Go", "example.com/current", "v2.0.0"): "child/go.mod",
        }
        for reverse in (False, True):
            with self.subTest(reverse=reverse):
                self.assertEqual(self.collect(contents, reverse), (
                    expected, ["child/go.mod", "go.sum"]))

    def test_empty_or_truncated_go_mod_does_not_restore_historical_versions(self):
        # Presence of a sibling go.mod controls precedence, even with no parsed
        # requirements. Falling back would mislabel historical checksums as a
        # current build list. This pins inventory policy, not Go syntax validity.
        for text in ("", """module example.com/app
go 1.22
""",
                     """require (
example.com/truncated
"""):
            for reverse in (False, True):
                with self.subTest(text=text, reverse=reverse):
                    contents = {
                        "app/go.mod": text,
                        "app/go.sum": """example.com/obsolete v1.0.0 h1:fixture=
""",
                        "other/go.sum": """example.com/other v2.0.0 h1:fixture=
""",
                    }
                    self.assertEqual(self.collect(contents, reverse), (
                        {("Go", "example.com/other", "v2.0.0"): "other/go.sum"},
                        ["app/go.mod", "other/go.sum"]))
