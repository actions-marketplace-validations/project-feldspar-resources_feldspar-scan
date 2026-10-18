"""Pin the documented, directory-local go.sum selection rule without network I/O."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock


SPEC = importlib.util.spec_from_file_location(
    "scan_go_sum_fallback_docs", Path(__file__).resolve().parents[1] / "scan.py")
scan = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(scan)


class GoSumFallbackDocsTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def write(self, path, text):
        destination = self.root / path
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(text, encoding="utf-8")

    def report(self):
        output = io.StringIO()
        with mock.patch.object(scan, "query_osv", return_value={}) as query, \
                mock.patch.object(scan, "http_json", side_effect=AssertionError("network")), \
                contextlib.redirect_stdout(output):
            status = scan.main(["scan.py", str(self.root), "--no-commit"])
        self.assertEqual(status, 0)
        return json.loads(output.getvalue()), query

    def test_empty_or_unrecognized_go_mod_does_not_fall_back(self):
        self.write("go.sum", "example.invalid/stale v1.0.0 h1:synthetic=" + chr(10))
        for text in ("", "module example.invalid/app" + chr(10), "unsupported content" + chr(10)):
            with self.subTest(text=text):
                self.write("go.mod", text)
                report, query = self.report()
                self.assertEqual(report["summary"]["packages_found"], 0)
                self.assertEqual(report["summary"]["lockfiles_parsed"], ["go.mod"])
                query.assert_not_called()

    def test_unreadable_selected_go_mod_does_not_fall_back(self):
        self.write("go.mod", "require example.invalid/current v2.0.0" + chr(10))
        self.write("go.sum", "example.invalid/stale v1.0.0 h1:synthetic=" + chr(10))
        original_read = scan.read_text

        def read_without_go_mod(path, *args, **kwargs):
            if Path(path).name == "go.mod":
                return None
            return original_read(path, *args, **kwargs)

        with mock.patch.object(scan, "read_text", side_effect=read_without_go_mod):
            report, query = self.report()
        self.assertEqual(report["summary"]["packages_found"], 0)
        self.assertEqual(report["summary"]["lockfiles_parsed"], [])
        query.assert_not_called()

    def test_go_mod_suppression_is_directory_local(self):
        self.write("go.mod", "module example.invalid/app" + chr(10))
        self.write("go.sum", "example.invalid/stale v1.0.0 h1:synthetic=" + chr(10))
        self.write("child/go.sum", "example.invalid/child v3.0.0 h1:synthetic=" + chr(10))
        report, query = self.report()
        self.assertEqual(report["summary"]["packages_found"], 1)
        self.assertEqual(report["summary"]["lockfiles_parsed"], ["child/go.sum", "go.mod"])
        query.assert_called_once_with([("Go", "example.invalid/child", "v3.0.0")])

    def test_go_mod_outside_selected_file_list_does_not_suppress(self):
        self.write("go.mod", "require example.invalid/current v2.0.0" + chr(10))
        self.write("go.sum", "example.invalid/stale v1.0.0 h1:synthetic=" + chr(10))
        scan.PARSED_LOCKFILES.clear()
        self.addCleanup(scan.PARSED_LOCKFILES.clear)
        packages = scan.collect_packages(str(self.root), [str(self.root / "go.sum")])
        self.assertEqual(packages, {("Go", "example.invalid/stale", "v1.0.0"): "go.sum"})
        self.assertEqual(scan.PARSED_LOCKFILES, ["go.sum"])
