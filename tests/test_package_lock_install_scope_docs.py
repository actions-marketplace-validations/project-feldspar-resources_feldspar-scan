"""Package-lock inventory is static, not filtered to an npm install profile."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock


SPEC = importlib.util.spec_from_file_location(
    "scan_package_lock_install_scope_docs", Path(__file__).resolve().parents[1] / "scan.py")
scan = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(scan)


class PackageLockInstallScopeDocsTests(unittest.TestCase):
    def fixture(self, version):
        entries = {
            "runtime-lib": {"version": "1.0.0"},
            "dev-lib": {"version": "2.0.0", "dev": True},
            "optional-lib": {"version": "3.0.0", "optional": True},
            "dev-optional-lib": {"version": "4.0.0", "devOptional": True},
            "platform-lib": {"version": "5.0.0", "os": ["synthetic-os"],
                             "cpu": ["synthetic-cpu"]},
        }
        if version == 1:
            entries["runtime-lib"]["dependencies"] = {
                "nested-dev-lib": {"version": "6.0.0", "dev": True}}
            return {"lockfileVersion": version, "dependencies": entries}
        packages = {"": {"name": "root-project", "version": "9.0.0"}}
        packages.update({"node_modules/" + name: meta for name, meta in entries.items()})
        packages["node_modules/runtime-lib/node_modules/nested-dev-lib"] = {
            "version": "6.0.0", "dev": True}
        return {"lockfileVersion": version, "packages": packages}

    def expected(self):
        return [("npm", name, version) for name, version in (
            ("runtime-lib", "1.0.0"), ("dev-lib", "2.0.0"),
            ("optional-lib", "3.0.0"), ("dev-optional-lib", "4.0.0"),
            ("platform-lib", "5.0.0"), ("nested-dev-lib", "6.0.0"))]

    def report(self, version, *flags):
        with tempfile.TemporaryDirectory() as root:
            Path(root, "package-lock.json").write_text(
                json.dumps(self.fixture(version)), encoding="utf-8")
            output = io.StringIO()
            with mock.patch.object(scan, "query_osv", return_value={}) as query, \
                    mock.patch.object(scan, "http_json", side_effect=AssertionError("network")), \
                    contextlib.redirect_stdout(output):
                status = scan.main(["scan.py", root, "--no-commit", *flags])
        self.assertEqual(status, 0)
        return json.loads(output.getvalue()), query

    def test_v2_and_v3_maps_keep_install_profile_metadata_entries(self):
        for version in (2, 3):
            with self.subTest(version=version):
                actual = scan.parse_package_lock(json.dumps(self.fixture(version)))
                self.assertCountEqual(actual, self.expected())

    def test_v1_tree_keeps_install_profile_metadata_entries(self):
        actual = scan.parse_package_lock(json.dumps(self.fixture(1)))
        self.assertCountEqual(actual, self.expected())

    def test_advisory_query_includes_all_inventory_scopes(self):
        for version in (1, 2, 3):
            with self.subTest(version=version):
                report, query = self.report(version)
                query.assert_called_once()
                self.assertCountEqual(query.call_args.args[0], self.expected())
                self.assertEqual(report["summary"]["packages_found"], 6)
                self.assertEqual(report["summary"]["packages_by_manifest"],
                                 {"package-lock.json": 6})
                self.assertEqual(report["summary"]["lockfiles_parsed"], ["package-lock.json"])

    def test_no_osv_keeps_all_inventory_scopes_without_querying(self):
        for version in (1, 2, 3):
            with self.subTest(version=version):
                report, query = self.report(version, "--no-osv")
                query.assert_not_called()
                self.assertEqual(report["summary"]["packages_found"], 6)
                self.assertEqual(report["summary"]["packages_by_ecosystem"], {"npm": 6})
                self.assertEqual(report["summary"]["vulnerable_packages"], 0)


if __name__ == "__main__":
    unittest.main()
