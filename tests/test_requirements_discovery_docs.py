"""Documented requirements discovery, using synthetic pins and no network."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from test_scan import scan


class RequirementsDiscoveryDocsTests(unittest.TestCase):
    def report(self, files, offline=False):
        with tempfile.TemporaryDirectory() as root:
            for name, content in files.items():
                path = Path(root, name)
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content, encoding="utf-8")
            stdout = io.StringIO()
            with mock.patch.object(scan, "query_osv", return_value={}) as query, \
                    mock.patch.object(scan, "git_head", return_value=None), \
                    contextlib.redirect_stdout(stdout):
                args = ["scan.py", root]
                if offline:
                    args.append("--no-osv")
                self.assertEqual(scan.main(args), 0)
            return json.loads(stdout.getvalue()), query

    def test_basename_matching_is_case_sensitive_at_each_depth(self):
        accepted = ["requirements.txt", "nested/requirements-dev.txt",
                    "nested/deeper/requirements_extra.txt", "requirementsprod.txt"]
        excluded = ["Requirements.txt", "requirements.TXT", "requirements.in",
                    "constraints.txt", "nested/base.txt", "myrequirements.txt"]
        files = {name: chr(10).join(['demo%d==1.0', '']) % n
                 for n, name in enumerate(accepted + excluded)}
        report, query = self.report(files)
        self.assertEqual(report["summary"]["lockfiles_parsed"], sorted(accepted))
        self.assertEqual(report["summary"]["packages_found"], len(accepted))
        query.assert_called_once()
        self.assertEqual(set(query.call_args.args[0]),
                         {("PyPI", "demo%d" % n, "1.0") for n in range(4)})
        self.assertEqual(report["findings"], [])

    def test_include_and_constraint_targets_are_not_followed(self):
        for directive in ("-r base.txt", "--requirement base.txt",
                          "--requirement=base.txt", "-c base.txt",
                          "--constraint base.txt", "--constraint=base.txt"):
            with self.subTest(directive=directive):
                report, query = self.report({
                    "requirements.txt": directive + chr(10).join(['', 'rootdemo==1.0', '']),
                    "base.txt": chr(10).join(['includeddemo==2.0', '']),
                })
                query.assert_called_once_with([("PyPI", "rootdemo", "1.0")])
                self.assertEqual(report["summary"]["lockfiles_parsed"],
                                 ["requirements.txt"])
                self.assertEqual(report["summary"]["packages_found"], 1)

    def test_matching_files_are_discovered_without_following_directives(self):
        for directive in ("", chr(10).join(['-r nested/requirements-dev.txt', '']),
                          chr(10).join(['-c nested/requirements-dev.txt', ''])):
            with self.subTest(directive=directive):
                report, query = self.report({
                    "requirements.txt": directive + chr(10).join(['rootdemo==1.0', '']),
                    "nested/requirements-dev.txt": chr(10).join(['devdemo==2.0', '']),
                    "vendor/requirements.txt": chr(10).join(['excludeddemo==3.0', '']),
                }, offline=True)
                query.assert_not_called()
                self.assertEqual(report["summary"]["lockfiles_parsed"],
                                 ["nested/requirements-dev.txt", "requirements.txt"])
                self.assertEqual(report["summary"]["packages_found"], 2)
                self.assertEqual(report["summary"]["packages_by_manifest"],
                                 {"nested/requirements-dev.txt": 1, "requirements.txt": 1})

    def test_directive_only_manifest_can_report_zero_packages(self):
        report, query = self.report({
            "requirements.txt": chr(10).join(['-r base.txt', '-c constraints.txt', '']),
            "base.txt": chr(10).join(['includeddemo==2.0', '']),
            "constraints.txt": chr(10).join(['constraintdemo==3.0', '']),
        })
        query.assert_not_called()
        self.assertEqual(report["summary"]["lockfiles_parsed"], ["requirements.txt"])
        self.assertEqual(report["summary"]["packages_found"], 0)
        self.assertEqual(report["findings"], [])
