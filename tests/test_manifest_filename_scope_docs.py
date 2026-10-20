"""Document filename-based inventory discovery using offline fixtures."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from test_scan import scan


NPM_LOCK = json.dumps({"lockfileVersion": 3, "packages": {
    "node_modules/synthetic-package": {"version": "1.2.3"}}})
UNSUPPORTED = {
    "npm-shrinkwrap.json": NPM_LOCK,
    "package.json": json.dumps({"dependencies": {"synthetic-package": "1.2.3"}}),
    "Pipfile.lock": json.dumps({"default": {"synthetic-package": {"version": "==1.2.3"}}}),
    "pyproject.toml": '''[project]
name = "synthetic-project"
dependencies = ["synthetic-package==1.2.3"]
''',
    "composer.lock": json.dumps({"packages": [{"name": "synthetic/package", "version": "1.2.3"}]}),
    "Package-lock.json": NPM_LOCK,
    "package-lock.json.bak": NPM_LOCK,
    "Requirements.txt": "synthetic-package==1.2.3" + chr(10),
    "requirements-dev.TXT": "synthetic-package==1.2.3" + chr(10),
}


class ManifestFilenameScopeDocsTests(unittest.TestCase):
    def report(self, root, *flags):
        with contextlib.redirect_stdout(io.StringIO()) as output:
            status = scan.main(['scan.py', str(root), *flags])
        self.assertEqual(status, 0)
        return json.loads(output.getvalue())

    def test_basename_matching_is_exact_with_requirements_exception(self):
        with tempfile.TemporaryDirectory() as root:
            for name, content in UNSUPPORTED.items():
                path = Path(root, 'nested', name)
                path.parent.mkdir(exist_ok=True)
                path.write_text(content, encoding='utf-8')
            for name, content, expected in (
                ('package-lock.json', NPM_LOCK, ('npm', 'synthetic-package', '1.2.3')),
                ('requirements-dev.txt', 'synthetic-package==1.2.3' + chr(10),
                 ('PyPI', 'synthetic-package', '1.2.3')),
            ):
                path = Path(root, 'nested', name)
                path.write_text(content, encoding='utf-8')
                with self.subTest(name=name), \
                        mock.patch.object(scan, 'PARSED_LOCKFILES', []), \
                        mock.patch.object(scan, 'ERRORS', []):
                    ignored = [str(Path(root, 'nested', n)) for n in UNSUPPORTED]
                    packages = scan.collect_packages(root, ignored + [str(path)])
                    self.assertEqual(packages, {expected: 'nested/' + name})
                    self.assertEqual(scan.PARSED_LOCKFILES, ['nested/' + name])
                    self.assertEqual(scan.ERRORS, [])

    def test_unsupported_only_files_do_not_supply_inventory_or_advisory_requests(self):
        for flags in ((), ('--no-osv',)):
            with self.subTest(flags=flags), tempfile.TemporaryDirectory() as root:
                for name, content in UNSUPPORTED.items():
                    Path(root, name).write_text(content, encoding='utf-8')
                with mock.patch.object(scan, 'http_json', side_effect=AssertionError('offline')) as http:
                    report = self.report(root, *flags)
                http.assert_not_called()
                self.assertEqual(report['summary']['packages_found'], 0)
                self.assertEqual(report['summary']['lockfiles_parsed'], [])
                self.assertEqual(report['summary']['by_category']['dependency-vuln'], 0)
                self.assertTrue(any('No supported dependency manifest was parsed' in note
                                    for note in report['summary']['notes']))

    def test_mixed_tree_queries_only_recognized_manifest_inventory(self):
        with tempfile.TemporaryDirectory() as root:
            for name, content in UNSUPPORTED.items():
                Path(root, name).write_text(content, encoding='utf-8')
            Path(root, 'requirements-prod.txt').write_text('supported-package==2.0' + chr(10), encoding='utf-8')
            with mock.patch.object(scan, 'query_osv', return_value={}) as query, \
                    mock.patch.object(scan, 'http_json', side_effect=AssertionError('offline')):
                report = self.report(root)
            query.assert_called_once()
            self.assertEqual(query.call_args.args[0], [
                ('PyPI', 'supported-package', '2.0')])
            self.assertEqual(report['summary']['packages_found'], 1)
            self.assertEqual(report['summary']['lockfiles_parsed'], ['requirements-prod.txt'])


if __name__ == '__main__':
    unittest.main()
