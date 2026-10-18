"""Offline examples of TOML lockfile source metadata limitations."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from test_scan import scan


FORMATS = {
    'poetry.lock': ('PyPI', (
        """[package.source]
type = "legacy"
url = "https://example.invalid/simple"
""",
        """[package.source]
type = "git"
url = "https://example.invalid/demo.git"
""",
        """[package.source]
type = "directory"
url = "../local-demo"
""",
    )),
    'uv.lock': ('PyPI', (
        'source = { registry = "https://example.invalid/simple" }',
        'source = { git = "https://example.invalid/demo.git" }',
        'source = { editable = "." }',
    )),
    'Cargo.lock': ('crates.io', (
        'source = "registry+https://example.invalid/index"',
        'source = "git+https://example.invalid/demo.git"',
        '',  # Local/workspace package with no source field.
    )),
}


def package(name, version, source):
    return chr(10).join(('[[package]]', 'name = "%s"' % name,
                         'version = "%s"' % version, source, '', ''))


class TomlSourceScopeDocsTests(unittest.TestCase):
    def report(self, filename, content, offline=False):
        with tempfile.TemporaryDirectory() as root:
            Path(root, filename).write_text(content, encoding='utf-8')
            with mock.patch.object(scan, 'http_json', return_value={}) as network, \
                    contextlib.redirect_stdout(io.StringIO()) as output, \
                    contextlib.redirect_stderr(io.StringIO()):
                args = ['scan.py', root, '--fail-on', 'low']
                if offline:
                    args.append('--no-osv')
                status = scan.main(args)
        self.assertEqual(status, 0)
        doc = json.loads(output.getvalue())
        self.assertEqual(doc['summary']['lockfiles_parsed'], [filename])
        self.assertEqual(doc['findings'], [])
        self.assertNotIn('errors', doc)
        return doc, network

    def test_source_metadata_does_not_filter_registry_queries(self):
        for filename, (ecosystem, sources) in FORMATS.items():
            with self.subTest(filename=filename):
                text = ''.join(package('synthetic-%d' % i, '1.0.0', source)
                               for i, source in enumerate(sources))
                doc, network = self.report(filename, text)
                self.assertEqual(doc['summary']['packages_found'], 3)
                network.assert_called_once_with(scan.OSV_BATCH, {'queries': [
                    {'package': {'name': 'synthetic-%d' % i, 'ecosystem': ecosystem},
                     'version': '1.0.0'} for i in range(3)
                ]})

    def test_different_sources_share_one_package_identity(self):
        for filename, (ecosystem, sources) in FORMATS.items():
            with self.subTest(filename=filename):
                text = ''.join(package('synthetic-demo', '1.0.0', source)
                               for source in sources)
                doc, network = self.report(filename, text)
                self.assertEqual(doc['summary']['packages_found'], 1)
                network.assert_called_once_with(scan.OSV_BATCH, {'queries': [
                    {'package': {'name': 'synthetic-demo', 'ecosystem': ecosystem},
                     'version': '1.0.0'}
                ]})

    def test_source_less_entries_and_offline_inventory(self):
        for filename, (ecosystem, sources) in FORMATS.items():
            with self.subTest(filename=filename):
                text = package('synthetic-bare', '1.0.0', '')
                text += package('synthetic-git', '2.0.0', sources[1])
                online, network = self.report(filename, text)
                offline, no_network = self.report(filename, text, offline=True)
                self.assertEqual(online['summary']['packages_found'], 2)
                self.assertEqual(offline['summary']['packages_found'], 2)
                network.assert_called_once_with(scan.OSV_BATCH, {'queries': [
                    {'package': {'name': 'synthetic-bare', 'ecosystem': ecosystem},
                     'version': '1.0.0'},
                    {'package': {'name': 'synthetic-git', 'ecosystem': ecosystem},
                     'version': '2.0.0'}
                ]})
                no_network.assert_not_called()
