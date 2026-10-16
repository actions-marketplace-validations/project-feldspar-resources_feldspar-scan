"""Offline end-to-end examples of the documented Gemfile source limits."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from test_scan import scan


GIT_SECTION = """GIT
  remote: https://example.invalid/synthetic.git
  specs:
    synthetic-git (1.0.0)

"""
PATH_SECTION = """PATH
  remote: ../synthetic-local
  specs:
    synthetic-local (2.0.0)

"""
GEM_SECTION = """GEM
  remote: https://example.invalid/gems/
  specs:
    synthetic-registry (3.0.0)
      synthetic-transitive (>= 1.0)
    synthetic-transitive (1.2.0)

"""


class GemfileSourceDocsTests(unittest.TestCase):
    def report(self, text):
        output = io.StringIO()
        with tempfile.TemporaryDirectory() as root:
            Path(root, 'Gemfile.lock').write_text(text, encoding='utf-8')
            with mock.patch.object(scan, 'http_json', return_value={
                    'results': [{}, {}]}) as network, \
                    contextlib.redirect_stdout(output), \
                    contextlib.redirect_stderr(io.StringIO()):
                status = scan.main(['scan.py', root, '--fail-on', 'low'])
        self.assertEqual(status, 0)
        doc = json.loads(output.getvalue())
        self.assertEqual(doc['summary']['lockfiles_parsed'], ['Gemfile.lock'])
        self.assertTrue(doc['summary']['osv_enabled'])
        self.assertEqual(doc['findings'], [])
        self.assertNotIn('errors', doc)
        return doc, network

    def test_only_gem_specs_enter_advisory_query(self):
        # Include non-registry sections on both sides to pin section isolation.
        for text in (GIT_SECTION + GEM_SECTION + PATH_SECTION,
                     PATH_SECTION + GEM_SECTION + GIT_SECTION):
            with self.subTest(text=text):
                doc, network = self.report(text)
                self.assertEqual(doc['summary']['packages_found'], 2)
                network.assert_called_once_with(scan.OSV_BATCH, {'queries': [
                    {'package': {'name': 'synthetic-registry',
                                 'ecosystem': 'RubyGems'}, 'version': '3.0.0'},
                    {'package': {'name': 'synthetic-transitive',
                                 'ecosystem': 'RubyGems'}, 'version': '1.2.0'},
                ]})

    def test_git_and_path_only_still_list_manifest_without_queries(self):
        for text in (GIT_SECTION, PATH_SECTION, GIT_SECTION + PATH_SECTION):
            with self.subTest(text=text):
                doc, network = self.report(text)
                self.assertEqual(doc['summary']['packages_found'], 0)
                self.assertEqual(doc['summary']['vulnerable_packages'], 0)
                network.assert_not_called()
