"""Offline examples of literal Gemfile versions and platform-independent inventory."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from test_scan import scan


SPECS = """GEM
  remote: https://example.invalid/gems/
  specs:
    synthetic-native (1.2.3)
    synthetic-native (1.2.3-x86_64-linux)
    synthetic-native (1.2.3-arm64-darwin)
    synthetic-support (2.0.0)
      synthetic-native (>= 1.0)

"""
METADATA = """PLATFORMS
  ruby

DEPENDENCIES
  synthetic-native

BUNDLED WITH
   2.6.0
"""
EXPECTED = [
    ('RubyGems', 'synthetic-native', '1.2.3'),
    ('RubyGems', 'synthetic-native', '1.2.3-x86_64-linux'),
    ('RubyGems', 'synthetic-native', '1.2.3-arm64-darwin'),
    ('RubyGems', 'synthetic-support', '2.0.0'),
]


class GemfilePlatformScopeDocsTests(unittest.TestCase):
    def report(self, text, *flags):
        output = io.StringIO()
        with tempfile.TemporaryDirectory() as root:
            Path(root, 'Gemfile.lock').write_text(text, encoding='utf-8')
            with mock.patch.object(scan, 'http_json', return_value={
                    'results': [{} for _ in EXPECTED]}) as network, \
                    contextlib.redirect_stdout(output), \
                    contextlib.redirect_stderr(io.StringIO()):
                status = scan.main(['scan.py', root, '--fail-on', 'low', *flags])
        self.assertEqual(status, 0)
        report = json.loads(output.getvalue())
        self.assertEqual(report['summary']['lockfiles_parsed'], ['Gemfile.lock'])
        self.assertEqual(report['findings'], [])
        self.assertNotIn('errors', report)
        return report, network

    def test_literal_versions_are_queried_without_platform_filtering(self):
        for metadata in (METADATA, METADATA.replace('  ruby', '  arm64-darwin')):
            with self.subTest(metadata=metadata):
                text = SPECS + metadata
                self.assertEqual(scan.parse_gemfile_lock(text), EXPECTED)
                report, network = self.report(text)
                self.assertEqual(report['summary']['packages_found'], 4)
                self.assertEqual(report['summary']['packages_by_ecosystem'], {'RubyGems': 4})
                network.assert_called_once_with(scan.OSV_BATCH, {'queries': [
                    {'package': {'name': name, 'ecosystem': ecosystem}, 'version': version}
                    for ecosystem, name, version in EXPECTED
                ]})

    def test_offline_inventory_retains_all_variants(self):
        report, network = self.report(SPECS + METADATA, '--no-osv')
        self.assertEqual(report['summary']['packages_found'], 4)
        self.assertEqual(report['summary']['packages_by_manifest'], {'Gemfile.lock': 4})
        self.assertFalse(report['summary']['osv_enabled'])
        network.assert_not_called()

    def test_metadata_alone_supplies_no_package_versions(self):
        self.assertEqual(scan.parse_gemfile_lock(METADATA), [])
        report, network = self.report(METADATA)
        self.assertEqual(report['summary']['packages_found'], 0)
        self.assertEqual(report['summary']['packages_by_manifest'], {'Gemfile.lock': 0})
        network.assert_not_called()
