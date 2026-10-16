"""Static requirements inventory scope; synthetic packages, no network."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from test_scan import scan


class RequirementsMarkerScopeTests(unittest.TestCase):
    requirements = '''demo[fast]==1.0; python_version < "0"
demo==1.0; python_version >= "0"
demo==2.0; sys_platform == "synthetic-platform"
unpinned>=3.0; python_version >= "0"
'''

    def test_parser_keeps_marker_exclusive_pins_and_strips_extras(self):
        self.assertEqual(scan.parse_requirements(self.requirements), [
            ('PyPI', 'demo', '1.0'),
            ('PyPI', 'demo', '1.0'),
            ('PyPI', 'demo', '2.0'),
        ])

    def report(self, root, *options):
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            status = scan.main(['scan.py', str(root), *options])
        self.assertEqual(status, 0)
        return json.loads(stdout.getvalue())

    def test_offline_inventory_deduplicates_extras_but_keeps_both_versions(self):
        with tempfile.TemporaryDirectory() as root:
            Path(root, 'requirements.txt').write_text(self.requirements)
            with mock.patch.object(scan, 'query_osv', side_effect=AssertionError('offline')):
                report = self.report(root, '--no-osv')
        self.assertEqual(report['summary']['packages_found'], 2)
        self.assertEqual(report['summary']['packages_by_ecosystem'], {'PyPI': 2})
        self.assertEqual(report['summary']['lockfiles_parsed'], ['requirements.txt'])
        self.assertEqual(report['findings'], [])

    def test_advisory_queries_include_pins_without_evaluating_markers(self):
        with tempfile.TemporaryDirectory() as root:
            Path(root, 'requirements.txt').write_text(self.requirements)
            with mock.patch.object(scan, 'query_osv', return_value={}) as query:
                report = self.report(root)
        query.assert_called_once_with([
            ('PyPI', 'demo', '1.0'), ('PyPI', 'demo', '2.0')])
        self.assertEqual(report['summary']['packages_found'], 2)
        self.assertEqual(report['findings'], [])
