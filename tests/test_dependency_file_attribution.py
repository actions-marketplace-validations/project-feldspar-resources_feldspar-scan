"""Pin the documented representative-file semantics with synthetic advisories."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from test_scan import scan


class DependencyFileAttributionTests(unittest.TestCase):
    def report(self, manifests):
        with tempfile.TemporaryDirectory() as root:
            for name, versions in manifests.items():
                path = Path(root, name)
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(chr(10).join('demo==' + v for v in versions))
            hits = {('PyPI', 'demo', version): ['SYNTHETIC-1']
                    for versions in manifests.values() for version in versions}
            output = io.StringIO()
            with mock.patch.object(scan, 'query_osv', return_value=hits) as query, \
                    mock.patch.object(scan, 'vuln_details', return_value={
                        'severity': 'high', 'fixed_in': [], 'summary': 'Synthetic advisory'}), \
                    mock.patch.object(scan, 'http_json', side_effect=AssertionError('offline')), \
                    contextlib.redirect_stdout(output), \
                    contextlib.redirect_stderr(io.StringIO()):
                status = scan.main(['scan.py', root, '--triage', '--fail-on', 'high'])
            self.assertEqual(status, 1)
            self.assertEqual(set(query.call_args.args[0]), set(hits))
            report = json.loads(output.getvalue())
            self.assertEqual(report['summary']['lockfiles_parsed'], sorted(manifests))
            self.assertEqual(report['summary']['packages_found'], len(hits))
            self.assertEqual(report['summary']['vulnerable_packages'], len(hits))
            self.assertEqual(len(report['findings']), len(hits))
            self.assertTrue(all(f['category'] == 'dependency-vuln' for f in report['findings']))
            return report

    def test_duplicate_shipped_manifests_report_only_first_sorted_path(self):
        report = self.report({'z/requirements.txt': ['1.0'],
                              'a/requirements.txt': ['1.0', '1.0']})
        self.assertEqual(report['findings'][0]['file'], 'a/requirements.txt')
        self.assertEqual(report['summary']['files_with_findings'], 1)
        self.assertEqual(report['summary']['files_with_findings_by_category']['dependency-vuln'], 1)

    def test_shipped_manifest_wins_in_either_sort_order(self):
        for shipped in ('a/requirements.txt', 'z/requirements.txt'):
            with self.subTest(shipped=shipped):
                report = self.report({'examples/requirements.txt': ['1.0'],
                                      shipped: ['1.0']})
                self.assertEqual(report['findings'][0]['file'], shipped)
                self.assertEqual(report['triage_summary']['dependency']['in_scaffold_lockfiles'], 0)
        report = self.report({'tests/requirements.txt': ['1.0'],
                              'examples/requirements.txt': ['1.0']})
        self.assertEqual(report['findings'][0]['file'], 'examples/requirements.txt')
        self.assertEqual(report['triage_summary']['dependency']['in_scaffold_lockfiles'], 1)

    def test_distinct_versions_keep_separate_representatives(self):
        report = self.report({'a/requirements.txt': ['1.0'],
                              'b/requirements.txt': ['2.0'],
                              'z/requirements.txt': ['1.0', '2.0']})
        self.assertEqual({f['version']: f['file'] for f in report['findings']},
                         {'1.0': 'a/requirements.txt', '2.0': 'b/requirements.txt'})
        self.assertEqual(report['summary']['files_with_findings'], 2)
        self.assertEqual(report['summary']['files_with_findings_by_category']['dependency-vuln'], 2)


if __name__ == '__main__':
    unittest.main()
