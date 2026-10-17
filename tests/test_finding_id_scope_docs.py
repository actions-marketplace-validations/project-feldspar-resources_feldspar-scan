"""Document report-local IDs with offline, synthetic Dockerfile findings."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from test_scan import scan


class FindingIdScopeDocsTests(unittest.TestCase):
    def report(self, root):
        output = io.StringIO()
        with mock.patch.object(scan, 'query_osv') as query, \
                contextlib.redirect_stdout(output):
            self.assertEqual(scan.main([
                'scan.py', root, '--no-osv', '--triage']), 0)
        query.assert_not_called()
        report = json.loads(output.getvalue())
        self.assertEqual(set(report['triage']),
                         {finding['id'] for finding in report['findings']})
        return report

    def test_same_line_findings_sort_by_summary_before_id_assignment(self):
        with tempfile.TemporaryDirectory() as root:
            Path(root, 'Dockerfile').write_text(
                chr(10).join(('FROM scratch', 'ENV Z_TOKEN=demo A_TOKEN=demo', 'USER app', '')),
                encoding='utf-8')
            findings = self.report(root)['findings']
        self.assertEqual(
            [(f['id'], f['category'], f['severity'], f['file'], f['line'],
              f['summary']) for f in findings],
            [('F-001', 'config', 'high', 'Dockerfile', 2,
              'Dockerfile ENV assigns secret-like variable A_TOKEN'),
             ('F-002', 'config', 'high', 'Dockerfile', 2,
              'Dockerfile ENV assigns secret-like variable Z_TOKEN')])

    def test_unchanged_finding_is_renumbered_when_earlier_path_is_added(self):
        with tempfile.TemporaryDirectory() as root:
            content = chr(10).join(('FROM scratch', 'USER root', ''))
            Path(root, 'z').mkdir()
            Path(root, 'z', 'Dockerfile').write_text(content, encoding='utf-8')
            before = self.report(root)['findings']
            Path(root, 'a').mkdir()
            Path(root, 'a', 'Dockerfile').write_text(content, encoding='utf-8')
            after = self.report(root)['findings']
            repeated = self.report(root)['findings']
        self.assertEqual([(f['id'], f['file']) for f in before],
                         [('F-001', 'z/Dockerfile')])
        self.assertEqual([(f['id'], f['file']) for f in after],
                         [('F-001', 'a/Dockerfile'), ('F-002', 'z/Dockerfile')])
        self.assertEqual({k: v for k, v in before[0].items() if k != 'id'},
                         {k: v for k, v in after[1].items() if k != 'id'})
        self.assertEqual(after, repeated)
