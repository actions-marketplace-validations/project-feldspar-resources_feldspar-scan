"""Dependency display fields are abbreviated; advisory processing is not."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from test_scan import scan


class AdvisoryEvidenceLimitsTests(unittest.TestCase):
    def report(self, root, ids, details, *options):
        with mock.patch.object(scan, 'query_osv', return_value={
                ('PyPI', 'synthetic-package', '1.0'): ids}), \
                mock.patch.object(scan, 'vuln_details',
                                  side_effect=lambda vid, cache: details[vid]), \
                mock.patch.object(scan, 'http_json', side_effect=AssertionError('offline')), \
                contextlib.redirect_stdout(io.StringIO()) as out, \
                contextlib.redirect_stderr(io.StringIO()):
            status = scan.main(['scan.py', root, '--no-commit', *options])
        return status, json.loads(out.getvalue())

    def test_advisories_beyond_evidence_still_drive_gate_fixes_and_counts(self):
        ids = ['SYNTHETIC-' + str(n) for n in (7, 3, 6, 2, 5, 1, 4)]
        details = {vid: {'severity': 'low', 'fixed_in': [],
                         'summary': 'First advisory ' + 'z' * 140}
                   for vid in ids}
        details[ids[-1]] = {'severity': 'critical', 'fixed_in': ['9.0'],
                            'summary': 'Last advisory'}
        with tempfile.TemporaryDirectory() as root:
            Path(root, 'requirements.txt').write_text('synthetic-package==1.0' + chr(10))
            status, plain = self.report(root, ids, details)
            gated, triaged = self.report(root, ids, details, '--triage', '--fail-on', 'critical')
        self.assertEqual((status, gated), (0, 1))
        self.assertEqual(len(plain['findings']), 1)
        finding = plain['findings'][0]
        self.assertEqual(finding['evidence'], ', '.join(ids[:5]))
        self.assertEqual(finding['vuln_ids'], sorted(ids))
        self.assertEqual(finding['summary'],
                         'synthetic-package 1.0 has 7 known vulnerability/ies ('
                         + details[ids[0]]['summary'][:120] + ')')
        self.assertEqual(finding['severity'], 'critical')
        self.assertEqual(finding['fixed_in'], ['9.0'])
        self.assertEqual(plain['summary']['unique_advisories'], 7)
        self.assertEqual(plain['summary']['dependency_findings_by_advisory'],
                         dict.fromkeys(sorted(ids), 1))
        self.assertEqual(plain['findings'], triaged['findings'])
        self.assertEqual(plain['manifest_hash'], triaged['manifest_hash'])
        self.assertEqual(triaged['triage'][finding['id']]['upgrade_to'], ['9.0'])
        self.assertEqual(triaged['summary']['gate'],
                         {'threshold': 'critical', 'matching_findings': 1, 'passed': False})

    def test_short_evidence_and_summary_are_not_padded_or_replaced(self):
        ids = ['SYNTHETIC-Z', 'SYNTHETIC-A']
        details = {vid: {'severity': 'low', 'fixed_in': [], 'summary': summary}
                   for vid, summary in zip(ids, ('First summary', 'Second summary'))}
        with tempfile.TemporaryDirectory() as root:
            Path(root, 'requirements.txt').write_text('synthetic-package==1.0' + chr(10))
            status, report = self.report(root, ids, details)
        self.assertEqual(status, 0)
        finding = report['findings'][0]
        self.assertEqual(finding['evidence'], 'SYNTHETIC-Z, SYNTHETIC-A')
        self.assertEqual(finding['vuln_ids'], ['SYNTHETIC-A', 'SYNTHETIC-Z'])
        self.assertEqual(finding['summary'],
                         'synthetic-package 1.0 has 2 known vulnerability/ies (First summary)')
