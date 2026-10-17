"""Retained-finding path counts; all inputs and advisories are synthetic."""
import contextlib
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from test_scan import scan


class FindingsPathContextTests(unittest.TestCase):
    def report(self, root, *options):
        output = io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(io.StringIO()):
            status = scan.main(['scan.py', str(root), *options])
        doc = json.loads(output.getvalue())
        counts = doc['summary']['findings_by_path_context']
        self.assertEqual(set(counts), {'scaffold', 'other'})
        self.assertEqual(sum(counts.values()), len(doc['findings']))
        return status, doc

    def test_empty_scan_has_both_zero_buckets(self):
        with tempfile.TemporaryDirectory() as root:
            status, doc = self.report(root, '--no-osv')
        self.assertEqual(status, 0)
        self.assertEqual(doc['summary']['findings_by_path_context'],
                         {'scaffold': 0, 'other': 0})

    def test_real_config_paths_count_findings_not_files(self):
        cases = {'examples/Dockerfile': 'scaffold', 'src/TESTS/Dockerfile': 'scaffold',
                 'contest/Dockerfile': 'other', 'test_app/Dockerfile': 'other',
                 'Dockerfile': 'other'}
        with tempfile.TemporaryDirectory() as root:
            for relative, context in cases.items():
                path = Path(root, relative)
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text('FROM alpine:latest' + chr(10) + 'USER root' + chr(10), encoding='utf-8')
            status, doc = self.report(root, '--no-osv', '--fail-on', 'low')
        self.assertEqual(status, 1)
        self.assertEqual(len(doc['findings']), 10)
        self.assertEqual(doc['summary']['files_with_findings'], 5)
        self.assertEqual(doc['summary']['findings_by_path_context'],
                         {'scaffold': 4, 'other': 6})
        self.assertEqual(doc['summary']['gate']['matching_findings'], 10)

    def test_mixed_categories_and_triage_preserve_findings_gate_and_hash(self):
        with tempfile.TemporaryDirectory() as root:
            Path(root, 'requirements.txt').write_text('sample-a==1.0' + chr(10))
            Path(root, 'docs').mkdir()
            Path(root, 'docs', 'Dockerfile').write_text('FROM alpine:latest' + chr(10) + 'USER root' + chr(10))
            def secret_fixture(root, files, add):
                add('secret', 'medium', 'src/settings.py', 1,
                    summary='Synthetic secret fixture', evidence='value omitted')
            with mock.patch.object(scan, 'query_osv', return_value={
                    ('PyPI', 'sample-a', '1.0'): ['SYNTH-1']}), \
                    mock.patch.object(scan, 'vuln_details', return_value={
                        'severity': 'high', 'summary': 'Synthetic advisory', 'fixed_in': []}), \
                    mock.patch.object(scan, 'scan_secrets', side_effect=secret_fixture):
                status, doc = self.report(root, '--fail-on', 'high')
                triage_status, triaged = self.report(root, '--triage', '--fail-on', 'high')
        self.assertEqual((status, triage_status), (1, 1))
        self.assertEqual(doc['summary']['findings_by_path_context'],
                         {'scaffold': 2, 'other': 2})
        self.assertEqual(set(f['category'] for f in doc['findings']),
                         {'secret', 'config', 'dependency-vuln'})
        self.assertEqual(doc['findings'], triaged['findings'])
        self.assertEqual(doc['manifest_hash'], triaged['manifest_hash'])
        self.assertEqual(doc['summary'], triaged['summary'])
        self.assertEqual(doc['summary']['gate'], {
            'threshold': 'high', 'matching_findings': 1, 'passed': False})
        canonical = json.dumps({k: doc[k] for k in ('findings', 'target', 'commit')},
                               sort_keys=True, separators=(',', ':'))
        self.assertEqual(doc['manifest_hash'], hashlib.sha256(canonical.encode()).hexdigest())

    def test_caps_count_only_retained_findings(self):
        for limit in ('MAX_FINDINGS', 'MAX_FINDINGS_PER_FILE'):
            with self.subTest(limit=limit), tempfile.TemporaryDirectory() as root:
                Path(root, 'examples').mkdir()
                Path(root, 'examples', 'Dockerfile').write_text('FROM alpine:latest' + chr(10) + 'USER root' + chr(10))
                with mock.patch.object(scan, limit, 1):
                    _, doc = self.report(root, '--no-osv')
                self.assertTrue(doc['summary']['truncated']['findings'])
                self.assertEqual(doc['summary']['findings_by_path_context'],
                                 {'scaffold': 1, 'other': 0})
