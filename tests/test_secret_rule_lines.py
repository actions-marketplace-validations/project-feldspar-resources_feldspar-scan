"""Offline coverage for distinct secret locations per rule."""
import contextlib
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from test_scan import scan

NL = chr(10)


class SecretRuleLineTests(unittest.TestCase):
    def report(self, root, *options):
        output = io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(io.StringIO()):
            status = scan.main(['scan.py', str(root), '--no-osv', *options])
        return status, json.loads(output.getvalue())

    def test_empty_and_config_only(self):
        with tempfile.TemporaryDirectory() as root:
            for populated in (False, True):
                with self.subTest(populated=populated):
                    if populated:
                        Path(root, 'compose.yml').write_text('privileged: true' + NL)
                    status, report = self.report(root)
                    self.assertEqual(status, 0)
                    self.assertEqual(report['summary']['secret_lines_by_rule'], {})
                    self.assertEqual(report['summary']['config_issues'], int(populated))

    def populate(self, root):
        # Deliberately synthetic generic assignments; no provider credentials.
        assignment = 'password="A1b2C3d4E5f6G7h8"'
        for name in ('one.txt', 'two.txt'):
            Path(root, name).write_text(assignment + ' ' + assignment + NL + assignment + NL)

    def test_repeated_hits_and_separate_files(self):
        with tempfile.TemporaryDirectory() as root:
            self.populate(root)
            _, plain = self.report(root)
            status, triaged = self.report(root, '--triage', '--compact', '--fail-on', 'medium')
        self.assertEqual(status, 1)
        self.assertEqual(plain['summary']['secret_hits'], 6)
        label = plain['findings'][0]['summary']
        self.assertEqual(plain['summary']['secret_lines_by_rule'], {label: 4})
        self.assertEqual(triaged['summary']['secret_lines_by_rule'], {label: 4})
        self.assertEqual(plain['findings'], triaged['findings'])
        self.assertEqual(plain['manifest_hash'], triaged['manifest_hash'])
        canonical = json.dumps({k: plain[k] for k in ('findings', 'target', 'commit')},
                               sort_keys=True, separators=(',', ':'))
        self.assertEqual(plain['manifest_hash'], hashlib.sha256(canonical.encode()).hexdigest())
        self.assertEqual(triaged['summary']['gate'],
                         {'threshold': 'medium', 'matching_findings': 6, 'passed': False})

    def test_labels_severities_and_category_isolation(self):
        def secrets(root, files, add):
            for label, file, line, severity in [
                ('Z rule', 'one', 1, 'high'), ('Z rule', 'one', 1, 'low'),
                ('A rule', 'one', 1, 'low'), ('Z rule', 'two', 1, 'unknown'),
                ('Z rule', 'one', 2, 'medium')
            ]:
                add('secret', severity, file, line, summary=label, evidence='synthetic')
        def config(root, files, add):
            add('config', 'high', 'three', 1, summary='Z rule', evidence='synthetic')
        with tempfile.TemporaryDirectory() as root, \
                mock.patch.object(scan, 'scan_secrets', secrets), \
                mock.patch.object(scan, 'scan_config', config):
            _, report = self.report(root)
        self.assertEqual(report['summary']['secret_lines_by_rule'], {'A rule': 1, 'Z rule': 3})
        self.assertEqual(list(report['summary']['secret_lines_by_rule']), ['A rule', 'Z rule'])

    def test_limits_only_count_retained_locations(self):
        with tempfile.TemporaryDirectory() as root:
            self.populate(root)
            for limit, value, count, flag in [
                ('MAX_FINDINGS', 2, 1, 'findings'),
                ('MAX_FINDINGS_PER_FILE', 2, 2, 'findings'),
                ('MAX_FILES', 1, 2, 'files')
            ]:
                with self.subTest(limit=limit), mock.patch.object(scan, limit, value):
                    _, report = self.report(root)
                    label = report['findings'][0]['summary']
                    self.assertTrue(report['summary']['truncated'][flag])
                    self.assertEqual(report['summary']['secret_lines_by_rule'], {label: count})
