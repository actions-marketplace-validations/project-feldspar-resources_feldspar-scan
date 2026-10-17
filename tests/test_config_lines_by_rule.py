"""Configuration rule locations count retained, line-addressable findings."""
import contextlib
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from test_scan import scan


class ConfigLinesByRuleTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)

    def report(self, *options):
        with contextlib.redirect_stdout(io.StringIO()) as out, \
                contextlib.redirect_stderr(io.StringIO()):
            status = scan.main(['scan.py', str(self.root), '--no-osv', *options])
        return status, json.loads(out.getvalue())

    def dockerfile(self, directory):
        folder = self.root / directory
        folder.mkdir(exist_ok=True)
        (folder / 'Dockerfile').write_text(chr(10).join((
            'FROM scratch', 'ENV PASSWORD=short PASSWORD=short TOKEN=short',
            'ENV PASSWORD=short', 'USER root', '')), encoding='utf-8')

    def test_empty_secret_only_and_unlocated_rules(self):
        self.assertEqual(self.report()[1]['summary']['config_lines_by_rule'], {})
        (self.root / 'settings.txt').write_text('password="your_placeholder_value"')
        (self.root / 'Dockerfile').write_text('FROM scratch')
        status, report = self.report('--fail-on=low')
        self.assertEqual(status, 1)
        self.assertEqual(report['summary']['secret_hits'], 1)
        self.assertEqual(report['summary']['config_issues'], 1)
        self.assertEqual(report['summary']['config_lines_by_rule'], {})

    def test_distinct_locations_by_rule_and_file(self):
        for folder in ('one', 'two'):
            self.dockerfile(folder)
        status, report = self.report('--triage', '--fail-on=high')
        self.assertEqual(status, 1)
        counts = report['summary']['config_lines_by_rule']
        self.assertEqual(counts, {
            'Dockerfile ENV assigns secret-like variable PASSWORD': 4,
            'Dockerfile ENV assigns secret-like variable TOKEN': 2,
            'Dockerfile final USER explicitly runs as root': 2,
        })
        self.assertEqual(list(counts), sorted(counts))
        self.assertEqual(report['summary']['config_issues'], 10)
        # Different rules can share a location; per-rule counts overlap.
        self.assertEqual(report['summary']['config_lines'], 6)
        self.assertEqual(report['summary']['gate'], {
            'threshold': 'high', 'matching_findings': 8, 'passed': False})
        self.assertIn('triage', report)
        plain_status, plain = self.report('--fail-on=high')
        self.assertEqual(plain_status, status)
        for key in ('findings', 'summary', 'manifest_hash'):
            self.assertEqual(plain[key], report[key])
        canonical = json.dumps({k: report[k] for k in ('findings', 'target', 'commit')},
                               sort_keys=True, separators=(',', ':'))
        self.assertEqual(report['manifest_hash'], hashlib.sha256(canonical.encode()).hexdigest())

    def test_caps_only_count_retained_locations(self):
        self.dockerfile('one')
        for limit in ('MAX_FINDINGS', 'MAX_FINDINGS_PER_FILE'):
            with self.subTest(limit=limit), mock.patch.object(scan, limit, 2):
                status, report = self.report('--fail-on=high')
                self.assertEqual(status, 1)
                self.assertTrue(report['summary']['truncated']['findings'])
                self.assertEqual(report['summary']['config_issues'], 2)
                self.assertEqual(report['summary']['config_lines_by_rule'], {
                    'Dockerfile ENV assigns secret-like variable PASSWORD': 1})

    def test_compact_sorted_named_output(self):
        self.dockerfile('one')
        # Keep the report outside the scanned directory.
        with tempfile.TemporaryDirectory() as outdir:
            destination = Path(outdir, 'report.json')
            with contextlib.redirect_stdout(io.StringIO()) as out, \
                    contextlib.redirect_stderr(io.StringIO()):
                status = scan.main(['scan.py', str(self.root), '--no-osv',
                                    '--compact', '--sort-keys', '--json', str(destination)])
            self.assertEqual((status, out.getvalue()), (0, ''))
            text = destination.read_text()
        self.assertEqual(len(text.splitlines()), 1)
        report = json.loads(text)
        self.assertEqual(report['summary']['config_lines_by_rule'], {
            'Dockerfile ENV assigns secret-like variable PASSWORD': 2,
            'Dockerfile ENV assigns secret-like variable TOKEN': 1,
            'Dockerfile final USER explicitly runs as root': 1,
        })
