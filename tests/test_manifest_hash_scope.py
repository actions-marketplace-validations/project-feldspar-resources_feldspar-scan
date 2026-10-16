"""Pin the documented hash scope using local synthetic files and a fixed HEAD."""
import contextlib
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from test_scan import scan


class ManifestHashScopeTests(unittest.TestCase):
    def report(self, target):
        output = io.StringIO()
        with mock.patch.object(scan, 'git_head', return_value='a' * 40), \
                mock.patch.object(scan, 'query_osv') as query, \
                contextlib.redirect_stdout(output):
            self.assertEqual(scan.main(['scan.py', target, '--no-osv']), 0)
        query.assert_not_called()
        report = json.loads(output.getvalue())
        canonical = json.dumps(
            {key: report[key] for key in ('findings', 'target', 'commit')},
            sort_keys=True, separators=(',', ':'))
        self.assertEqual(report['manifest_hash'],
                         hashlib.sha256(canonical.encode()).hexdigest())
        return report

    def test_working_tree_findings_change_hash_with_same_head(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root, '.env')
            path.write_text('# empty configuration', encoding='utf-8')
            before = self.report(root)
            path.write_text('FEATURE_FLAG=enabled', encoding='utf-8')
            after = self.report(root)
            repeated = self.report(root)
        self.assertEqual(before['commit'], after['commit'])
        self.assertEqual(before['target'], after['target'])
        self.assertEqual(before['findings'], [])
        self.assertEqual(len(after['findings']), 1)
        self.assertEqual(after['findings'][0]['category'], 'config')
        self.assertNotEqual(before['manifest_hash'], after['manifest_hash'])
        self.assertEqual(after['manifest_hash'], repeated['manifest_hash'])

    def test_target_spelling_changes_hash_for_same_tree_and_head(self):
        with tempfile.TemporaryDirectory() as root:
            Path(root, '.env').write_text('FEATURE_FLAG=enabled', encoding='utf-8')
            plain = self.report(root)
            dotted = self.report(root + '/.')
        self.assertEqual(plain['commit'], dotted['commit'])
        self.assertEqual(plain['findings'], dotted['findings'])
        self.assertEqual(plain['target'], root)
        self.assertEqual(dotted['target'], root + '/.')
        self.assertNotEqual(plain['manifest_hash'], dotted['manifest_hash'])

    def test_content_edits_without_findings_do_not_change_hash(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root, 'notes.txt')
            path.write_text('first harmless note', encoding='utf-8')
            before = self.report(root)
            path.write_text('different harmless note', encoding='utf-8')
            after = self.report(root)
        self.assertEqual(before['findings'], [])
        self.assertEqual(after['findings'], [])
        self.assertEqual(before['manifest_hash'], after['manifest_hash'])
