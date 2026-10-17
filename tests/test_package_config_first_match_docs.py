"""Package-config warnings identify the first matching line, not every credential."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


NL = chr(10)
SCANNER = Path(__file__).resolve().parents[1] / 'scan.py'


class PackageConfigFirstMatchDocsTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix='fds-package-config-docs-')
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)

    def scan(self, *options):
        result = subprocess.run(
            [sys.executable, str(SCANNER), str(self.root), '--no-osv', *options],
            capture_output=True, text=True, timeout=10)
        self.assertIn(result.returncode, (0, 1), result.stderr)
        return result, json.loads(result.stdout)

    def test_first_qualifying_line_per_file_after_skipped_entries(self):
        for basename in ('.npmrc', '.pypirc'):
            for first, second in (('password = demo-one', '_authToken=demo-two'),
                                  ('_authToken=demo-one', 'password: demo-two')):
                with self.subTest(basename=basename, first=first):
                    prefix = NL.join(('# password=comment', '; _authToken=comment', 'password =   ', ''))
                    if basename == '.npmrc':
                        prefix += '//registry.invalid/:_authToken = ${DEMO_TOKEN}' + NL
                    path = self.root / basename
                    path.write_text(prefix + first + NL + second + NL, encoding='utf-8')
                    result, doc = self.scan('--fail-on=high', '--triage')
                    self.assertEqual(result.returncode, 1)
                    self.assertEqual(len(doc['findings']), 1)
                    finding = doc['findings'][0]
                    self.assertEqual((finding['category'], finding['severity'], finding['file'],
                                      finding['line'], finding['summary']),
                                     ('config', 'high', basename, prefix.count(NL) + 1,
                                      'Credential committed in ' + basename))
                    self.assertNotIn('demo-one', json.dumps(doc))
                    self.assertNotIn('demo-two', json.dumps(doc))
                    self.assertEqual(doc['summary']['config_issues'], 1)
                    self.assertEqual(doc['summary']['gate']['matching_findings'], 1)
                    self.assertEqual(doc['triage'][finding['id']]['action'], 'review')
                    path.unlink()

    def test_nested_files_count_separately_and_triage_preserves_raw_report(self):
        for relative in ('.npmrc', 'nested/.npmrc', 'nested/.pypirc'):
            path = self.root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(NL.join(('password=demo-one', 'password=demo-two', '')), encoding='utf-8')
        result, plain = self.scan('--fail-on=high')
        triaged_result, triaged = self.scan('--fail-on=high', '--triage')
        self.assertEqual((result.returncode, triaged_result.returncode), (1, 1))
        self.assertEqual(plain['findings'], triaged['findings'])
        self.assertEqual(plain['manifest_hash'], triaged['manifest_hash'])
        self.assertEqual(plain['summary'], triaged['summary'])
        self.assertEqual([(f['file'], f['line']) for f in plain['findings']],
                         [('.npmrc', 1), ('nested/.npmrc', 1), ('nested/.pypirc', 1)])
        self.assertEqual(plain['summary']['config_issues'], 3)
        self.assertEqual(plain['summary']['config_lines'], 3)
        self.assertEqual(plain['summary']['files_with_findings'], 3)
        self.assertEqual(plain['summary']['config_issues_by_rule'], {
            'Credential committed in .npmrc': 2, 'Credential committed in .pypirc': 1})

    def test_readme_states_first_match_limit_and_separate_secret_scan(self):
        readme = (SCANNER.parent / 'README.md').read_text(encoding='utf-8')
        self.assertIn('only the first qualifying config finding per file', readme)
        self.assertIn('not a count of credentials', readme)
        self.assertIn('separate secret scan can emit additional findings', readme)
