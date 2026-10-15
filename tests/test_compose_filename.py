"""Offline regression tests for Compose filename coverage."""
import json
from pathlib import Path
import tempfile
import unittest

from test_scan import scan, _collect, _run


class ComposeFilenameTests(unittest.TestCase):
    config = 'services:\n  app:\n    image: synthetic\n    privileged: true\n'

    def collect(self, filename, text):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root, filename)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding='utf-8')
            return _collect(root, scan.scan_config)

    def test_supported_filenames_report_same_finding(self):
        for filename in ('compose.yml', 'compose.yaml', 'nested/compose.yaml',
                         'docker-compose.yml', 'docker-compose.yaml',
                         'docker-compose.override.yaml'):
            with self.subTest(filename=filename):
                hits = self.collect(filename, self.config)
                self.assertEqual(len(hits), 1)
                self.assertEqual(hits[0], {
                    'category': 'config', 'severity': 'medium',
                    'file': filename, 'line': 4,
                    'summary': 'docker-compose service runs privileged',
                    'evidence': 'privileged: true',
                })

    def test_unrelated_filenames_are_ignored(self):
        for filename in ('compose.yaml.bak', 'compose.yaml.txt',
                         'not-compose.yaml', 'settings.yaml'):
            with self.subTest(filename=filename):
                self.assertEqual(self.collect(filename, self.config), [])

    def test_false_or_missing_privileged_remains_clear(self):
        for filename in ('compose.yml', 'compose.yaml'):
            for text in (self.config.replace('true', 'false'),
                         'services:\n  app:\n    image: synthetic\n'):
                with self.subTest(filename=filename, text=text):
                    self.assertEqual(self.collect(filename, text), [])

    def test_cli_summary_gate_and_triage(self):
        with tempfile.TemporaryDirectory() as root:
            Path(root, 'compose.yaml').write_text(self.config, encoding='utf-8')
            rc, output, _ = _run(root, '--no-osv', '--fail-on', 'medium')
            self.assertEqual(rc, 1)
            report = json.loads(output)
            self.assertEqual(report['summary']['config_issues'], 1)
            self.assertEqual(report['summary']['files_with_findings'], 1)
            self.assertEqual(report['summary']['by_severity']['medium'], 1)
            rc, output, _ = _run(root, '--no-osv', '--triage', '--fail-on', 'high')
            self.assertEqual(rc, 0)
            triaged = json.loads(output)
            self.assertEqual(triaged['findings'], report['findings'])
            self.assertEqual(triaged['manifest_hash'], report['manifest_hash'])


if __name__ == '__main__':
    unittest.main()
