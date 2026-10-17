"""Offline examples of the documented Compose line-matching limitations."""
import json
from pathlib import Path
import tempfile
import unittest

from test_scan import scan, _collect, _run


class ComposeHeuristicDocsTests(unittest.TestCase):
    def test_case_insensitive_lines_do_not_require_service_ancestry(self):
        text = """x-metadata:
  "PRIVILEGED": TRUE # review this line
unrelated:
  'Privileged': True
"""
        with tempfile.TemporaryDirectory() as root:
            path = Path(root, 'nested', 'compose.yaml')
            path.parent.mkdir()
            path.write_text(text, encoding='utf-8')
            hits = _collect(root, scan.scan_config)
        self.assertEqual(hits, [
            {'category': 'config', 'severity': 'medium',
             'file': 'nested/compose.yaml', 'line': line,
             'summary': 'docker-compose service runs privileged',
             'evidence': 'privileged: true'}
            for line in (2, 4)
        ])

    def test_quoted_values_and_inline_mappings_are_not_matched(self):
        text = """services:
  app:
    privileged: "true"
    privileged: 'TRUE'
  inline: {privileged: true}
  # privileged: true
  privileged: trueish
"""
        with tempfile.TemporaryDirectory() as root:
            Path(root, 'compose.yaml').write_text(text, encoding='utf-8')
            Path(root, 'COMPOSE.yaml').write_text('privileged: true' + chr(10), encoding='utf-8')
            self.assertEqual(_collect(root, scan.scan_config), [])

    def test_heuristic_findings_still_gate_and_survive_triage(self):
        with tempfile.TemporaryDirectory() as root:
            Path(root, 'compose.yaml').write_text(
                '''x-metadata:
  "PRIVILEGED": TRUE
  privileged: true
''',
                encoding='utf-8')
            rc, output, _ = _run(root, '--no-osv', '--fail-on', 'medium')
            self.assertEqual(rc, 1)
            plain = json.loads(output)
            rc, output, _ = _run(root, '--no-osv', '--fail-on', 'medium', '--triage')
            self.assertEqual(rc, 1)
            triaged = json.loads(output)
            rc, _, _ = _run(root, '--no-osv', '--fail-on', 'high')
            self.assertEqual(rc, 0)
        self.assertEqual(plain['summary']['config_issues'], 2)
        self.assertEqual(plain['summary']['config_lines'], 2)
        self.assertEqual(plain['summary']['files_with_findings'], 1)
        self.assertEqual(plain['summary']['gate'], {
            'threshold': 'medium', 'matching_findings': 2, 'passed': False})
        self.assertEqual([f['line'] for f in plain['findings']], [2, 3])
        for key in ('findings', 'manifest_hash', 'summary'):
            self.assertEqual(plain[key], triaged[key])


if __name__ == '__main__':
    unittest.main()
