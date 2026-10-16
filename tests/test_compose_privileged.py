"""Offline regression checks for the plain Compose privileged declaration."""
import json
from pathlib import Path
import tempfile
import unittest

from test_scan import scan, _collect, _run


class ComposePrivilegedTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = self.temp.name

    def findings(self, line, filename='compose.yml'):
        path = Path(self.root, filename)
        path.write_text('services:\n  app:\n    ' + line + '\n', encoding='utf-8')
        try:
            return _collect(self.root, scan.scan_config)
        finally:
            path.unlink()

    def test_true_declarations_keep_location_severity_and_safe_evidence(self):
        for line in ('privileged: true', 'privileged:true',
                     'privileged: TRUE  ', 'privileged:\ttrue',
                     'privileged: true # synthetic annotation',
                     'privileged: true\t# synthetic annotation'):
            with self.subTest(line=line):
                hits = self.findings(line)
                self.assertEqual(len(hits), 1)
                hit = hits[0]
                self.assertEqual(hit['file'], 'compose.yml')
                self.assertEqual(hit['line'], 3)
                self.assertEqual(hit['severity'], 'medium')
                self.assertEqual(hit['summary'], 'docker-compose service runs privileged')
                self.assertEqual(hit['evidence'], 'privileged: true')

    def test_comments_and_other_keys_do_not_report(self):
        for line in ('# privileged: true', '## privileged: true',
                     'unprivileged: true', 'not_privileged: true',
                     'x-privileged: true', 'description: privileged: true',
                     'command: "echo privileged: true"',
                     'image: app:1 # privileged: true'):
            with self.subTest(line=line):
                self.assertEqual(self.findings(line), [])

    def test_values_other_than_plain_true_do_not_report(self):
        for value in ('false', 'trueish', 'true123', 'true_suffix', 'true-false',
                      'true#text', 'true trailing', '"true"', "'true'", '',
                      '${PRIVILEGED}', '${PRIVILEGED:-true}'):
            with self.subTest(value=value):
                self.assertEqual(self.findings('privileged: ' + value), [])

    def test_existing_compose_filename_variants(self):
        for filename in ('docker-compose.yml', 'docker-compose.yaml',
                         'docker-compose.override.yml', 'compose.yml'):
            with self.subTest(filename=filename):
                self.assertEqual(len(self.findings('privileged: true', filename)), 1)

    def test_offline_cli_gate_ignores_comments_but_preserves_real_finding(self):
        path = Path(self.root, 'compose.yml')
        text = 'services:\n  app:\n    # privileged: true\n    privileged: false\n'
        path.write_text(text, encoding='utf-8')
        rc, output, _ = _run(self.root, '--no-osv', '--fail-on', 'medium')
        self.assertEqual(rc, 0)
        report = json.loads(output)
        self.assertEqual(report['summary']['config_issues'], 0)
        path.write_text(text + '    privileged: true # synthetic annotation\n',
                        encoding='utf-8')
        rc, output, _ = _run(self.root, '--no-osv', '--fail-on', 'medium')
        self.assertEqual(rc, 1)
        report = json.loads(output)
        self.assertEqual(report['summary']['config_issues'], 1)
        self.assertEqual(report['summary']['by_severity']['medium'], 1)
        self.assertEqual(report['findings'][0]['line'], 5)
        self.assertNotIn('synthetic annotation', output)


if __name__ == '__main__':
    unittest.main()
