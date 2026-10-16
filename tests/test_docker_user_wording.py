"""Offline coverage for evidence-limited missing-USER finding text."""
import json
from pathlib import Path
import tempfile
import unittest

from test_scan import scan, _collect, _run


class DockerUserWordingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = self.temp.name

    def write(self, *lines, filename='Dockerfile'):
        Path(self.root, filename).write_text(chr(10).join(lines) + chr(10), encoding='utf-8')

    def test_missing_user_reports_only_observed_instruction_absence(self):
        for filename in ('Dockerfile', 'Dockerfile.release'):
            with self.subTest(filename=filename):
                self.write('FROM synthetic-base:1', '# USER app', filename=filename)
                hits = _collect(self.root, scan.scan_config)
                Path(self.root, filename).unlink()
                self.assertEqual(len(hits), 1)
                self.assertEqual(hits[0]['summary'],
                                 'Dockerfile has no USER instruction (runtime user unverified)')
                self.assertEqual(hits[0]['evidence'], 'no USER directive')
                self.assertEqual(hits[0]['severity'], 'low')
                self.assertEqual(hits[0]['file'], filename)
                self.assertIsNone(hits[0]['line'])

    def test_explicit_users_remain_distinct(self):
        for user in ('app', '1000', '${APP_USER}'):
            with self.subTest(user=user):
                self.write('FROM synthetic-base:1', 'USER ' + user)
                self.assertEqual(_collect(self.root, scan.scan_config), [])
        self.write('FROM synthetic-base:1', 'USER root')
        hits = _collect(self.root, scan.scan_config)
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]['summary'],
                         'Dockerfile final USER explicitly runs as root')

    def test_cli_gates_and_triage_retain_low_finding(self):
        self.write('FROM synthetic-base:1')
        rc, output, _ = _run(self.root, '--no-osv', '--fail-on', 'low')
        self.assertEqual(rc, 1)
        report = json.loads(output)
        self.assertEqual(report['summary']['config_issues'], 1)
        self.assertEqual(report['summary']['by_severity']['low'], 1)
        self.assertIn('runtime user unverified', report['findings'][0]['summary'])
        rc, output, _ = _run(self.root, '--no-osv', '--triage', '--fail-on', 'high')
        self.assertEqual(rc, 0)
        triaged = json.loads(output)
        self.assertEqual(report['findings'], triaged['findings'])
        self.assertEqual(report['manifest_hash'], triaged['manifest_hash'])


if __name__ == '__main__':
    unittest.main()
