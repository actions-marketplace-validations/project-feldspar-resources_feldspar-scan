"""Offline checks for an explicitly root final Dockerfile user."""
import json
from pathlib import Path
import tempfile
import unittest

from test_scan import scan, _collect, _run


class DockerRootUserTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = self.temp.name

    def findings(self, text):
        Path(self.root, 'Dockerfile').write_text(text, encoding='utf-8')
        return _collect(self.root, scan.scan_config)

    def test_final_root_name_uid_and_groups(self):
        for user in ('root', '0', 'root:root', 'root:1000', '0:app', '0:1000'):
            with self.subTest(user=user):
                hits = self.findings('FROM alpine:3.20\nUSER app\nUSER ' + user + '\n')
                self.assertEqual(len(hits), 1)
                self.assertEqual(hits[0]['summary'],
                                 'Dockerfile final USER explicitly runs as root')
                self.assertEqual(hits[0]['severity'], 'low')
                self.assertEqual(hits[0]['line'], 3)
                self.assertEqual(hits[0]['file'], 'Dockerfile')
                self.assertEqual(hits[0]['evidence'], 'USER root or UID 0 (value omitted)')

    def test_nonroot_override_and_unresolved_users(self):
        for user in ('app', '1000', 'app:root', '1000:0', 'Root', 'rootless',
                     '${APP_USER}', '$APP_USER', 'root${SUFFIX}'):
            with self.subTest(user=user):
                self.assertEqual(self.findings(
                    'FROM alpine:3.20\nUSER root\nUSER ' + user + '\n'), [])

    def test_stage_reset_comments_and_heredocs(self):
        prefix = ('FROM alpine:3.20 AS build\nUSER root\n'
                  'FROM alpine:3.20\n')
        self.assertEqual(self.findings(prefix), [])
        self.assertEqual(self.findings(prefix + 'USER app\n'), [])
        self.assertEqual(self.findings(prefix + 'USER app\n# USER root\n'
                                     'COPY <<EOF /example\nUSER root\nEOF\n'), [])
        hits = self.findings(prefix + 'USER app\nuser \\\n    0:1000\n')
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]['line'], 5)

    def test_cli_gate_and_triage_preserve_raw_finding(self):
        self.findings('FROM alpine:3.20\nUSER root:synthetic-group\n')
        rc, output, _ = _run(self.root, '--no-osv', '--fail-on', 'low')
        self.assertEqual(rc, 1)
        doc = json.loads(output)
        self.assertEqual(doc['summary']['config_issues'], 1)
        self.assertEqual(doc['summary']['by_severity']['low'], 1)
        self.assertNotIn('synthetic-group', output)
        rc, output, _ = _run(self.root, '--no-osv', '--triage', '--fail-on', 'high')
        self.assertEqual(rc, 0)
        triaged = json.loads(output)
        self.assertEqual(doc['findings'], triaged['findings'])
        self.assertEqual(doc['manifest_hash'], triaged['manifest_hash'])


if __name__ == '__main__':
    unittest.main()
