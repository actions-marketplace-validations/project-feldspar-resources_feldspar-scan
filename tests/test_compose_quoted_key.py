"""Offline checks for quoted Compose privileged keys; no credentials or services."""
import json
from pathlib import Path
import tempfile
import unittest

from test_scan import scan, _collect, _run


class ComposeQuotedKeyTests(unittest.TestCase):
    def collect(self, declaration, filename='compose.yaml'):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root, filename)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(f'''services:
  app:
    {declaration}
''', encoding='utf-8')
            return _collect(root, scan.scan_config)

    def test_paired_quotes_keep_existing_finding_contract(self):
        for name in ('compose.yml', 'nested/compose.yaml', 'docker-compose.yml',
                     'docker-compose.override.yaml'):
            expected = self.collect('privileged: true', name)
            self.assertEqual(len(expected), 1)
            for key in ('"privileged"', "'privileged'", '"PRIVILEGED"'):
                for value in ('true', 'TRUE', '\ttrue # synthetic annotation'):
                    with self.subTest(name=name, key=key, value=value):
                        self.assertEqual(self.collect(key + ': ' + value, name), expected)

    def test_malformed_or_unrelated_keys_do_not_report(self):
        for key in ('"privileged\'', '\'privileged"', '"privileged',
                    "privileged'", '"unprivileged"', '"x-privileged"',
                    '"privileged_extra"', '" privileged"', '"privileged "'):
            with self.subTest(key=key):
                self.assertEqual(self.collect(key + ': true'), [])

    def test_values_comments_and_filenames_remain_bounded(self):
        for key in ('"privileged"', "'privileged'"):
            for value in ('false', 'trueish', 'true#comment', 'true trailing',
                          '"true"', "'true'", '${PRIVILEGED}', ''):
                with self.subTest(key=key, value=value):
                    self.assertEqual(self.collect(key + ': ' + value), [])
            for prefix in ('# ', 'description: ', 'image: app # '):
                with self.subTest(prefix=prefix):
                    self.assertEqual(self.collect(prefix + key + ': true'), [])
            self.assertEqual(self.collect(key + ': true', 'settings.yaml'), [])

    def test_offline_cli_gate_and_triage(self):
        with tempfile.TemporaryDirectory() as root:
            Path(root, 'compose.yaml').write_text(
                '''services:
  app:
    "privileged": true # synthetic annotation
''',
                encoding='utf-8')
            rc, output, _ = _run(root, '--no-osv', '--fail-on', 'medium')
            self.assertEqual(rc, 1)
            plain = json.loads(output)
            self.assertEqual(plain['summary']['config_issues'], 1)
            self.assertEqual(plain['findings'][0]['line'], 3)
            self.assertEqual(plain['findings'][0]['evidence'], 'privileged: true')
            self.assertNotIn('synthetic annotation', output)
            rc, output, _ = _run(root, '--no-osv', '--triage', '--fail-on', 'high')
            self.assertEqual(rc, 0)
            triaged = json.loads(output)
            self.assertEqual(triaged['findings'], plain['findings'])
            self.assertEqual(triaged['manifest_hash'], plain['manifest_hash'])


if __name__ == '__main__':
    unittest.main()
