"""Documented dotenv template exemption applies only to the config check."""
import json
from pathlib import Path
import tempfile
import unittest

from test_scan import scan, _collect, _run


class DotenvTemplateTests(unittest.TestCase):
    def test_template_suffixes_skip_config_assignments(self):
        for suffix in ('example', 'sample', 'template', 'dist'):
            for stem in ('.env', '.env.production', 'nested/.env'):
                for prefix in ('', 'export '):
                    with self.subTest(suffix=suffix, stem=stem, prefix=prefix):
                        with tempfile.TemporaryDirectory() as root:
                            path = Path(root, stem + '.' + suffix)
                            path.parent.mkdir(parents=True, exist_ok=True)
                            path.write_text(prefix + 'PORT=8080', encoding='utf-8')
                            self.assertEqual(_collect(root, scan.scan_config), [])

    def test_suffix_exemption_is_exact_and_case_sensitive(self):
        for filename in ('.env', '.env.production', '.env.example.bak',
                         '.env.examples', '.env.EXAMPLE', '.env.sample.local'):
            with self.subTest(filename=filename), tempfile.TemporaryDirectory() as root:
                Path(root, filename).write_text('export PORT=8080',
                                                encoding='utf-8')
                findings = _collect(root, scan.scan_config)
                self.assertEqual(len(findings), 1)
                self.assertEqual(findings[0]['category'], 'config')
                self.assertEqual(findings[0]['severity'], 'high')
                self.assertEqual(findings[0]['file'], filename)
                self.assertEqual(findings[0]['line'], 1)

    def test_template_secrets_remain_redacted_and_gate_on_raw_severity(self):
        # Synthetic generic value, never a provider-issued credential.
        value = 'A1b2C3d4E5f6G7h8'
        for suffix in ('example', 'sample', 'template', 'dist'):
            with self.subTest(suffix=suffix), tempfile.TemporaryDirectory() as root:
                filename = '.env.' + suffix
                Path(root, filename).write_text('password="' + value + '"',
                                                encoding='utf-8')
                for extra in ((), ('--triage',)):
                    rc, output, _ = _run(root, '--no-osv', '--fail-on', 'medium', *extra)
                    self.assertEqual(rc, 1)
                    self.assertNotIn(value, output)
                    report = json.loads(output)
                    self.assertEqual(report['summary']['config_issues'], 0)
                    self.assertEqual(report['summary']['secret_hits'], 1)
                    finding, = report['findings']
                    self.assertEqual(finding['category'], 'secret')
                    self.assertEqual(finding['severity'], 'medium')
                    self.assertEqual(finding['file'], filename)
                    self.assertEqual(finding['line'], 1)
                rc, _, _ = _run(root, '--no-osv', '--fail-on', 'high')
                self.assertEqual(rc, 0)
