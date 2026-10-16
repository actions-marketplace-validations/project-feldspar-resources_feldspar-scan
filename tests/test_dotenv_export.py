"""Committed .env export assignments; all values are synthetic."""
import json
from pathlib import Path
import tempfile
import unittest

from test_scan import scan


class DotenvExportTests(unittest.TestCase):
    def collect(self, text, name='.env'):
        findings = []

        def add(category, severity, file, line, **details):
            findings.append(dict(category=category, severity=severity,
                                 file=file, line=line, **details))

        with tempfile.TemporaryDirectory() as root:
            path = Path(root, name)
            path.write_text(text, encoding='utf-8')
            scan.scan_config(root, [str(path)], add)
        return findings

    def test_export_assignments_keep_location_severity_and_redaction(self):
        value = 'synthetic-value-123456789'
        for name in ('.env', '.env.production'):
            for prefix in ('export ', 'export\t', '  export  '):
                with self.subTest(name=name, prefix=prefix):
                    findings = self.collect('# comment\n\n' + prefix +
                                            'SERVICE_KEY = ' + value + '\n', name)
                    self.assertEqual(len(findings), 1)
                    finding = findings[0]
                    self.assertEqual(finding['category'], 'config')
                    self.assertEqual(finding['severity'], 'high')
                    self.assertEqual(finding['file'], name)
                    self.assertEqual(finding['line'], 3)
                    self.assertEqual(finding['summary'],
                                     'Committed .env file with assignments')
                    self.assertEqual(finding['evidence'],
                                     scan.redact((prefix + 'SERVICE_KEY ').lstrip()) + '=…')
                    self.assertNotIn(value, json.dumps(findings))

    def test_comments_and_malformed_exports_are_not_assignments(self):
        for line in ('# export PORT=8080', '  # export PORT=8080',
                     'export PORT', 'export 1PORT=8080', 'export -n PORT=8080',
                     'exportPORT value=8080', 'export\n PORT', 'EXPORT PORT=8080'):
            with self.subTest(line=line):
                self.assertEqual(self.collect(line), [])

    def test_template_suffixes_remain_excluded(self):
        for suffix in ('example', 'sample', 'template', 'dist'):
            with self.subTest(suffix=suffix):
                self.assertEqual(self.collect('export PORT=8080\n', '.env.' + suffix), [])

    def test_only_first_assignment_is_reported(self):
        for first in ('export PORT=8080', 'PORT=8080', 'exported_PORT=8080'):
            with self.subTest(first=first):
                findings = self.collect('# comment\n' + first + '\nexport HOST=localhost\n')
                self.assertEqual(len(findings), 1)
                self.assertEqual(findings[0]['line'], 2)
