"""Pin the documented remote ADD heuristic without fetching or building."""
import json
from pathlib import Path
import tempfile
import unittest

from test_scan import _run, scan


class DockerAddScopeDocsTests(unittest.TestCase):
    def collect(self, instructions):
        findings = []

        def add(category, severity, file, line, **fields):
            findings.append(dict(category=category, severity=severity,
                                 file=file, line=line, **fields))

        scan._scan_dockerfile(chr(10).join([
            'FROM scratch', 'USER app', *instructions,
        ]), 'Dockerfile', add)
        return findings

    def test_sources_options_and_one_finding_per_instruction(self):
        digest = 'a' * 64  # Synthetic digest; never checked against a download.
        cases = [
            'ADD https://example.invalid/one /app/',
            'ADD HTTP://example.invalid/one https://example.invalid/two /app/',
            'ADD ["HTTPS://example.invalid/one", "https://example.invalid/two", "/app/"]',
            'ADD --checksum=sha256:' + digest + ' https://example.invalid/one /app/',
            'ADD --chown=app --chmod=0444 ["https://example.invalid/one", "/app/"]',
        ]
        for instruction in cases:
            with self.subTest(instruction=instruction):
                self.assertEqual(self.collect([instruction]), [{
                    'category': 'config', 'severity': 'low', 'file': 'Dockerfile',
                    'line': 3, 'summary': 'Dockerfile uses ADD with a remote URL',
                    'evidence': 'ADD remote URL (value omitted)',
                }])

    def test_only_literal_http_sources_are_checked(self):
        # Some are intentionally invalid Docker syntax: this is a lexical check.
        cases = [
            'ADD local.tar /app/',
            'ADD local.tar https://example.invalid/destination',
            'ADD ["local.tar", "https://example.invalid/destination"]',
            'ADD https://example.invalid/only-operand',
            'ADD git://example.invalid/repo.git /app/',
            'ADD ssh://example.invalid/repo.git /app/',
            'ADD git@example.invalid:repo.git /app/',
            'ADD ftp://example.invalid/archive /app/',
            'ADD $SOURCE /app/',
            'ADD ${SOURCE} /app/',
            'COPY https://example.invalid/archive /app/',
        ]
        for instruction in cases:
            with self.subTest(instruction=instruction):
                self.assertEqual(self.collect([instruction]), [])

    def test_checksum_finding_survives_triage_and_low_gate(self):
        lines = [
            'FROM scratch', 'USER app',
            'ADD --checksum=sha256:' + 'a' * 64 + ' ' + chr(92),
            '    https://example.invalid/one?flavour=demo ' + chr(92),
            '    https://example.invalid/two /app/',
        ]
        with tempfile.TemporaryDirectory() as root:
            Path(root, 'Dockerfile').write_text(chr(10).join(lines), encoding='utf-8')
            baseline = None
            for triage in (False, True):
                for threshold, expected_code in (('low', 1), ('medium', 0)):
                    with self.subTest(triage=triage, threshold=threshold):
                        flags = ['--no-osv', '--fail-on', threshold]
                        if triage:
                            flags.append('--triage')
                        code, output, error = _run(root, *flags)
                        self.assertEqual(code, expected_code, error)
                        doc = json.loads(output)
                        self.assertEqual(len(doc['findings']), 1)
                        finding = doc['findings'][0]
                        self.assertEqual((finding['category'], finding['severity'],
                                          finding['line']), ('config', 'low', 3))
                        self.assertEqual(finding['summary'],
                                         'Dockerfile uses ADD with a remote URL')
                        self.assertEqual(finding['evidence'], 'ADD remote URL (value omitted)')
                        self.assertNotIn('example.invalid', output)
                        self.assertNotIn('flavour=demo', output)
                        self.assertNotIn('a' * 64, output)
                        self.assertEqual(doc['summary']['gate']['passed'], expected_code == 0)
                        if triage:
                            self.assertEqual(doc['triage'][finding['id']]['action'], 'review')
                        result = (doc['findings'], doc['manifest_hash'])
                        if baseline is None:
                            baseline = result
                        self.assertEqual(result, baseline)
