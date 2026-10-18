"""Pin the documented USER heuristics without building or inspecting images."""
import json
from pathlib import Path
import tempfile
import unittest

from test_scan import _run, scan


class DockerUserScopeDocsTests(unittest.TestCase):
    def collect(self, lines):
        findings = []

        def add(category, severity, file, line, **fields):
            findings.append(dict(category=category, severity=severity,
                                 file=file, line=line, **fields))

        scan._scan_dockerfile(chr(10).join(lines), 'Dockerfile', add)
        return findings

    def test_root_user_is_a_literal_case_sensitive_match(self):
        for user in ('root', '0', 'root:app', '0:1000', 'root:group-name_1.2'):
            with self.subTest(user=user):
                self.assertEqual(self.collect(['FROM scratch', 'USER ' + user]), [{
                    'category': 'config', 'severity': 'low', 'file': 'Dockerfile',
                    'line': 2, 'summary': 'Dockerfile final USER explicitly runs as root',
                    'evidence': 'USER root or UID 0 (value omitted)',
                }])
        for user in ('ROOT', '00', 'app:root', '1000:0', '$USER', '${USER}',
                     '"root"', "'root'", 'root:', 'root # comment'):
            with self.subTest(user=user):
                self.assertEqual(self.collect(['FROM scratch', 'USER ' + user]), [])

    def test_missing_user_is_whole_file_and_inheritance_is_not_resolved(self):
        # An earlier USER suppresses the missing-USER rule; final-stage identity
        # is not resolved even when FROM names the stage that explicitly used root.
        for final_base in ('scratch', 'builder'):
            with self.subTest(final_base=final_base):
                self.assertEqual(self.collect([
                    'FROM scratch AS builder', 'USER root', 'FROM ' + final_base,
                ]), [])
        self.assertEqual(self.collect([
            'FROM scratch', 'USER root', 'USER app',
        ]), [])
        findings = self.collect(['FROM scratch', '# USER app', 'FROM scratch'])
        self.assertEqual(findings, [{
            'category': 'config', 'severity': 'low', 'file': 'Dockerfile',
            'line': None,
            'summary': 'Dockerfile has no USER instruction (runtime user unverified)',
            'evidence': 'no USER directive',
        }])

    def test_continued_final_user_location_triage_and_gate(self):
        text = chr(10).join([
            'FROM scratch AS builder', 'USER app', 'FROM scratch',
            'USER ' + chr(92), '    0:1000',
        ])
        with tempfile.TemporaryDirectory() as root:
            Path(root, 'Dockerfile').write_text(text, encoding='utf-8')
            baseline = None
            for triage in (False, True):
                for threshold, expected in (('low', 1), ('medium', 0)):
                    with self.subTest(triage=triage, threshold=threshold):
                        flags = ['--no-osv', '--fail-on', threshold]
                        if triage:
                            flags.append('--triage')
                        code, output, error = _run(root, *flags)
                        self.assertEqual(code, expected, error)
                        report = json.loads(output)
                        self.assertEqual(len(report['findings']), 1)
                        finding = report['findings'][0]
                        self.assertEqual((finding['category'], finding['severity'],
                                          finding['line']), ('config', 'low', 4))
                        self.assertEqual(finding['evidence'],
                                         'USER root or UID 0 (value omitted)')
                        self.assertNotIn('0:1000', output)
                        self.assertEqual(report['summary']['gate']['passed'], expected == 0)
                        if triage:
                            self.assertEqual(report['triage'][finding['id']]['action'], 'review')
                        result = (report['findings'], report['manifest_hash'])
                        if baseline is None:
                            baseline = result
                        self.assertEqual(result, baseline)
