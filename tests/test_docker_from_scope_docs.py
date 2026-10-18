"""Pin the documented FROM heuristic without fetching or building images."""
import json
from pathlib import Path
import tempfile
import unittest

from test_scan import _run, scan


class DockerFromScopeDocsTests(unittest.TestCase):
    def collect(self, instructions):
        findings = []

        def add(category, severity, file, line, **fields):
            findings.append(dict(category=category, severity=severity,
                                 file=file, line=line, **fields))

        scan._scan_dockerfile(chr(10).join([*instructions, 'USER app']),
                              'Dockerfile', add)
        return findings

    def test_registry_ports_and_exact_latest_tag(self):
        for image, expected_count in (
            ('registry.example.invalid:5000/team/app', 1),
            ('registry.example.invalid:5000/team/app:latest', 1),
            ('registry.example.invalid:5000/team/app:v1', 0),
            ('registry.example.invalid:5000/team/app:Latest', 0),
            ('registry.example.invalid:5000/team/app:latest-extra', 0),
        ):
            with self.subTest(image=image):
                findings = self.collect(['FROM --platform=linux/amd64 ' + image])
                self.assertEqual(len(findings), expected_count)
                if findings:
                    self.assertEqual(findings[0], {
                        'category': 'config', 'severity': 'low',
                        'file': 'Dockerfile', 'line': 1,
                        'summary': 'Dockerfile base image uses latest (explicit or implicit)',
                        'evidence': 'FROM unversioned image or :latest (value omitted)',
                    })

    def test_digest_exclusion_is_syntactic(self):
        # Synthetic shapes only; no digest or image existence is verified.
        for digest in ('0' * 64, 'aB' * 32):
            with self.subTest(digest=digest):
                self.assertEqual(self.collect(['FROM app:latest@sha256:' + digest]), [])
        # A non-latest tag is independently excluded, even with a malformed digest.
        self.assertEqual(self.collect(['FROM app:v1@sha256:short']), [])

    def test_aliases_scratch_and_variables_are_not_resolved(self):
        self.assertEqual(self.collect([
            'FROM alpine:v1 AS Builder', 'FROM bUiLdEr', 'FROM ScRaTcH',
            'FROM $BASE', 'FROM alpine:${TAG}',
        ]), [])
        # Only earlier aliases are recognized. All FROM instructions are checked.
        findings = self.collect(['FROM builder', 'FROM alpine:v1 AS builder'])
        self.assertEqual([f['line'] for f in findings], [1])

    def test_unused_stage_finding_survives_triage_and_low_gate(self):
        text = chr(10).join([
            '# An unused stage is still inspected.',
            'FROM --platform=linux/amd64 ' + chr(92),
            '    registry.example.invalid:5000/team/app AS unused',
            'FROM scratch', 'USER app',
        ])
        with tempfile.TemporaryDirectory() as root:
            Path(root, 'Dockerfile').write_text(text, encoding='utf-8')
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
                                          finding['line']), ('config', 'low', 2))
                        self.assertEqual(finding['summary'],
                                         'Dockerfile base image uses latest (explicit or implicit)')
                        self.assertEqual(finding['evidence'],
                                         'FROM unversioned image or :latest (value omitted)')
                        self.assertNotIn('registry.example.invalid', output)
                        self.assertEqual(doc['summary']['gate']['passed'], expected_code == 0)
                        if triage:
                            self.assertEqual(doc['triage'][finding['id']]['action'], 'review')
                        result = (doc['findings'], doc['manifest_hash'])
                        if baseline is None:
                            baseline = result
                        self.assertEqual(result, baseline)
