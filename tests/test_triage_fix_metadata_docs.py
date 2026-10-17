"""Pin documented triage metadata limits with synthetic, offline advisories."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from test_scan import scan


class TriageFixMetadataDocsTests(unittest.TestCase):
    def report(self, root, responses, triage):
        hits = {('PyPI', 'sample-package', '1.0'): list(responses)}

        def response(url, *args, **kwargs):
            value = responses[url.rsplit('/', 1)[-1]]
            if isinstance(value, Exception):
                raise value
            return value

        output = io.StringIO()
        args = ['scan.py', root, '--fail-on', 'low']
        if triage:
            args.append('--triage')
        with mock.patch.object(scan, 'query_osv', return_value=hits), \
                mock.patch.object(scan, 'http_json', side_effect=response), \
                contextlib.redirect_stdout(output), \
                contextlib.redirect_stderr(io.StringIO()):
            code = scan.main(args)
        return code, json.loads(output.getvalue())

    def test_empty_fix_metadata_routes_to_monitor_even_after_fetch_failure(self):
        for detail, errors in (({}, 0), (OSError('synthetic detail failure'), 1)):
            with self.subTest(errors=errors), tempfile.TemporaryDirectory() as root:
                Path(root, 'requirements.txt').write_text('sample-package==1.0' + chr(10))
                responses = {'SYNTH-1': detail}
                plain_code, plain = self.report(root, responses, False)
                code, report = self.report(root, responses, True)
                finding, = report['findings']
                self.assertEqual(finding['fixed_in'], [])
                self.assertEqual(finding['severity'], 'unknown')
                self.assertEqual(report['triage'][finding['id']]['action'], 'monitor')
                self.assertEqual(report['triage_summary']['dependency']['monitor_only'], 1)
                self.assertEqual(report['summary']['errors_count'], errors)
                if errors:
                    self.assertIn('synthetic detail failure', report['errors'][0])
                self.assertEqual((plain_code, code), (0, 0))
                self.assertTrue(report['summary']['gate']['passed'])
                self.assertEqual(plain['findings'], report['findings'])
                self.assertEqual(plain['manifest_hash'], report['manifest_hash'])

    def test_one_fix_among_multiple_advisories_routes_package_to_upgrade(self):
        responses = {
            'SYNTH-1': {'database_specific': {'severity': 'HIGH'},
                        'affected': [{'ranges': [{'events': [{'fixed': '2.0'}]}]}]},
            'SYNTH-2': {},
            'SYNTH-3': OSError('synthetic detail failure'),
        }
        with tempfile.TemporaryDirectory() as root:
            Path(root, 'requirements.txt').write_text('sample-package==1.0' + chr(10))
            plain_code, plain = self.report(root, responses, False)
            code, report = self.report(root, responses, True)
        finding, = report['findings']
        self.assertEqual(finding['vuln_ids'], sorted(responses))
        self.assertEqual(finding['fixed_in'], ['2.0'])
        interpretation = report['triage'][finding['id']]
        self.assertEqual(interpretation['action'], 'upgrade')
        self.assertEqual(interpretation['upgrade_to'], ['2.0'])
        self.assertEqual(report['triage_summary']['dependency'], {
            'upgradeable': 1, 'monitor_only': 0, 'in_scaffold_lockfiles': 0})
        self.assertEqual(report['summary']['errors_count'], 1)
        self.assertEqual((plain_code, code), (1, 1))
        self.assertEqual(plain['findings'], report['findings'])
        self.assertEqual(plain['manifest_hash'], report['manifest_hash'])

    def test_help_and_readme_explain_metadata_limits(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(scan.main(['scan.py', '--help']), 0)
        self.assertIn('reported fix metadata', output.getvalue())
        readme = Path(scan.__file__).with_name('README.md').read_text()
        self.assertIn('does not prove that no patched release exists', readme)
        self.assertIn('does not prove that every advisory is resolved', readme)
