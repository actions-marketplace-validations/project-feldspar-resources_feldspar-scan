"""Pin the documented secret-scan exclusion of readable SVG content, offline."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from test_scan import scan


class SecretExtensionDocsTests(unittest.TestCase):
    # Synthetic assignment inside readable SVG; no real credential is used.
    VALUE = 'A1b2C3d4E5f6G7h8'
    CONTENT = chr(10).join(('<svg>', '<!-- password="' + VALUE + '" -->', '</svg>', ''))

    def report(self, root, *options):
        output = io.StringIO()
        with contextlib.redirect_stdout(output), \
                contextlib.redirect_stderr(io.StringIO()), \
                mock.patch.object(scan, 'http_json', side_effect=AssertionError('network')):
            status = scan.main(['scan.py', str(root), '--no-osv',
                                '--fail-on', 'medium', *options])
        return status, json.loads(output.getvalue())

    def test_svg_case_variants_skip_readable_content_and_do_not_trip_gate(self):
        for suffix in ('.svg', '.SVG', '.SvG'):
            with self.subTest(suffix=suffix), tempfile.TemporaryDirectory() as root:
                path = Path(root, 'image' + suffix)
                path.write_text(self.CONTENT, encoding='utf-8')
                self.assertEqual(scan.read_text(str(path)), self.CONTENT)
                status, report = self.report(root, '--triage')
                self.assertEqual(status, 0)
                self.assertEqual(report['findings'], [])
                self.assertEqual(report['summary']['files_scanned'], 1)
                self.assertEqual(report['summary']['secret_hits'], 0)
                self.assertFalse(any(report['summary']['truncated'].values()))
                self.assertEqual(report['triage_summary']['secrets']['total'], 0)

    def test_identical_text_file_is_detected_alongside_excluded_svg(self):
        with tempfile.TemporaryDirectory() as root:
            for name in ('image.svg', 'image.txt'):
                Path(root, name).write_text(self.CONTENT, encoding='utf-8')
            status, plain = self.report(root)
            triaged_status, triaged = self.report(root, '--triage')
        self.assertEqual((status, triaged_status), (1, 1))
        self.assertEqual(plain['summary']['files_scanned'], 2)
        self.assertFalse(any(plain['summary']['truncated'].values()))
        self.assertEqual(plain['summary']['secret_hits'], 1)
        self.assertEqual(len(plain['findings']), 1)
        finding = plain['findings'][0]
        self.assertEqual((finding['file'], finding['line']), ('image.txt', 2))
        self.assertEqual(finding['severity'], 'medium')
        self.assertEqual(finding['summary'], 'Hardcoded password assignment')
        self.assertEqual(finding['evidence'], 'A1b2…')
        self.assertNotIn(self.VALUE, json.dumps(plain))
        self.assertEqual(plain['findings'], triaged['findings'])
        self.assertEqual(plain['manifest_hash'], triaged['manifest_hash'])
        self.assertEqual(triaged['triage_summary']['secrets']['needs_review'], 1)
