"""Preserve attribute-name context at the bounded placeholder lookback edge."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest

from test_scan import scan


TOKEN = 'npm_' + 'A1b2C3' * 6
VALUE = 'A1b2C3d4E5f6G7h8'


class PlaceholderLookbackBoundaryTests(unittest.TestCase):
    def prefix(self, stem, distance, generic=False):
        tail = 'token="' if generic else ''
        opening = "placeholder='"
        return stem + opening + ' ' * (distance - len(opening + tail)) + tail

    def test_extended_names_at_lookback_edge_keep_original_hint(self):
        for stem in ('data-', 'custom_', 'not', '9', 'é'):
            for distance in (39, 40, 41):
                with self.subTest(stem=stem, distance=distance):
                    self.assertIsNone(scan._pattern_hint(
                        TOKEN, self.prefix(stem, distance)))
                    self.assertIsNone(scan._value_hint(
                        VALUE, self.prefix(stem, distance, generic=True)))

    def test_real_attributes_keep_existing_lookback_limit(self):
        for stem in ('', '<input ', '{', 'é '):
            for distance in (39, 40, 41):
                expected = 'form-placeholder?' if distance <= 40 else None
                with self.subTest(stem=stem, distance=distance):
                    self.assertEqual(scan._pattern_hint(
                        TOKEN, self.prefix(stem, distance)), expected)
                    self.assertEqual(scan._value_hint(
                        VALUE, self.prefix(stem, distance, generic=True)), expected)
        for hint, value in ((scan._pattern_hint, TOKEN), (scan._value_hint, VALUE)):
            self.assertIsNone(hint(value, self.prefix(' ', 39) + "'"))
            self.assertEqual(hint(value, "data-placeholder='' placeholder='"),
                             'form-placeholder?')

    def test_scan_preserves_severity_gate_redaction_and_triage(self):
        for generic, value, severity in ((False, TOKEN, 'high'), (True, VALUE, 'medium')):
            for stem, hinted in (('data-', False), ('<input ', True)):
                with self.subTest(generic=generic, stem=stem):
                    text = self.prefix(stem, 40, generic) + value + ('"' if generic else '') + "'"
                    with tempfile.TemporaryDirectory() as root:
                        Path(root, 'settings.txt').write_text(text, encoding='utf-8')
                        out, err = io.StringIO(), io.StringIO()
                        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                            code = scan.main(['scan.py', root, '--no-osv', '--triage',
                                              '--fail-on', severity])
                    self.assertEqual(code, 0 if hinted else 1, err.getvalue())
                    report = json.loads(out.getvalue())
                    hit, = report['findings']
                    self.assertEqual(hit['severity'], 'low' if hinted else severity)
                    self.assertEqual(hit['file'], 'settings.txt')
                    self.assertEqual(hit['line'], 1)
                    self.assertEqual(hit['evidence'], value[:4] + '…' +
                                     (' (form-placeholder?)' if hinted else ''))
                    triage = report['triage'][hit['id']]
                    self.assertEqual(triage['likely_false_positive'], hinted)
                    if not hinted:
                        self.assertEqual(triage['action'], 'review')
                    self.assertNotIn(value, out.getvalue())
