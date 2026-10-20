"""Tab-indented output changes whitespace only; all scans stay offline."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from test_scan import scan


class TabIndentTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name) / 'repo'
        self.root.mkdir()
        (self.root / 'café').mkdir()
        self.fixture = self.root / 'café' / 'compose.yaml'
        self.fixture.write_text(chr(10).join(('services:', '  app:', '    privileged: true', '')),
                                encoding='utf-8')

    def report(self, *flags):
        with mock.patch.object(scan, 'query_osv') as query, \
                mock.patch.object(scan.subprocess, 'run') as process, \
                contextlib.redirect_stdout(io.StringIO()) as out, \
                contextlib.redirect_stderr(io.StringIO()) as err:
            code = scan.main(['scan.py', str(self.root), '--no-osv',
                              '--no-commit', '--no-timestamp', *flags])
            query.assert_not_called()
            process.assert_not_called()
        return code, out.getvalue(), err.getvalue()

    def test_exact_bytes_and_report_gate_triage_equivalence(self):
        for threshold, code in [('none', 0), ('medium', 1), ('high', 0)]:
            for extra in [(), ('--sort-keys',), ('--unicode-json',),
                          ('--summary-only', '--sort-keys', '--unicode-json')]:
                with self.subTest(threshold=threshold, extra=extra):
                    flags = ('--triage', '--fail-on', threshold, *extra)
                    baseline = self.report(*flags)
                    result = self.report(*flags, '--tab-indent')
                    self.assertEqual(result[0], code)
                    self.assertEqual(result[2], baseline[2])
                    document = json.loads(baseline[1])
                    self.assertEqual(json.loads(result[1]), document)
                    self.assertEqual(result[1], json.dumps(
                        document, indent='\t', sort_keys='--sort-keys' in extra,
                        ensure_ascii='--unicode-json' not in extra) + chr(10))
                    self.assertIn(chr(10) + '\t"', result[1])

    def test_precedence_and_invocation_isolation(self):
        default = self.report()
        compact = self.report('--compact')
        tabs = self.report('--tab-indent')
        self.assertEqual(tabs[0], 0)
        self.assertEqual(self.report('--tab-indent', '--pretty'), default)
        self.assertEqual(self.report('--tab-indent', '--compact'), compact)
        self.assertEqual(self.report('--compact', '--tab-indent'), tabs)
        self.assertEqual(self.report('--pretty', '--tab-indent', '--tab-indent'), tabs)
        for width in range(9):
            with self.subTest(width=width):
                self.assertEqual(self.report('--tab-indent', '--indent', str(width)),
                                 self.report('--indent', str(width)))
                self.assertEqual(self.report('--indent', str(width), '--tab-indent'), tabs)
        self.assertEqual(self.report(), default)

    def test_named_file_stdout_and_empty_report(self):
        self.fixture.unlink()
        flags = ('--tab-indent', '--unicode-json', '--sort-keys')
        expected = self.report(*flags)
        self.assertEqual(expected[0], 0)
        self.assertEqual(json.loads(expected[1])['findings'], [])
        self.assertEqual(self.report(*flags, '--json', '-'), expected)
        destination = self.root.parent / 'report.json'
        result = self.report(*flags, '--json', str(destination), '--quiet')
        self.assertEqual(result, (0, '', ''))
        self.assertEqual(destination.read_bytes(), expected[1].encode('utf-8'))

    def test_help_describes_tab_indentation(self):
        result = self.report('--help')
        self.assertEqual((result[0], result[2]), (0, ''))
        self.assertIn('--tab-indent', result[1])
        self.assertIn('one tab per JSON level', result[1])
        self.assertIn('last formatting flag wins', result[1])
