"""Pin the documented require-only inventory without invoking Go or the network."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from test_scan import scan


class GoDirectiveScopeDocsTests(unittest.TestCase):
    NL = chr(10)
    EXPECTED = {
        ('Go', 'example.invalid/original', 'v1.2.3'),
        ('Go', 'example.invalid/local', 'v2.3.4'),
        ('Go', 'example.invalid/excluded', 'v3.4.5'),
    }

    def manifest(self, block):
        requires = self.NL.join([
            'require (',
            ' example.invalid/original v1.2.3',
            ' example.invalid/local v2.3.4 // indirect',
            ' example.invalid/excluded v3.4.5',
            ')', '',
        ])
        replacements = [
            'example.invalid/original v1.2.3 => example.invalid/fork v9.9.9',
            'example.invalid/local => ./replacement',
        ]
        if block:
            lines = ['replace (', *replacements, ')', 'exclude (',
                     'example.invalid/excluded v3.4.5', ')']
        else:
            lines = ['replace ' + row for row in replacements]
            lines.append('exclude example.invalid/excluded v3.4.5')
        prefix = self.NL.join(['module example.invalid/app', '', 'go 1.22', ''])
        return prefix + requires + self.NL.join(lines) + self.NL

    def report(self, root, *options):
        with contextlib.redirect_stdout(io.StringIO()) as output, \
                contextlib.redirect_stderr(io.StringIO()):
            status = scan.main(['scan.py', str(root), *options])
        return status, json.loads(output.getvalue())

    def test_replacements_and_exclusions_do_not_rewrite_require_inventory(self):
        for block in (False, True):
            with self.subTest(block=block):
                parsed = scan.parse_go_mod(self.manifest(block))
                self.assertEqual(set(parsed), self.EXPECTED)
                self.assertEqual(len(parsed), 3)

    def test_directives_alone_do_not_add_inventory(self):
        self.assertEqual(scan.parse_go_mod(self.NL.join([
            'module example.invalid/app',
            'replace example.invalid/original => example.invalid/fork v9.9.9',
            'exclude example.invalid/excluded v3.4.5', '',
        ])), [])

    def test_query_uses_original_require_identities_without_go_resolution(self):
        for block in (False, True):
            with self.subTest(block=block), tempfile.TemporaryDirectory() as root:
                Path(root, 'go.mod').write_text(self.manifest(block), encoding='utf-8')
                # A sibling go.sum cannot supply the replacement identity either.
                Path(root, 'go.sum').write_text(
                    'example.invalid/fork v9.9.9 h1:synthetic' + self.NL, encoding='utf-8')
                with mock.patch.object(scan, 'query_osv', return_value={}) as query, \
                        mock.patch.object(scan, 'http_json', side_effect=AssertionError('offline')), \
                        mock.patch.object(scan, 'git_head', return_value=None), \
                        mock.patch.object(scan.subprocess, 'run', side_effect=AssertionError('no tools')):
                    status, report = self.report(root)
                query.assert_called_once()
                self.assertEqual(set(query.call_args.args[0]), self.EXPECTED)
                self.assertEqual(status, 0)
                self.assertEqual(report['summary']['packages_found'], 3)
                self.assertEqual(report['summary']['lockfiles_parsed'], ['go.mod'])

    def test_no_osv_preserves_require_inventory_without_queries(self):
        with tempfile.TemporaryDirectory() as root:
            Path(root, 'go.mod').write_text(self.manifest(True), encoding='utf-8')
            with mock.patch.object(scan, 'query_osv') as query, \
                    mock.patch.object(scan, 'http_json', side_effect=AssertionError('offline')):
                status, report = self.report(root, '--no-osv')
            query.assert_not_called()
            self.assertEqual(status, 0)
            self.assertEqual(report['summary']['packages_by_ecosystem'], {'Go': 3})
            self.assertEqual(report['summary']['packages_by_manifest'], {'go.mod': 3})
            self.assertFalse(report['summary']['osv_enabled'])


if __name__ == '__main__':
    unittest.main()
