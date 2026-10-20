"""Pin the documented Yarn source exclusions without contacting any service."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from test_scan import scan


EXCLUDED = {
    'workspace': '*', 'patch': 'pkg@npm:1.2.3#synthetic.patch',
    'portal': './local', 'link': './local', 'file': './local.tgz',
    'exec': './generate.js', 'git': '//example.invalid/repo.git',
    'github': 'example/repo', 'http': '//example.invalid/pkg.tgz',
    'https': '//example.invalid/pkg.tgz',
}


def excluded_lockfile():
    return '''__metadata:
  version: 8
''' + ''.join(
        '''"excluded-%s@%s:%s":
  version: 1.2.3
''' % (proto, proto, target)
        for proto, target in EXCLUDED.items())


class YarnSourceScopeDocsTests(unittest.TestCase):
    def report(self, root, *options):
        with contextlib.redirect_stdout(io.StringIO()) as output:
            status = scan.main(['scan.py', str(root), *options])
        self.assertEqual(status, 0)
        return json.loads(output.getvalue())

    def test_excluded_protocols_keep_registry_positive_controls(self):
        for proto, target in EXCLUDED.items():
            for name in ('pkg', '@scope/pkg'):
                with self.subTest(protocol=proto, name=name):
                    text = ('''"%s@%s:%s":
  version: 1.2.3
'''
                            '''"%s@npm:^2.0.0":
  version: 2.1.0
'''
                            '''legacy@^3.0.0:
  version "3.2.0"
'''
                            % (name, proto, target, name))
                    self.assertEqual(scan.parse_yarn_lock(text), [
                        ('npm', name, '2.1.0'), ('npm', 'legacy', '3.2.0')])

    def test_mixed_descriptor_list_filters_each_source(self):
        text = ('''"local@file:./local, @scope/registry@npm:^2.0.0":
'''
                '''  version: 2.1.0
''')
        self.assertEqual(scan.parse_yarn_lock(text), [
            ('npm', '@scope/registry', '2.1.0')])

    def test_advisory_queries_only_include_registry_entries(self):
        text = excluded_lockfile() + (
            '''"@scope/registry@npm:^2.0.0":
  version: 2.1.0
'''
            '''legacy@^3.0.0:
  version "3.2.0"
''')
        with tempfile.TemporaryDirectory() as root:
            Path(root, 'yarn.lock').write_text(text, encoding='utf-8')
            with mock.patch.object(scan, 'query_osv', return_value={}) as query, \
                    mock.patch.object(scan, 'http_json', side_effect=AssertionError('offline')):
                report = self.report(root)
            query.assert_called_once()
            self.assertEqual(set(query.call_args.args[0]), {
                ('npm', '@scope/registry', '2.1.0'), ('npm', 'legacy', '3.2.0')})
            self.assertEqual(report['summary']['packages_found'], 2)
            self.assertEqual(report['summary']['packages_by_manifest'], {'yarn.lock': 2})

    def test_excluded_only_lockfile_is_parsed_but_has_no_advisory_requests(self):
        for options in ((), ('--no-osv',)):
            with self.subTest(options=options), tempfile.TemporaryDirectory() as root:
                Path(root, 'yarn.lock').write_text(excluded_lockfile(), encoding='utf-8')
                with mock.patch.object(scan, 'http_json', side_effect=AssertionError('offline')) as http:
                    report = self.report(root, *options)
                http.assert_not_called()
                self.assertEqual(report['summary']['packages_found'], 0)
                self.assertEqual(report['summary']['lockfiles_parsed'], ['yarn.lock'])
                self.assertEqual(report['summary']['packages_by_manifest'], {'yarn.lock': 0})
                self.assertEqual(report['summary']['by_category']['dependency-vuln'], 0)


if __name__ == '__main__':
    unittest.main()
