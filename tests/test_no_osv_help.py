"""Keep --no-osv help aligned with behavior; all network access is mocked."""
import contextlib
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

from test_scan import scan


class NoOsvHelpTests(unittest.TestCase):
    def run_cli(self, *args):
        output = io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(io.StringIO()):
            status = scan.main(['scan.py', *args])
        return status, output.getvalue()

    def test_help_explains_scope_and_url_clone(self):
        for args in ((), ('-h',), ('--help',)):
            with self.subTest(args=args):
                status, help_text = self.run_cli(*args)
                self.assertEqual(status, 0)
                self.assertIn('--no-osv        skip OSV dependency advisory lookups', help_text)
                self.assertIn('package inventory and local secret/config checks still run', help_text)
                self.assertIn('URL targets still clone; use a local path for offline scanning', help_text)

    def test_local_scan_keeps_inventory_findings_and_gate_without_osv(self):
        with tempfile.TemporaryDirectory() as root:
            Path(root, 'requirements.txt').write_text('example-package==1.2.3\n')
            # Synthetic value, not a live credential; this also triggers the .env check.
            Path(root, '.env').write_text('password="A1b2C3d4E5f6G7h8"\n')
            with mock.patch.object(scan, 'query_osv', side_effect=AssertionError('OSV called')) as query:
                with mock.patch.object(scan, 'http_json', side_effect=AssertionError('HTTP called')):
                    status, output = self.run_cli(root, '--no-osv', '--fail-on', 'high')
            query.assert_not_called()
            report = json.loads(output)
            self.assertEqual(status, 1)
            self.assertFalse(report['summary']['osv_enabled'])
            self.assertEqual(report['summary']['packages_found'], 1)
            self.assertEqual(report['summary']['lockfiles_parsed'], ['requirements.txt'])
            self.assertEqual({f['category'] for f in report['findings']}, {'secret', 'config'})

    def test_url_target_still_clones_with_no_osv(self):
        target = 'https://example.invalid/synthetic/repo.git'
        with tempfile.TemporaryDirectory() as root:
            with mock.patch.object(scan.tempfile, 'mkdtemp', return_value=root):
                with mock.patch.object(scan.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, '', '')) as run:
                    with mock.patch.object(scan, 'git_head', return_value=None):
                        with mock.patch.object(scan, 'http_json', side_effect=AssertionError('HTTP called')):
                            status, output = self.run_cli(target, '--no-osv')
            self.assertEqual(status, 0)
            run.assert_called_once()
            self.assertEqual(run.call_args.args[0],
                             ['git', '-c', 'core.symlinks=false', 'clone', '--depth', '1', target, root])
            self.assertFalse(json.loads(output)['summary']['osv_enabled'])
