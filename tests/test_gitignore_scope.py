"""Pin the documented local scan scope using an offline, synthetic Git tree."""
import contextlib
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

from test_scan import scan


class GitignoreScopeTests(unittest.TestCase):
    def test_untracked_and_ignored_files_are_scanned_and_can_trip_gate(self):
        with tempfile.TemporaryDirectory() as root:
            def git(*args):
                return subprocess.run(
                    ['git', '-C', root, *args], check=True,
                    capture_output=True, text=True).stdout.splitlines()

            git('init', '-q')
            Path(root, '.gitignore').write_text('ignored.txt' + chr(10), encoding='utf-8')
            for name in ('tracked.txt', 'untracked.txt', 'ignored.txt'):
                Path(root, name).write_text(
                    'password="A1b2C3d4E5f6G7h8"' + chr(10), encoding='utf-8')
            git('add', '.gitignore', 'tracked.txt')
            self.assertEqual(git('ls-files'), ['.gitignore', 'tracked.txt'])
            self.assertEqual(git('ls-files', '--others', '--exclude-standard'),
                             ['untracked.txt'])
            self.assertEqual(git('check-ignore', 'ignored.txt'), ['ignored.txt'])

            # Scanner exclusions still apply even to a file in Git's index.
            Path(root, 'node_modules').mkdir()
            Path(root, 'node_modules', 'hidden.txt').write_text(
                'password="A1b2C3d4E5f6G7h8"' + chr(10), encoding='utf-8')
            git('add', 'node_modules/hidden.txt')
            Path(root, '.git', 'hidden.txt').write_text(
                'password="A1b2C3d4E5f6G7h8"' + chr(10), encoding='utf-8')

            def report():
                output = io.StringIO()
                with contextlib.redirect_stdout(output), contextlib.redirect_stderr(io.StringIO()):
                    status = scan.main(['scan.py', root, '--no-osv', '--fail-on', 'medium'])
                return status, json.loads(output.getvalue())

            status, doc = report()
            self.assertEqual(status, 1)
            self.assertEqual({f['file'] for f in doc['findings']},
                             {'tracked.txt', 'untracked.txt', 'ignored.txt'})
            self.assertEqual(len(doc['findings']), 3)
            self.assertTrue(all(f['severity'] == 'medium' for f in doc['findings']))
            self.assertNotIn('A1b2C3d4E5f6G7h8', json.dumps(doc))

            # An ignored file alone can trip the gate, without a tracked hit.
            Path(root, 'tracked.txt').unlink()
            Path(root, 'untracked.txt').unlink()
            status, doc = report()
            self.assertEqual(status, 1)
            self.assertEqual([f['file'] for f in doc['findings']], ['ignored.txt'])

            Path(root, 'ignored.txt').unlink()
            status, doc = report()
            self.assertEqual(status, 0)
            self.assertEqual(doc['findings'], [])
