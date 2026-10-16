"""Pin the documented byte-based secret text limit using synthetic inputs."""
import contextlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import scan


class SecretSizeLimitDocsTests(unittest.TestCase):
    # Synthetic generic value; no provider credential or network access.
    newline = bytes([10])
    assignment = b'password = "Ab7Cd8Ef9Gh2Jk3L"' + newline

    def scan_bytes(self, content):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root, 'settings.txt')
            path.write_bytes(content)
            stdout = io.StringIO()
            with mock.patch.object(scan, 'http_json', side_effect=AssertionError('network')), \
                    contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(io.StringIO()):
                code = scan.main(['scan.py', root, '--no-osv', '--fail-on', 'medium'])
            return code, json.loads(stdout.getvalue())

    def test_exact_one_mib_file_is_scanned(self):
        content = self.assignment + self.newline * (1024 * 1024 - len(self.assignment))
        code, report = self.scan_bytes(content)
        self.assertEqual(code, 1)
        self.assertEqual(report['summary']['secret_hits'], 1)
        hit, = report['findings']
        self.assertEqual((hit['line'], hit['severity']), (1, 'medium'))
        self.assertEqual(hit['evidence'], 'Ab7C…')
        self.assertNotIn('Ab7Cd8Ef9Gh2Jk3L', json.dumps(report))

    def test_one_byte_over_skips_entire_file_including_first_line(self):
        content = self.assignment + self.newline * (1024 * 1024 + 1 - len(self.assignment))
        code, report = self.scan_bytes(content)
        self.assertEqual(code, 0)
        self.assertEqual(report['findings'], [])
        # Neither file selection nor these flags measure successful text coverage.
        self.assertEqual(report['summary']['files_scanned'], 1)
        self.assertEqual(report['summary']['truncated'], {'files': False, 'findings': False})
        self.assertNotIn('errors', report)

    def test_multibyte_limit_counts_bytes_not_characters(self):
        text = self.assignment.decode() + ('é' + chr(10)) * 350000
        self.assertLess(len(text), 1024 * 1024)
        self.assertGreater(len(text.encode()), 1024 * 1024)
        code, report = self.scan_bytes(text.encode())
        self.assertEqual(code, 0)
        self.assertEqual(report['findings'], [])

    def test_oversize_file_does_not_prevent_other_file_findings(self):
        with tempfile.TemporaryDirectory() as root:
            large = Path(root, 'large.txt')
            small = Path(root, 'small.txt')
            large.write_bytes(self.assignment + self.newline * (1024 * 1024))
            small.write_bytes(self.assignment)
            hits = []
            scan.scan_secrets(root, [str(large), str(small)],
                              lambda *args, **kwargs: hits.append((args, kwargs)))
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0][0], ('secret', 'medium', 'small.txt', 1))


if __name__ == '__main__':
    unittest.main()
