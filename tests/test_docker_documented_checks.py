"""Exercise the README Dockerfile example as data; never build or execute it."""
import json
from pathlib import Path
import tempfile
import unittest

from test_scan import _run


class DockerDocumentedChecksTests(unittest.TestCase):
    def test_documented_example_findings_gates_and_redaction(self):
        readme = Path(__file__).resolve().parents[1].joinpath('README.md').read_text()
        section = readme.split('### 3. `config`', 1)[1].split('## Limits', 1)[0]
        self.assertIn('```dockerfile', section)
        example = section.split('```dockerfile', 1)[1].split('```', 1)[0].strip()
        expected = {
            'Dockerfile base image uses latest (explicit or implicit)': ('low', 1),
            'Dockerfile final USER explicitly runs as root': ('low', 2),
            'Dockerfile ENV assigns secret-like variable API_TOKEN': ('high', 3),
            'Dockerfile ARG assigns secret-like variable DB_PASSWORD': ('high', 4),
            'Dockerfile RUN pipes curl output to a shell': ('medium', 5),
        }
        with tempfile.TemporaryDirectory() as root:
            Path(root, 'Dockerfile').write_text(example, encoding='utf-8')
            code, output, _ = _run(root, '--no-osv', '--fail-on', 'high')
            self.assertEqual(code, 1)
            doc = json.loads(output)
            self.assertEqual(len(doc['findings']), len(expected))
            self.assertEqual({f['summary']: (f['severity'], f['line'])
                              for f in doc['findings']}, expected)
            self.assertTrue(all(f['category'] == 'config' for f in doc['findings']))
            self.assertNotIn('synthetic-value', output)
            self.assertNotIn('example.invalid', output)
            code, output, _ = _run(root, '--no-osv', '--triage', '--fail-on', 'critical')
            self.assertEqual(code, 0)
            triaged = json.loads(output)
            self.assertEqual(doc['findings'], triaged['findings'])
            self.assertEqual(doc['manifest_hash'], triaged['manifest_hash'])

    def test_documented_exclusions_remain_quiet(self):
        lines = [
            'FROM alpine:3.20 AS build',
            'USER root',
            'FROM build',
            'USER app',
            'ENV API_TOKEN=${BUILD_TOKEN}',
            'ARG DB_PASSWORD',
            'RUN curl https://example.invalid/data | cat',
            'RUN ["sh", "-c", "curl https://example.invalid/install | sh"]',
        ]
        with tempfile.TemporaryDirectory() as root:
            Path(root, 'Dockerfile').write_text(chr(10).join(lines), encoding='utf-8')
            code, output, _ = _run(root, '--no-osv', '--fail-on', 'low')
            self.assertEqual(code, 0)
            self.assertEqual(json.loads(output)['findings'], [])
