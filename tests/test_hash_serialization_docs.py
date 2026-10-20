"""Exercise the README hash recipe against Unicode reports without network access."""
import contextlib
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from test_scan import scan


class HashSerializationDocsTests(unittest.TestCase):
    def test_readme_recipe_recomputes_hash_across_report_formats(self):
        readme = (Path(__file__).resolve().parents[1] / "README.md").read_text()
        newline = chr(10)
        recipe = readme.split('```python' + newline + 'import hashlib' + newline, 1)[1].split('```', 1)[0]
        recipe = 'import hashlib' + newline + recipe
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary, "café-東京-🚀")
            root.mkdir()
            Path(root, "Dockerfile").write_text("FROM scratch" + newline, encoding="utf-8")
            expected_hash = None
            for flags in ([], ["--unicode-json"], ["--compact", "--unicode-json"],
                          ["--sort-keys", "--indent", "4", "--triage"]):
                with self.subTest(flags=flags):
                    output = io.StringIO()
                    with mock.patch.object(scan, "git_head", return_value="a" * 40), \
                            mock.patch.object(scan, "http_json", side_effect=AssertionError("network")), \
                            contextlib.redirect_stdout(output):
                        self.assertEqual(scan.main(["scan.py", str(root), "--no-osv", *flags]), 0)
                    report = json.loads(output.getvalue())
                    self.assertTrue(report["findings"])
                    with mock.patch("builtins.open", mock.mock_open(read_data=output.getvalue())):
                        namespace = {}
                        exec(compile(recipe, "README.md hash recipe", "exec"), namespace)
                    canonical = namespace["canonical"]
                    self.assertTrue(canonical.isascii())
                    self.assertIn(r"\ud83d\ude80", canonical)
                    self.assertNotEqual(hashlib.sha256((canonical + newline).encode()).hexdigest(),
                                        report["manifest_hash"])
                    unescaped = json.dumps(namespace["payload"], sort_keys=True,
                                           separators=(",", ":"), ensure_ascii=False)
                    self.assertNotEqual(hashlib.sha256(unescaped.encode()).hexdigest(),
                                        report["manifest_hash"])
                    if expected_hash is None:
                        expected_hash = report["manifest_hash"]
                    self.assertEqual(report["manifest_hash"], expected_hash)
