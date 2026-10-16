"""pnpm package-section comments must not hide subsequent dependencies."""
import importlib.util
from pathlib import Path
import unittest


spec = importlib.util.spec_from_file_location(
    "pnpm_comments_scan", Path(__file__).resolve().parents[1] / "scan.py")
scan = importlib.util.module_from_spec(spec)
spec.loader.exec_module(scan)


class PnpmCommentTests(unittest.TestCase):
    def test_comments_preserve_package_section_and_real_sections_end_it(self):
        for comment in ("# package group", "#", "# snapshots:", "  # package group"):
            with self.subTest(comment=comment):
                text = f"""lockfileVersion: '9.0'
# packages:
  outside@9.9.9:
packages:
  first@1.0.0:
{comment}
  '@scope/second@2.0.0':
snapshots:
# packages:
  snapshot-only@3.0.0:
"""
                self.assertEqual(scan.parse_pnpm_lock(text), [
                    ("npm", "first", "1.0.0"),
                    ("npm", "@scope/second", "2.0.0"),
                ])


if __name__ == "__main__":
    unittest.main()
