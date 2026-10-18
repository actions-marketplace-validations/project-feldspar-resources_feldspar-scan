"""Only direct entries of pnpm's packages section belong in the inventory."""
from pathlib import Path
import tempfile
import unittest

from test_hardening import load


class PnpmSectionIsolationTests(unittest.TestCase):
    def test_unrelated_sections_and_nested_keys_do_not_become_packages(self):
        scan = load("pnpm_section_parser", "scan.py")
        for section in ("importers", "snapshots", "settings"):
            for newline in (chr(10), chr(13) + chr(10)):
                with self.subTest(section=section, newline=repr(newline)):
                    text = f"""{section}:
  before@9.0.0:
packages:
  first@1.2.3:
    dependencies:
      nested@8.0.0:
  '@scope/second@4.5.6':
    resolution: {{}}
{section}:
  after@9.0.0:
""".replace(chr(10), newline)
                    self.assertEqual(scan.parse_pnpm_lock(text), [
                        ("npm", "first", "1.2.3"),
                        ("npm", "@scope/second", "4.5.6"),
                    ])

    def test_collection_excludes_snapshot_only_packages(self):
        scan = load("pnpm_section_collection", "scan.py")
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            mixed = root / "pnpm-lock.yaml"
            mixed.write_text("""packages:
  actual@1.2.3:
    resolution: {}
snapshots:
  actual@1.2.3:
    dependencies: {}
  snapshot-only@9.0.0:
    dependencies: {}
""", encoding="utf-8")
            other = root / "other" / "pnpm-lock.yaml"
            other.parent.mkdir()
            other.write_text("""snapshots:
  absent@9.0.0:
    dependencies: {}
""", encoding="utf-8")
            self.assertEqual(scan.collect_packages(str(root), [str(mixed), str(other)]), {
                ("npm", "actual", "1.2.3"): "pnpm-lock.yaml",
            })
            self.assertEqual(scan.PARSED_LOCKFILES, [
                "pnpm-lock.yaml", "other/pnpm-lock.yaml",
            ])
            self.assertEqual(scan.ERRORS, [])
