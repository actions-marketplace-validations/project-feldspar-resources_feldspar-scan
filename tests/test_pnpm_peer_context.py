"""Peer contexts must not become package names or advisory query versions."""
from pathlib import Path
import tempfile
import unittest

from test_hardening import load


class PnpmPeerContextTests(unittest.TestCase):
    def test_peer_suffixes_preserve_package_identity(self):
        scan = load("pnpm_peer_parser", "scan.py")
        for name in ("demo", "@scope/demo"):
            for prefix in ("", "/"):
                for quote in ("", "'"):
                    for peers in ("(peer@2.0.0)",
                                  "(@scope/peer@2.0.0)(other@3.0.0)"):
                        with self.subTest(name=name, prefix=prefix,
                                          quote=quote, peers=peers):
                            key = f"{prefix}{name}@1.2.3{peers}"
                            text = f"""packages:
  {quote}{key}{quote}:
    resolution: {{}}
  neighbor@4.5.6:
    resolution: {{}}
"""
                            self.assertEqual(scan.parse_pnpm_lock(text), [
                                ("npm", name, "1.2.3"),
                                ("npm", "neighbor", "4.5.6"),
                            ])

    def test_collection_deduplicates_peer_variants_but_preserves_versions(self):
        scan = load("pnpm_peer_collection", "scan.py")
        text = """packages:
  '@scope/demo@1.2.3(peer@2.0.0)':
    resolution: {}
  '@scope/demo@1.2.3(@scope/peer@3.0.0)(other@4.0.0)':
    resolution: {}
  '@scope/demo@1.2.4(peer@2.0.0)':
    resolution: {}
  plain@5.6.7:
    resolution: {}
"""
        with tempfile.TemporaryDirectory() as root:
            path = Path(root, "pnpm-lock.yaml")
            path.write_text(text, encoding="utf-8")
            self.assertEqual(scan.collect_packages(root, [str(path)]), {
                ("npm", "@scope/demo", "1.2.3"): "pnpm-lock.yaml",
                ("npm", "@scope/demo", "1.2.4"): "pnpm-lock.yaml",
                ("npm", "plain", "5.6.7"): "pnpm-lock.yaml",
            })
        self.assertEqual(scan.PARSED_LOCKFILES, ["pnpm-lock.yaml"])
        self.assertEqual(scan.ERRORS, [])
