"""Unicode assignment-name boundaries using synthetic, offline values."""
import tempfile
import unittest
from pathlib import Path

from test_scan import _collect, scan


class GenericUnicodeBoundaryTests(unittest.TestCase):
    value = "Ab3Cd6Ef9Gh2Jk5M"

    def findings(self, text):
        with tempfile.TemporaryDirectory() as root:
            Path(root, "settings.txt").write_text(text, encoding="utf-8")
            return _collect(root, scan.scan_secrets)

    def test_unicode_alphanumeric_prefixes_are_part_of_longer_names(self):
        for prefix in ("é", "Ω", "Ж", "密", "١", "９"):
            for name in ("api_key", "api-key", "apikey", "secret", "password", "passwd", "token"):
                with self.subTest(prefix=prefix, name=name):
                    self.assertEqual(self.findings(f'{prefix}{name}="{self.value}"'), [])

    def test_standalone_quoted_and_separated_names_keep_metadata(self):
        for name in ("token", "TOKEN", '"secret"', "'password'", "密_token", "é-secret"):
            with self.subTest(name=name):
                hits = self.findings('heading' + chr(10) + f'{name}="{self.value}"')
                self.assertEqual(len(hits), 1)
                self.assertEqual(hits[0]["category"], "secret")
                self.assertEqual(hits[0]["severity"], "medium")
                self.assertEqual(hits[0]["file"], "settings.txt")
                self.assertEqual(hits[0]["line"], 2)
                self.assertEqual(hits[0]["evidence"], scan.redact(self.value))
                self.assertNotIn(self.value, str(hits))

    def test_rejected_name_does_not_hide_later_assignment(self):
        hits = self.findings(f'密secret="{self.value}"; token="{self.value}"')
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["summary"], "Hardcoded token assignment")

    def test_provider_detection_is_independent_of_assignment_name(self):
        synthetic = "ghp_" + "A1b2C3d4E5f6" * 3
        hits = self.findings(f'密token="{synthetic}"')
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["summary"], "GitHub token detected")
        self.assertEqual(hits[0]["severity"], "high")
        self.assertNotIn(synthetic, str(hits))
