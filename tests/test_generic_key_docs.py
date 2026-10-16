"""Pin the generic-assignment names and limits documented in the README."""
from pathlib import Path
import tempfile
import unittest

import scan


class GenericKeyDocumentationTests(unittest.TestCase):
    def findings(self, text):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "settings.txt"
            path.write_text(text, encoding="utf-8")
            found = []
            scan.scan_secrets(directory, [str(path)],
                              lambda *args, **kwargs: found.append((args, kwargs)))
            return found

    def test_documented_names_delimiters_case_and_quotes(self):
        value = "aB3dE6gH9jK2mN5p"  # synthetic, exactly 16 characters
        for name in ("api_key", "api-key", "apikey", "secret", "password", "passwd", "token"):
            for spelling in (name, name.upper()):
                for delimiter in ("=", ":"):
                    for quote in ("'", '"'):
                        for key_quote in ("", quote):
                            with self.subTest(name=spelling, delimiter=delimiter,
                                              quote=quote, key_quote=key_quote):
                                text = (f"{key_quote}{spelling}{key_quote} {delimiter} "
                                        f"{quote}{value}{quote}")
                                self.assertEqual(self.findings(text), [
                                    (("secret", "medium", "settings.txt", 1), {
                                        "summary": f"Hardcoded {name} assignment",
                                        "evidence": "aB3d…",
                                    })])

    def test_bare_key_short_unquoted_and_whitespace_values_are_not_generic_hits(self):
        value = "aB3dE6gH9jK2mN5p"
        for text in (f'key = "{value}"', f'"KEY": "{value}"',
                     f'password = "{value[:-1]}"', f'password = {value}',
                     f'password = "{value} has spaces"'):
            with self.subTest(text=text):
                self.assertEqual(self.findings(text), [])

    def test_readme_names_match_documented_contract(self):
        readme = (Path(__file__).resolve().parents[1] / "README.md").read_text()
        self.assertIn("bare `key` is not recognized", readme)
        self.assertNotIn('generic `key/secret/password/token', readme)


if __name__ == "__main__":
    unittest.main()
