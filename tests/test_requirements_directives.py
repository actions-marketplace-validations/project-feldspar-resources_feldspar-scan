"""Requirements options and comments must not become dependency pins."""
import unittest

from test_scan import scan


class RequirementsDirectiveTests(unittest.TestCase):
    def test_option_lines_with_pin_like_values_are_ignored(self):
        directives = (
            "-r requirements==9.9",
            "--requirement=requirements==9.9",
            "-c constraints==9.9",
            "--constraint=constraints==9.9",
            "-e local-project==9.9",
            "--editable=local-project==9.9",
            "--find-links=wheelhouse==9.9",
            "--index-url=https://example.invalid/simple?q==9.9",
            "--extra-index-url=https://example.invalid/extra?q==9.9",
            "--no-binary=demo==9.9",
            "--only-binary=demo==9.9",
            "--unknown-option=demo==9.9",
        )
        for directive in directives:
            for indent in ("", "  ", chr(9)):
                with self.subTest(directive=directive, indent=repr(indent)):
                    text = chr(10).join((
                        "before-demo==1.2.3", indent + directive,
                        "after-demo[extra]==4.5.6"))
                    self.assertEqual(scan.parse_requirements(text), [
                        ("PyPI", "before-demo", "1.2.3"),
                        ("PyPI", "after-demo", "4.5.6"),
                    ])

    def test_comment_pins_are_ignored_without_losing_real_pins(self):
        text = """# comment-demo==9.9
  # indented-demo==9.9
first-demo==1.2.3 # trailing-demo==9.9
unversioned-demo # hidden-demo==9.9
last-demo==4.5.6
"""
        self.assertEqual(scan.parse_requirements(text), [
            ("PyPI", "first-demo", "1.2.3"),
            ("PyPI", "last-demo", "4.5.6"),
        ])
