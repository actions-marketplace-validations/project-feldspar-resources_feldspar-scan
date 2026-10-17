"""Non-registry Yarn descriptors must not contaminate registry inventory."""

import unittest

import scan


class YarnProtocolIsolationTests(unittest.TestCase):
    # Literal fixtures make removal of an exclusion visible to these tests.
    SOURCES = (
        "workspace:packages/local", "patch:local@npm:1.2.3#./local.patch",
        "portal:../local", "link:../local", "file:../local.tgz",
        "exec:./generator.js", "git://example.invalid/repo.git#tag",
        "github:example/repo#tag", "http://example.invalid/local.tgz",
        "https://example.invalid/local.tgz",
    )

    def test_non_registry_blocks_reset_pending_names_and_recover(self):
        for name in ("local", "@scope/local"):
            for source in self.SOURCES:
                with self.subTest(name=name, source=source):
                    text = chr(10).join((
                        'unfinished@npm:^9:', '  resolved "unused"',
                        f'"{name}@{source}":', '  version: 1.2.3',
                        'good@npm:^2:', '  version: 2.3.4', '',
                    ))
                    self.assertEqual(scan.parse_yarn_lock(text),
                                     [("npm", "good", "2.3.4")])

    def test_mixed_descriptors_keep_only_registry_names(self):
        for source in self.SOURCES:
            for quoted_list in (False, True):
                with self.subTest(source=source, quoted_list=quoted_list):
                    descriptors = [f"@scope/local@{source}", "good@npm:^2",
                                   "good@npm:~2.3", "@scope/good@npm:^2"]
                    if quoted_list:
                        header = '"' + ', '.join(descriptors) + '"'
                    else:
                        header = ', '.join(f'"{item}"' for item in descriptors)
                    self.assertEqual(
                        scan.parse_yarn_lock(chr(10).join(
                            (header + ':', '  version: 2.3.4', ''))),
                        [("npm", "good", "2.3.4"),
                         ("npm", "@scope/good", "2.3.4")])
