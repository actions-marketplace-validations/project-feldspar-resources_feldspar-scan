"""Incomplete TOML package records must not borrow neighboring fields."""
import os
import tempfile
import unittest
from unittest import mock

from test_scan import scan


class TomlIncompleteRecordTests(unittest.TestCase):
    FORMATS = (("poetry.lock", "PyPI"), ("uv.lock", "PyPI"),
               ("Cargo.lock", "crates.io"))
    INCOMPLETE = (
        '''[[package]]
name="orphan"
[[package]]
version="9.9"
''',
        '''[[package]]
version="9.9"
[[package]]
name="orphan"
''',
        '''[[package]]
name=""
version="9.9"
''',
        '''[[package]]
name="orphan"
version=""
''',
        '''[[package]]
''',
    )
    BEFORE = '''[[package]]
name="before"
version="1.2.3"
'''
    AFTER = '''[[package]]
name="after"
version="4.5.6"
'''

    def decoders(self):
        modes = [("fallback", None)]
        if scan.tomllib is not None:
            modes.append(("stdlib", scan.tomllib))
        return modes

    def test_incomplete_records_do_not_join_or_discard_valid_neighbors(self):
        for mode, decoder in self.decoders():
            for filename, ecosystem in self.FORMATS:
                for incomplete in self.INCOMPLETE:
                    with self.subTest(mode=mode, filename=filename,
                                      incomplete=incomplete), \
                         mock.patch.object(scan, "tomllib", decoder):
                        handler = scan.DEP_HANDLERS[filename]
                        self.assertEqual(handler(incomplete), [])
                        text = incomplete + self.BEFORE + incomplete + self.AFTER + incomplete
                        self.assertEqual(handler(text), [
                            (ecosystem, "before", "1.2.3"),
                            (ecosystem, "after", "4.5.6"),
                        ])

    def test_collection_keeps_complete_records_and_manifest_attribution(self):
        for mode, decoder in self.decoders():
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as root, \
                 mock.patch.object(scan, "tomllib", decoder), \
                 mock.patch.object(scan, "ERRORS", []), \
                 mock.patch.object(scan, "PARSED_LOCKFILES", []):
                paths, expected = [], {}
                for filename, ecosystem in self.FORMATS:
                    path = os.path.join(root, filename)
                    name = filename.split(".")[0]
                    with open(path, "w", encoding="utf-8") as fh:
                        fh.write("".join(self.INCOMPLETE))
                        fh.write('''[[package]]
name="%s"
version="1.0"
''' % name)
                    paths.append(path)
                    expected[(ecosystem, name, "1.0")] = filename
                self.assertEqual(scan.collect_packages(root, paths), expected)
                self.assertEqual(scan.PARSED_LOCKFILES, [f for f, _ in self.FORMATS])
                self.assertEqual(scan.ERRORS, [])
