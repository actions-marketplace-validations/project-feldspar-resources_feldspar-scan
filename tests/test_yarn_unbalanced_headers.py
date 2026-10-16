"""Yarn lockfile resilience to incomplete quoted headers."""

import unittest

import scan


class YarnUnbalancedHeaderTests(unittest.TestCase):
    def test_unbalanced_quoted_headers_are_skipped(self):
        text = '''"missing-close@npm:^1:
  version: 1.0.0
missing-open@npm:^2":
  version: 2.0.0
"good@npm:^3":
  version: 3.0.0
'''
        self.assertEqual(scan.parse_yarn_lock(text), [("npm", "good", "3.0.0")])
