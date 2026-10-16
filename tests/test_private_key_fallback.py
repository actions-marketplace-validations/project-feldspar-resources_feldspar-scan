"""Pin the documented header fallback using synthetic, non-key text only."""
import base64
import json
import tempfile
import unittest
from pathlib import Path

from test_scan import _collect, scan

NL = chr(10)
CRLF = chr(13) + NL


class PrivateKeyFallbackTests(unittest.TestCase):
    def findings(self, text):
        with tempfile.TemporaryDirectory() as root:
            Path(root, "settings.txt").write_text(text, encoding="utf-8")
            return _collect(root, scan.scan_secrets)

    def test_missing_footer_at_body_threshold_preserves_metadata_and_redaction(self):
        body = base64.b64encode(b"not key data!!!").decode()
        self.assertEqual(len(body), 20)
        for label in ("PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY",
                      "OPENSSH PRIVATE KEY", "DSA PRIVATE KEY", "PGP PRIVATE KEY"):
            for newline in (NL, CRLF):
                with self.subTest(label=label, newline=newline):
                    text = newline.join(("heading", "-----BEGIN %s-----" % label,
                                         " \t" + body + " \t", ""))
                    hits = self.findings(text)
                    self.assertEqual(len(hits), 1)
                    hit = hits[0]
                    self.assertEqual(hit["summary"], "Private key block detected")
                    self.assertEqual(hit["category"], "secret")
                    self.assertEqual(hit["severity"], "critical")
                    self.assertEqual(hit["file"], "settings.txt")
                    self.assertEqual(hit["line"], 2)
                    self.assertEqual(hit["evidence"], "----…")
                    self.assertNotIn(body, json.dumps(hits))

    def test_fallback_is_shape_only_and_does_not_downgrade_body_masks(self):
        # Neither repeated padding nor a mask is usable private-key material.
        for body in ("=" * 20, "x" * 20):
            with self.subTest(body=body):
                hits = self.findings("-----BEGIN RSA PRIVATE KEY-----" + NL + body)
                self.assertEqual(len(hits), 1)
                self.assertEqual(hits[0]["severity"], "critical")
                self.assertEqual(hits[0]["evidence"], "----…")

    def test_bare_short_invalid_or_nonadjacent_body_is_ignored(self):
        header = "-----BEGIN RSA PRIVATE KEY-----" + NL
        for body in ("", "A" * 19, "A" * 19 + "!", NL + "A" * 20,
                     "Proc-Type: 4,ENCRYPTED" + NL + "A" * 20):
            with self.subTest(body=body):
                self.assertEqual(self.findings(header + body), [])
        self.assertEqual(self.findings(
            "-----BEGIN CUSTOM PRIVATE KEY-----" + NL + "A" * 20), [])

    def test_complete_block_supersedes_fallback(self):
        body = base64.b64encode(b"synthetic plain text 0123456789" * 6).decode()
        lines = NL.join(body[i:i + 64] for i in range(0, len(body), 64))
        hits = self.findings("-----BEGIN RSA PRIVATE KEY-----" + NL + lines
                             + NL + "-----END RSA PRIVATE KEY-----" + NL)
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["summary"], "Multiline private key block detected")
        self.assertEqual(hits[0]["severity"], "critical")
        self.assertEqual(hits[0]["evidence"], "----…")
