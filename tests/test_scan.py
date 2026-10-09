#!/usr/bin/env python3
"""Regression tests for scan.py (stdlib unittest, no network).

Run from the repository root:  python3 -m unittest discover -s tests -v

They pin the documented behaviour of the v0.4 / v0.4.1 heuristics so a later change cannot
silently undo them:
  * value-shape hints on secret hits (expression / non-ascii / dotted-name / word-like /
    form-placeholder / example-key / placeholder) downgrade the raw severity to low and are
    classified likely-false-positive by --triage, while real-shaped values stay "review";
  * test / fixture / locale paths and filenames are likely-false-positive;
  * URL values are never hardcoded secrets; a PEM header inside source is not a leaked key;
  * evidence is always redacted (the scanner never prints the matched value);
  * go.mod is preferred over go.sum; Yarn Berry lockfiles parse; scaffold lockfiles are tagged;
  * summary.lockfiles_parsed / summary.notes, manifest_hash determinism, --triage additivity and
    the --fail-on gate on the committed test_fixture.
"""
import hashlib
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SCAN_PY = os.path.join(ROOT, "scan.py")
FIXTURE = os.path.join(ROOT, "test_fixture")

_spec = importlib.util.spec_from_file_location("feldspar_scan", SCAN_PY)
scan = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(scan)


def _reset_globals():
    del scan.ERRORS[:]
    del scan.PARSED_LOCKFILES[:]


def _tree(files):
    """Write {relative path: text} into a fresh temp dir and return its path."""
    root = tempfile.mkdtemp(prefix="fds-test-")
    for rel, text in files.items():
        path = os.path.join(root, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)
    return root


def _collect(root, fn):
    """Run one scan_* function over a tree and return the findings it added."""
    out = []

    def add(category, severity, file, line, summary, evidence, **kw):
        out.append({"category": category, "severity": severity, "file": file, "line": line,
                    "summary": summary, "evidence": evidence})

    fn(root, sorted(scan.walk(root)), add)
    return out


# ------------------------------------------------------------- value hints
class ValueHintTests(unittest.TestCase):
    """v0.4.1: shape judgements on the value of a generic `key = "value"` hit."""

    def test_hint_classes(self):
        cases = [
            # n8n credential expressions / env references
            ("={{$credentials.apiKey}}", "expression?"),
            ("$__env{SECRET_VALUE_1234}", "expression?"),
            ("$SOME_ENV_VARIABLE_NAME", "expression?"),
            ("{{ .Values.secretName }}", "expression?"),
            ("#{ENV['DATABASE_PASS']}", "expression?"),
            ("var(--token-color-primary)", "expression?"),
            # `${…}` is caught by the placeholder regex first; either way it clears
            ("${DB_PASSWORD_FROM_ENV}", "placeholder?"),
            ("your-api-key-goes-here", "placeholder?"),
            ("changeme-changeme-changeme", "placeholder?"),
            ("<insert-token-here-please>", "placeholder?"),
            ("xxxxxxxxxxxxxxxxxxxxxxxx", "placeholder?"),
            # localized UI copy (discourse locales)
            ("パスワードを入力してください", "non-ascii?"),
            ("Mot de passe oublié ?", "non-ascii?"),
            # highlighter scope names / grafana flag names
            ("entity.other.inherited-class", "dotted-name?"),
            ("feature.toggle.new-nav-bar", "dotted-name?"),
            # home-assistant constants, growatt field names
            ("long_lived_access_token", "word-like?"),
            ("refresh-token-cookie-name", "word-like?"),
            # masked values
            ("0000000000000000000000", "example-key?"),
            ("********************", "example-key?"),
        ]
        for value, want in cases:
            with self.subTest(value=value):
                self.assertEqual(scan._value_hint(value), want)

    def test_real_shaped_values_have_no_hint(self):
        """Anything with digits / credential structure must stay a medium 'review' hit."""
        for value in [
            "sk-9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c",        # vendor key with digits
            "$2b$12$abcdefghijklmnopqrstuv",             # bcrypt hash ($ + digit is not an env ref)
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.sig",  # JWT (dots, but digits)
            "hunter2hunter2hunter2",                     # dev default with a digit
            "api.v2.key.with.digit7",                     # dotted but carries a digit
            "A9b8C7d6E5f4G3h2I1j0K9l8",                   # mixed random
        ]:
            with self.subTest(value=value):
                self.assertIsNone(scan._value_hint(value))
                self.assertEqual(scan._generic_sev(value), ("medium", None))

    def test_form_placeholder_context(self):
        # the value itself looks real; the surrounding attribute says it is example text
        self.assertEqual(scan._value_hint("abcdef1234567890abcdef", 'placeholder="'),
                         "form-placeholder?")
        self.assertEqual(scan._value_hint("abcdef1234567890abcdef", "  placeholder: '"),
                         "form-placeholder?")
        self.assertIsNone(scan._value_hint("abcdef1234567890abcdef", "  apiKey: '"))

    def test_pattern_hints(self):
        """Fixed-pattern hits (AWS/Slack/GitHub): documented example keys + masks + placeholders."""
        self.assertEqual(scan._pattern_hint("AKIAIOSFODNN7EXAMPLE"), "example-key?")
        self.assertEqual(scan._pattern_hint("ghp_16C7e42F292c6912E7710c838347Ae178B4a"), "example-key?")
        self.assertEqual(scan._pattern_hint("xoxb-xxxxxxxxxxxxxxxx"), "example-key?")
        self.assertEqual(scan._pattern_hint("AKIAABCDEFGHIJKLMNOP", 'placeholder="'), "form-placeholder?")
        self.assertIsNone(scan._pattern_hint("xoxb-1234567890-abcdefghij"))
        self.assertIsNone(scan._pattern_hint("AKIAABCDEFGHIJKLMNOP"))

    def test_every_hint_name_is_a_known_value_hint(self):
        """_secret_false_positive only recognises names listed in VALUE_HINTS."""
        for v in ["={{$x.y}}", "パスワード", "a.b.c", "word_like_value", "000000000000", "your-key-here"]:
            self.assertIn(scan._value_hint(v), scan.VALUE_HINTS)
        self.assertIn("form-placeholder?", scan.VALUE_HINTS)


# ----------------------------------------------------------- scan_secrets
class ScanSecretsTests(unittest.TestCase):

    def setUp(self):
        _reset_globals()
        self.root = _tree({
            "src/config.py": "\n".join([
                'API_KEY = "sk-9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c"',       # real-shaped -> medium
                'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"',                       # docs example -> low
                'OAUTH2_TOKEN = "https://example.com/oauth/token"',       # URL -> nothing (v0.4)
                'PEM_HEADER_RE = "-----BEGIN RSA PRIVATE KEY-----"',       # header in code -> nothing
                "",
            ]),
            "src/node.ts": "  apiKey: '={{$credentials.apiKey}}',\n",      # expression -> low
            "src/consts.py": 'ATTR_TOKEN = "long_lived_access_token"\n',   # word-like -> low
            "src/form.html": '<input placeholder="AKIAIOSFODNN7EXAMPL2">\n',  # placeholder attr -> low
            "config/locales/server.ja.yml": 'password: "パスワードを入力してください。再入力"\n',  # non-ascii -> low
            "keys/id_rsa": "-----BEGIN RSA PRIVATE KEY-----\n"
                           "MIIEowIBAAKCAQEAu7x0Zz3vK8y2m4Q5n6P7q8R9s0T1u2V3w4X5y6Z7a8B9c0D1\n"
                           "-----END RSA PRIVATE KEY-----\n",             # real PEM -> critical
            "lib/vendor.min.js": 'password="aaaaaaaaaaaaaaaaaaaaaaaaaaaa1"\n',  # minified -> skipped
        })
        self.findings = _collect(self.root, scan.scan_secrets)
        self.by_file = {}
        for f in self.findings:
            self.by_file.setdefault(f["file"], []).append(f)

    def _one(self, rel):
        fs = self.by_file.get(rel, [])
        self.assertEqual(len(fs), 1, "expected exactly one finding in %s, got %r" % (rel, fs))
        return fs[0]

    def test_real_shaped_generic_hit_is_medium_without_hint(self):
        f = [x for x in self.by_file["src/config.py"] if x["line"] == 1][0]
        self.assertEqual(f["severity"], "medium")
        self.assertEqual(f["summary"], "Hardcoded api_key assignment")
        self.assertNotIn("?)", f["evidence"])

    def test_example_aws_key_is_low_with_hint(self):
        f = [x for x in self.by_file["src/config.py"] if x["line"] == 2][0]
        self.assertEqual(f["severity"], "low")
        self.assertIn("(example-key?)", f["evidence"])

    def test_url_value_and_pem_header_in_code_are_not_findings(self):
        lines = sorted(x["line"] for x in self.by_file["src/config.py"])
        self.assertEqual(lines, [1, 2])

    def test_hint_classes_end_to_end(self):
        self.assertIn("(expression?)", self._one("src/node.ts")["evidence"])
        self.assertIn("(word-like?)", self._one("src/consts.py")["evidence"])
        self.assertIn("(non-ascii?)", self._one("config/locales/server.ja.yml")["evidence"])
        for rel in ("src/node.ts", "src/consts.py", "config/locales/server.ja.yml"):
            self.assertEqual(self._one(rel)["severity"], "low")

    def test_placeholder_attribute_downgrades_fixed_pattern_hit(self):
        f = self._one("src/form.html")
        self.assertEqual(f["severity"], "low")
        self.assertIn("(form-placeholder?)", f["evidence"])

    def test_real_private_key_block_is_critical(self):
        f = self._one("keys/id_rsa")
        self.assertEqual((f["severity"], f["summary"]), ("critical", "Private key block detected"))

    def test_minified_js_is_skipped(self):
        self.assertNotIn("lib/vendor.min.js", self.by_file)

    def test_evidence_is_always_redacted(self):
        """The scanner must never print the matched value: at most 4 leading characters + '…'."""
        for f in self.findings:
            ev = f["evidence"].split(" (", 1)[0]
            self.assertTrue(ev.endswith("…"), f)
            self.assertLessEqual(len(ev), 5, f)
        self.assertNotIn("sk-9f8e7d6c", json.dumps(self.findings))
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", json.dumps(self.findings))


# ----------------------------------------------------------------- triage
class TriageTests(unittest.TestCase):

    def _sec(self, path, evidence="abcd…"):
        return {"id": "F", "category": "secret", "severity": "medium", "file": path,
                "line": 1, "summary": "x", "evidence": evidence}

    def test_path_and_filename_false_positives(self):
        for path, want in [
            ("src/__fixtures__/keys.ts", "fixture"),
            ("src/testutils/helpers.py", "testutils"),
            ("packages/x/test-utils/a.ts", "test-utils"),
            ("app/__mocks__/client.js", "mock"),
            ("tests/unit/a.py", "test"),
            ("examples/basic/config.py", "example"),
            ("src/__snapshots__/x.snap", "snapshot"),
            ("config/locales/server.ja.yml", "localization"),
            ("web/i18n/de.json", "localization"),
            ("src/testUtils.ts", "filename marks"),
            ("src/foo.test.ts", "filename marks"),
            ("conf/settings.example", "filename marks"),
        ]:
            with self.subTest(path=path):
                is_fp, reason = scan._secret_false_positive(self._sec(path))
                self.assertTrue(is_fp, path)
                self.assertIn(want, reason)

    def test_shipped_path_real_value_stays_review(self):
        self.assertEqual(scan._secret_false_positive(self._sec("src/config.py")), (False, None))
        # a path that merely CONTAINS 'test' as part of a word is not a test path
        self.assertEqual(scan._secret_false_positive(self._sec("src/contest/config.py")), (False, None))
        self.assertEqual(scan._secret_false_positive(self._sec("src/language/parser.py")), (False, None))

    def test_value_hint_in_evidence_is_false_positive(self):
        for note, reason in scan.VALUE_HINTS.items():
            is_fp, got = scan._secret_false_positive(self._sec("src/config.py", "abcd… (%s)" % note))
            self.assertTrue(is_fp, note)
            self.assertEqual(got, reason)

    def test_triage_findings_classification_and_summary(self):
        findings = [
            {"id": "F-001", "category": "dependency-vuln", "severity": "high", "file": "package-lock.json",
             "package": "lodash", "fixed_in": ["4.17.21"]},
            {"id": "F-002", "category": "dependency-vuln", "severity": "medium", "file": "go.sum",
             "package": "x/y", "fixed_in": []},
            {"id": "F-003", "category": "dependency-vuln", "severity": "high",
             "file": "examples/demo/package-lock.json", "package": "react", "fixed_in": ["19.0.1"]},
            {"id": "F-004", "category": "secret", "severity": "medium", "file": "src/config.py",
             "evidence": "sk-9…"},
            {"id": "F-005", "category": "secret", "severity": "low", "file": "src/consts.py",
             "evidence": "long… (word-like?)"},
            {"id": "F-006", "category": "config", "severity": "low", "file": "Dockerfile", "evidence": "x"},
        ]
        per_id, summary = scan.triage_findings(findings)
        self.assertEqual(set(per_id), {f["id"] for f in findings})
        self.assertEqual(per_id["F-001"]["action"], "upgrade")
        self.assertEqual(per_id["F-001"]["upgrade_to"], ["4.17.21"])
        self.assertEqual(per_id["F-002"]["action"], "monitor")
        self.assertIn("go.sum", per_id["F-002"]["note"])
        self.assertTrue(per_id["F-003"].get("scaffold"))
        self.assertEqual(per_id["F-003"]["priority"], "low")
        self.assertFalse(per_id["F-004"]["likely_false_positive"])
        self.assertEqual(per_id["F-004"]["action"], "review")
        self.assertTrue(per_id["F-005"]["likely_false_positive"])
        self.assertEqual(per_id["F-005"]["action"], "informational")
        self.assertEqual(per_id["F-006"], {"action": "review"})
        self.assertEqual(summary["dependency"],
                         {"upgradeable": 2, "monitor_only": 1, "in_scaffold_lockfiles": 1})
        self.assertEqual(summary["secrets"],
                         {"total": 2, "likely_false_positive": 1, "needs_review": 1})
        self.assertIn("1 secret hit(s) needing review", summary["headline"])
        self.assertIn("1 of the dependency hits are in example/fixture/benchmark lockfiles", summary["headline"])
        self.assertEqual(scan.triage_findings([])[1]["headline"], "no actionable findings after triage")


# -------------------------------------------------------------- lockfiles
class LockfileTests(unittest.TestCase):

    def setUp(self):
        _reset_globals()

    def test_go_mod_preferred_over_go_sum(self):
        root = _tree({
            "go.mod": "module example.com/app\n\ngo 1.22\n\nrequire (\n\tgithub.com/a/b v1.2.3\n"
                      "\tgithub.com/c/d v0.9.0 // indirect\n)\n\nrequire github.com/e/f v2.0.0\n",
            "go.sum": "github.com/a/b v1.0.0 h1:x=\ngithub.com/a/b v1.0.0/go.mod h1:y=\n"
                      "github.com/a/b v1.2.3 h1:x=\ngithub.com/old/mod v0.1.0 h1:z=\n",
        })
        pkgs = scan.collect_packages(root, sorted(scan.walk(root)))
        self.assertEqual(sorted(pkgs), [("Go", "github.com/a/b", "v1.2.3"),
                                        ("Go", "github.com/c/d", "v0.9.0"),
                                        ("Go", "github.com/e/f", "v2.0.0")])
        self.assertEqual(scan.PARSED_LOCKFILES, ["go.mod"])  # go.sum skipped, not parsed

    def test_go_sum_used_only_without_go_mod(self):
        root = _tree({"go.sum": "github.com/a/b v1.0.0 h1:x=\ngithub.com/a/b v1.0.0/go.mod h1:y=\n"})
        pkgs = scan.collect_packages(root, sorted(scan.walk(root)))
        self.assertEqual(sorted(pkgs), [("Go", "github.com/a/b", "v1.0.0")])
        self.assertEqual(scan.PARSED_LOCKFILES, ["go.sum"])

    def test_yarn_v1_and_berry(self):
        v1 = 'lodash@^4.17.0, lodash@^4.17.15:\n  version "4.17.21"\n  resolved "x"\n'
        self.assertEqual(scan.parse_yarn_lock(v1), [("npm", "lodash", "4.17.21")])
        berry = ('__metadata:\n  version: 8\n\n"lodash@npm:^4.17.0, lodash@npm:^4.17.15":\n'
                 '  version: 4.17.21\n  resolution: "lodash@npm:4.17.21"\n\n'
                 '"myapp@workspace:.":\n  version: 0.0.0-use.local\n  resolution: "myapp@workspace:."\n\n'
                 '"left-pad@patch:left-pad@npm:1.3.0#./p.patch":\n  version: 1.3.0\n\n'
                 '"typescript@patch:typescript@npm%3A^5.4.0#optional!builtin<compat/typescript>":\n'
                 '  version: 5.4.5\n\n'
                 '"@babel/core@npm:^7.24.0":\n  version: 7.24.4\n\n'
                 '"@scope/local@workspace:packages/local":\n  version: 0.0.0-use.local\n')
        # v0.4.2: patch:/workspace: entries are skipped even though their key holds several "@"
        self.assertEqual(scan.parse_yarn_lock(berry),
                         [("npm", "lodash", "4.17.21"), ("npm", "@babel/core", "7.24.4")])
        self.assertEqual(scan.parse_yarn_lock('"@babel/core@^7.0.0", "@babel/core@^7.1.0":\n  version "7.1.2"\n'),
                         [("npm", "@babel/core", "7.1.2")])

    def test_requirements_and_package_lock(self):
        self.assertEqual(scan.parse_requirements("requests==2.31.0  # pinned\nflask>=2\n-e .\n"
                                                 "urllib3[socks]==1.26.5; python_version<'3'\n"),
                         [("PyPI", "requests", "2.31.0"), ("PyPI", "urllib3", "1.26.5")])
        lock = json.dumps({"packages": {"": {"name": "app"},
                                        "node_modules/lodash": {"version": "4.17.20"},
                                        "node_modules/a/node_modules/b": {"version": "1.0.0"}}})
        self.assertEqual(sorted(scan.parse_package_lock(lock)),
                         [("npm", "b", "1.0.0"), ("npm", "lodash", "4.17.20")])

    def test_scaffold_lockfile_attribution(self):
        """A package@version listed by both a shipped and a fixture lockfile is attributed to the shipped one."""
        lock = json.dumps({"packages": {"node_modules/react": {"version": "18.2.0"}}})
        root = _tree({"examples/demo/package-lock.json": lock, "package-lock.json": lock})
        pkgs = scan.collect_packages(root, sorted(scan.walk(root)))
        self.assertEqual(pkgs[("npm", "react", "18.2.0")], "package-lock.json")
        root = _tree({"examples/demo/package-lock.json": lock})
        pkgs = scan.collect_packages(root, sorted(scan.walk(root)))
        self.assertEqual(pkgs[("npm", "react", "18.2.0")], "examples/demo/package-lock.json")


# ---------------------------------------------------------------- the CLI
def _run(*args):
    p = subprocess.run([sys.executable, SCAN_PY] + list(args), capture_output=True, text=True, timeout=120)
    return p.returncode, p.stdout, p.stderr


class CliTests(unittest.TestCase):

    def test_fixture_offline_findings_and_gate(self):
        """The committed test_fixture, offline: 4 findings; --fail-on high trips, critical does not."""
        out = os.path.join(tempfile.mkdtemp(prefix="fds-cli-"), "fx.json")
        rc, _, err = _run(FIXTURE, "--no-osv", "--triage", "--json", out)
        self.assertEqual(rc, 0, err)
        with open(out) as fh:
            d = json.load(fh)
        self.assertEqual(d["version"], scan.VERSION)
        self.assertEqual(d["summary"]["by_severity"], {"critical": 0, "high": 1, "medium": 1, "low": 2, "unknown": 0})
        self.assertEqual(d["summary"]["lockfiles_parsed"], ["package-lock.json", "requirements.txt"])
        self.assertNotIn("notes", d["summary"])
        self.assertEqual([f["id"] for f in d["findings"]], ["F-001", "F-002", "F-003", "F-004"])
        self.assertEqual(d["triage_summary"]["secrets"], {"total": 2, "likely_false_positive": 1, "needs_review": 1})
        aws = [f for f in d["findings"] if f["summary"].startswith("AWS access key")][0]
        self.assertEqual(aws["severity"], "low")
        self.assertTrue(d["triage"][aws["id"]]["likely_false_positive"])
        self.assertEqual(_run(FIXTURE, "--no-osv", "--fail-on", "high", "--json", os.devnull)[0], 1)
        self.assertEqual(_run(FIXTURE, "--no-osv", "--fail-on", "critical", "--json", os.devnull)[0], 0)
        self.assertEqual(_run(FIXTURE, "--no-osv", "--fail-on", "bogus", "--json", os.devnull)[0], 2)

    def test_manifest_hash_is_deterministic_and_triage_additive(self):
        d1 = json.loads(_run(FIXTURE, "--no-osv")[1])
        d2 = json.loads(_run(FIXTURE, "--no-osv", "--triage")[1])
        self.assertEqual(d1["manifest_hash"], d2["manifest_hash"])
        self.assertNotIn("triage", d1)
        self.assertIn("triage", d2)
        self.assertEqual(d1["findings"], d2["findings"])
        canon = json.dumps({"findings": d1["findings"], "target": d1["target"], "commit": d1["commit"]},
                           sort_keys=True, separators=(",", ":"))
        self.assertEqual(d1["manifest_hash"], hashlib.sha256(canon.encode()).hexdigest())

    def test_no_manifest_note(self):
        root = _tree({"README.md": "hello\n"})
        d = json.loads(_run(root, "--no-osv")[1])
        self.assertEqual(d["summary"]["lockfiles_parsed"], [])
        self.assertTrue(d["summary"]["notes"][0].startswith("No supported dependency manifest was parsed"))
        self.assertEqual(d["findings"], [])

    def test_bad_target_and_unknown_arg(self):
        self.assertEqual(_run(os.path.join(ROOT, "does-not-exist"), "--no-osv")[0], 2)
        self.assertEqual(_run(FIXTURE, "--no-osv", "--bogus")[0], 2)


if __name__ == "__main__":
    unittest.main()
