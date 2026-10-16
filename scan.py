#!/usr/bin/env python3
"""feldspar-discovery-scan: deterministic, dependency-free repo scanner.

Usage: scan.py <local-repo-path-or-git-https-url> [--json out.json] [--no-osv]
               [--fail-on SEV] [--triage] [--compact]
       scan.py --version

  --version       print scanner name and version, then exit (standalone invocation).

  -h, --help      show this help; also accepted after the target.
  --json PATH     write JSON to PATH; use - for stdout (also the default).
  --compact       write JSON on one line, to stdout or --json PATH.
  --no-osv        skip OSV dependency advisory lookups;
                  package inventory and local secret/config checks still run.
                  URL targets still clone; use a local path for offline scanning.
  --fail-on SEV   exit 1 when any finding is at or above SEV (critical|high|medium|low).
                  Use none to disable the gate (the default); findings are still reported.
                  "unknown"-severity findings never trigger the gate.
  --triage        add a deterministic interpretation layer (top-level "triage" +
                  "triage_summary"): classifies secret hits in test/fixture/example
                  paths as likely false positives, and marks each dependency advisory
                  as upgrade (patch available) or monitor (no patched release yet).
                  Discovers nothing and adds no findings, so the raw findings set and
                  manifest_hash are unchanged; triage is a separate, additive section.
                  v0.4: dependency hits from lockfiles under test/fixture/example/benchmark
                  paths are tagged scaffold (low priority).

Exit codes: 0 no severity gate fired; 1 gate fired (--fail-on);
            2 bad args / bad path; 3 clone failed.
Without --fail-on, findings do not change the exit code. Code 0 does not certify a complete assessment.
Review errors, summary.notes, summary.lockfiles_parsed, and summary.packages_found in the report.

v0.4 (2026-10-08, from the 25-repo dataset in datasets/): go.mod is the Go build list and is
preferred over go.sum (which lists superseded versions too); Yarn Berry lockfiles are parsed;
`summary.lockfiles_parsed` + a `summary.notes` warning when no manifest was parsed.
Generic assignments whose values start with http://, https://, ws:// or wss://
(case-insensitive) are skipped; provider-token patterns inside URLs still report.
v0.4.1 (2026-10-08): second secret heuristic beyond paths — value-shape hints (template/env
references, localized text, dotted identifier names, digit-less word-like values, form
placeholders, documented example keys and masked values) tag the evidence `(hint?)`, drop the raw
severity to low and are classified likely-false-positive by --triage; translation-catalogue paths
(locales/, i18n/, …) and __fixtures__/__mocks__/testutils paths likewise.
v0.4.2 (2026-10-08): Yarn Berry `pkg@patch:pkg@npm:…` / `workspace:` entries were split at the
last "@", so the skip-protocol check never saw them and a bogus `pkg@patch:pkg` package was emitted;
fixed (split after the scoped name). Regression tests in tests/ (python3 -m unittest discover -s tests).
"""
import hashlib
import json
import os
import re
import shlex
import stat
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
from datetime import datetime, timezone
from itertools import islice

try:
    import tomllib
except ImportError:  # pragma: no cover - py<3.11
    tomllib = None

SCANNER = "feldspar-discovery-scan"
VERSION = "0.4.15"
OSV_BATCH = "https://api.osv.dev/v1/querybatch"
OSV_VULN = "https://api.osv.dev/v1/vulns/"
HTTP_TIMEOUT = 20
SKIP_DIRS = {".git", "node_modules", "vendor", "dist", "build", ".venv", "venv",
             "__pycache__", ".mypy_cache", ".tox", ".next", "target"}
BIN_EXT = {".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".pdf", ".zip", ".gz",
           ".tgz", ".bz2", ".xz", ".7z", ".jar", ".class", ".so", ".dylib", ".dll",
           ".exe", ".woff", ".woff2", ".ttf", ".eot", ".mp3", ".mp4", ".wasm", ".pyc"}
LOCKFILES = {"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock",
             "uv.lock", "Cargo.lock", "Gemfile.lock", "go.sum", "go.mod", "composer.lock"}
MAX_TEXT = 1024 * 1024
MAX_FINDINGS_PER_FILE = 100
MAX_FINDINGS = 5000
MAX_FILES = 50000
SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
ERRORS = []
PARSED_LOCKFILES = []   # relative paths of dependency manifests actually parsed (v0.4; summary.lockfiles_parsed)


# ---------------------------------------------------------------- utilities
def walk(root, skipped=None, max_files=None):
    yielded = 0
    for dirpath, dirnames, filenames in os.walk(root):
        regular_dirs = []
        for dirname in sorted(dirnames):
            if dirname in SKIP_DIRS:
                continue
            try:
                is_dir = stat.S_ISDIR(os.lstat(os.path.join(dirpath, dirname)).st_mode)
            except OSError:
                is_dir = False
            if is_dir:
                regular_dirs.append(dirname)
            elif skipped is not None:
                skipped["non_regular"] += 1
        dirnames[:] = regular_dirs
        for fn in sorted(filenames):
            path = os.path.join(dirpath, fn)
            try:
                regular = stat.S_ISREG(os.lstat(path).st_mode)
            except OSError:
                regular = False
            if regular:
                yield path
                yielded += 1
                if max_files is not None and yielded >= max_files:
                    return
            elif skipped is not None:
                skipped["non_regular"] += 1


def read_text(path, limit=MAX_TEXT):
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
        with os.fdopen(fd, "rb") as fh:
            st = os.fstat(fh.fileno())
            if not stat.S_ISREG(st.st_mode) or st.st_size > limit:
                return None
            raw = fh.read(limit + 1)
            if len(raw) > limit:
                return None
    except OSError:
        return None
    if b"\x00" in raw:
        return None
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        try:
            return raw.decode("latin-1")
        except Exception:
            return None


def redact(value, n=4):
    value = value.strip()
    return value[:n] + "…" if len(value) > n else value + "…"


# ------------------------------------------------------------ dep parsers
def parse_requirements(text):
    out = []
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line or line.startswith("-"):
            continue
        line = line.split(";", 1)[0].strip()
        if "==" not in line:
            continue
        name, _, ver = line.partition("==")
        name = re.split(r"[\[<>!~ ]", name.strip())[0].strip()
        ver = ver.strip().strip('"\'')
        if name and re.match(r"^[0-9][^\s,=<>!]*$", ver):
            out.append(("PyPI", name, ver))
    return out


def parse_toml_packages(text, ecosystem):
    out = []
    if tomllib:
        try:
            data = tomllib.loads(text)
        except (ValueError, RecursionError):
            # Includes invalid TOML, oversized integers and excessive nesting.
            return []
        packages = data.get("package", []) or []
        if not isinstance(packages, list):
            return []
        for pkg in packages:
            if not isinstance(pkg, dict):
                return []
            n, v = pkg.get("name"), pkg.get("version")
            if n and v:
                if not isinstance(n, str) or not isinstance(v, str):
                    return []
                out.append((ecosystem, n, str(v)))
        return out
    # Older Python versions without tomllib retain the line-based fallback.
    name = ver = None
    for line in text.splitlines():
        s = line.strip()
        if s == "[[package]]":
            name = ver = None
        m = re.match(r'^name\s*=\s*"([^"]+)"', s)
        if m:
            name = m.group(1)
        m = re.match(r'^version\s*=\s*"([^"]+)"', s)
        if m:
            ver = m.group(1)
        if name and ver:
            out.append((ecosystem, name, ver))
            name = ver = None
    return out


def parse_package_lock(text):
    out = []
    try:
        if text.startswith("\ufeff"):
            text = text[1:]  # Some producers emit a UTF-8 BOM; json.loads(str) rejects it.
        data = json.loads(text)
    except (ValueError, RecursionError):
        # JSON syntax errors, integer conversion limits and excessive nesting.
        return out
    if not isinstance(data, dict):
        return out
    pkgs = data.get("packages")
    if isinstance(pkgs, dict):
        for key, meta in pkgs.items():
            if not key or not isinstance(meta, dict):
                continue
            ver = meta.get("version")
            if "node_modules/" in key:
                name = key.rsplit("node_modules/", 1)[1]
            else:
                continue
            if name and isinstance(ver, str) and ver:
                out.append(("npm", name, ver))
    deps = data.get("dependencies")
    if isinstance(deps, dict) and not out:
        # Preserve depth-first order without consuming Python's call stack.
        stack = [iter(deps.items())]
        while stack:
            item = next(stack[-1], None)
            if item is None:
                stack.pop()
                continue
            name, meta = item
            if isinstance(meta, dict):
                ver = meta.get("version")
                if isinstance(ver, str) and ver:
                    out.append(("npm", name, ver))
                if isinstance(meta.get("dependencies"), dict):
                    stack.append(iter(meta["dependencies"].items()))
    return out


YARN_SKIP_PROTOCOLS = {"workspace", "patch", "portal", "link", "file", "exec", "git", "github", "http", "https"}


def parse_yarn_lock(text):
    """Yarn v1 (`name@^1.0.0:` / `  version "1.0.0"`) and Yarn Berry v2+ (`"name@npm:^1.0.0":` /
    `  version: 1.0.0`, `__metadata:` header). Workspace/patch/portal entries are not registry packages
    and are skipped (v0.4 — before this, Berry lockfiles silently yielded 0 packages)."""
    out = []
    names = []
    for line in text.splitlines():
        if line.startswith("__metadata"):
            names = []
            continue
        if line and not line.startswith((" ", "\t", "#")):
            names = []
            if not line.rstrip().endswith(":"):
                continue
            spec = line.rstrip()[:-1]
            if spec.startswith('"') and spec.endswith('"') and spec.count('"') == 2:
                spec = spec[1:-1]  # Yarn can quote the entire comma-separated descriptor list.
            for part in spec.split(","):
                part = part.strip()
                if part.startswith('"') != part.endswith('"'):
                    continue  # An unbalanced quoted descriptor is incomplete.
                part = part.strip('"')
                if not part:
                    continue
                # split at the FIRST "@" after the (possibly @scoped/) name: a Berry
                # `pkg@patch:pkg@npm:1.0#…` entry has several, and rfind took the last one,
                # which hid the patch: protocol and emitted `pkg@patch:pkg` as a package (v0.4.2)
                at = part.find("@", 1)
                if at > 0:
                    rng = part[at + 1:]
                    proto = rng.split(":", 1)[0] if ":" in rng else None
                    if proto in YARN_SKIP_PROTOCOLS:
                        continue
                    names.append(part[:at])
        else:
            m = re.fullmatch(
                r'\s+version:?\s+(?:"([^"\s]+)"|\'([^\'\s]+)\'|([^\s"\'#]+))\s*(?:#.*)?',
                line)
            if m and names:
                ver = next(group for group in m.groups() if group is not None)
                if re.match(r"^\d", ver):
                    for n in dict.fromkeys(names):
                        out.append(("npm", n, ver))
                names = []
    return out


def parse_pnpm_lock(text):
    out = []
    in_pkgs = False
    for line in text.splitlines():
        if re.match(r"^packages:\s*$", line):
            in_pkgs = True
            continue
        if in_pkgs and line and not line.startswith((" ", "\t")):
            in_pkgs = False
        if not in_pkgs:
            continue
        # A quoted key must have both quotes; a truncated key is not a package.
        m = re.match(r"^\s{2}(?:'(/?[^:'\s]+)'|(/?[^:'\s]+)):\s*$", line)
        if not m:
            continue
        key = (m.group(1) or m.group(2)).lstrip("/")
        key = key.split("(", 1)[0]
        at = key.rfind("@")
        if at <= 0:
            continue
        name, ver = key[:at], key[at + 1:]
        if re.match(r"^\d", ver):
            out.append(("npm", name, ver))
    return out


def parse_go_sum(text):
    """go.sum lists EVERY module version the module graph ever touched, including superseded ones
    (dataset 2026-10-08: 1,089 of 1,099 vulnerable go.sum rows were not in go.mod). It is only used
    when no go.mod sits beside it (v0.4); prefer parse_go_mod."""
    out = []
    for line in text.splitlines():
        parts = line.split()
        # A go.sum record has exactly a module, version, and h1 checksum.
        # Ignore truncated or malformed records instead of reporting a dependency.
        if len(parts) != 3 or not parts[2].startswith("h1:") or len(parts[2]) == 3:
            continue
        mod, ver = parts[0], parts[1]
        if ver.endswith("/go.mod"):
            ver = ver[: -len("/go.mod")]
        if mod and ver.startswith("v") and len(ver) > 1:
            out.append(("Go", mod, ver))
    return out


def parse_go_mod(text):
    """The `require` set of go.mod = the module's build list (direct + `// indirect`, Go 1.17+)."""
    out = []
    in_req = False
    for line in text.splitlines():
        s = line.split("//", 1)[0].strip()
        if not s:
            continue
        if re.fullmatch(r"require\s+\(", s):
            in_req = True
            continue
        if in_req and s == ")":
            in_req = False
            continue
        m = None
        if in_req:
            m = re.match(r"^(\S+)\s+(v\S+)$", s)
        elif s.startswith("require "):
            m = re.match(r"^require\s+(\S+)\s+(v\S+)$", s)
        if m:
            out.append(("Go", m.group(1), m.group(2)))
    return out


def parse_gemfile_lock(text):
    out = []
    in_gem = False
    in_specs = False
    for line in text.splitlines():
        if line and not line[0].isspace():
            in_gem = line == "GEM"
            in_specs = False
            continue
        if in_gem and re.match(r"^\s{2}specs:\s*$", line):
            in_specs = True
            continue
        if not in_specs:
            continue
        m = re.match(r"^\s{4}([A-Za-z0-9_.\-]+) \(([^)]+)\)\s*$", line)
        if m:
            out.append(("RubyGems", m.group(1), m.group(2)))
    return out


DEP_HANDLERS = {
    "requirements.txt": parse_requirements,
    "poetry.lock": lambda t: parse_toml_packages(t, "PyPI"),
    "uv.lock": lambda t: parse_toml_packages(t, "PyPI"),
    "Cargo.lock": lambda t: parse_toml_packages(t, "crates.io"),
    "package-lock.json": parse_package_lock,
    "yarn.lock": parse_yarn_lock,
    "pnpm-lock.yaml": parse_pnpm_lock,
    "go.sum": parse_go_sum,
    "go.mod": parse_go_mod,
    "Gemfile.lock": parse_gemfile_lock,
}


def collect_packages(root, files):
    seen = {}
    gomod_dirs = {os.path.dirname(p) for p in files if os.path.basename(p) == "go.mod"}
    for path in files:
        base = os.path.basename(path)
        handler = DEP_HANDLERS.get(base)
        if handler is None and base.startswith("requirements") and base.endswith(".txt"):
            handler = parse_requirements
        if handler is None:
            continue
        if base == "go.sum" and os.path.dirname(path) in gomod_dirs:
            continue  # go.mod beside it is the build list; go.sum also records superseded versions
        text = read_text(path, 8 * 1024 * 1024)
        if text is None:
            continue
        try:
            pkgs = handler(text)
        except Exception as exc:
            ERRORS.append("parse %s: %s" % (os.path.relpath(path, root), exc))
            continue
        rel = os.path.relpath(path, root)
        PARSED_LOCKFILES.append(rel)
        scaffold = bool(TEST_PATH_RE.search(rel))
        for eco, name, ver in pkgs:
            key = (eco, name, ver)
            prev = seen.get(key)
            # attribute a package@version to a shipped lockfile over a fixture/example one when both list it
            if prev is None or (not scaffold and TEST_PATH_RE.search(prev)):
                seen[key] = rel
    return seen


# ------------------------------------------------------------------- OSV
def http_json(url, payload=None):
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(
        url, data=data,
        headers={"Content-Type": "application/json", "User-Agent": SCANNER + "/" + VERSION})
    with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as resp:
        return json.loads(resp.read().decode())


def sev_from_score(score):
    try:
        s = float(score)
    except (TypeError, ValueError):
        return None
    if s >= 9:
        return "critical"
    if s >= 7:
        return "high"
    if s >= 4:
        return "medium"
    return "low"


CVSS_SEV = {"CRITICAL": "critical", "HIGH": "high", "MODERATE": "medium",
            "MEDIUM": "medium", "LOW": "low"}


def parse_cvss_score(vector):
    # CVSS v3 vectors sometimes appear as raw scores in OSV `severity[].score`.
    m = re.match(r"^\d+(\.\d+)?$", str(vector).strip())
    return float(m.group(0)) if m else None


def vuln_details(vid, cache):
    if vid in cache:
        return cache[vid]
    info = {"severity": "unknown", "fixed_in": [], "summary": vid}
    try:
        v = http_json(OSV_VULN + vid)
    except Exception as exc:
        ERRORS.append("osv vuln %s: %s" % (vid, exc))
        cache[vid] = info
        return info
    info["summary"] = (v.get("summary") or (v.get("details") or "").split("\n")[0] or vid)[:200]
    ds = (v.get("database_specific") or {}).get("severity")
    if isinstance(ds, str) and ds.upper() in CVSS_SEV:
        info["severity"] = CVSS_SEV[ds.upper()]
    if info["severity"] == "unknown":
        for s in v.get("severity") or []:
            score = parse_cvss_score(s.get("score", ""))
            mapped = sev_from_score(score) if score is not None else None
            if mapped:
                info["severity"] = mapped
                break
    fixed = []
    for aff in v.get("affected") or []:
        for rng in aff.get("ranges") or []:
            for ev in rng.get("events") or []:
                if ev.get("fixed"):
                    fixed.append(ev["fixed"])
    info["fixed_in"] = sorted(dict.fromkeys(fixed))[:10]
    cache[vid] = info
    return info


def query_osv(packages):
    """packages: list of (eco, name, ver). Returns {(eco,name,ver): [vuln_ids]}"""
    result = {}
    keys = list(packages)
    for i in range(0, len(keys), 500):
        chunk = keys[i:i + 500]
        payload = {"queries": [
            {"package": {"name": n, "ecosystem": e}, "version": v} for (e, n, v) in chunk]}
        try:
            resp = http_json(OSV_BATCH, payload)
        except Exception as exc:
            ERRORS.append("osv querybatch: %s" % exc)
            continue
        for key, res in zip(chunk, resp.get("results") or []):
            ids = [x.get("id") for x in (res.get("vulns") or []) if x.get("id")]
            if ids:
                result[key] = ids
    return result


# --------------------------------------------------------------- secrets
# v0.4.1 value-shape hints. From the 2026-10-08 dataset (datasets/2026-10-08-popular-oss):
# of the 313 secret hits the path/placeholder rule left for review, roughly two thirds were
# template or env-variable references (`={{$credentials.apiKey}}`, `$__env{…}`, `#{…}`,
# `var(--…)`), localized UI strings, syntax-highlighter scope names (`token: 'entity.name'`)
# or AWS/Slack example values inside form `placeholder=` attributes. Each hint is appended
# to the (redacted) evidence as `(hint?)` and downgrades the raw severity to low; triage
# reads the same hints. A hint is a shape judgement, not proof — it never deletes a finding.
VALUE_HINTS = {
    "placeholder?": "value looks like a placeholder, not a real secret",
    "expression?": "value is a template/env-variable reference, not a literal credential",
    "non-ascii?": "value contains non-ASCII text (localized string or masked value); credentials are ASCII",
    "dotted-name?": "value is a dotted identifier with no digits (highlighter scope / flag / host name)",
    "form-placeholder?": "match sits in a form placeholder attribute (example text shown to users)",
    "example-key?": "value is a documented example key or an x/0/* masked pattern",
    "word-like?": "value is letters/underscores/hyphens only, no digits (constant name, enum value or field key)",
}
EXPR_RE = re.compile(r"^(=?\{\{|\$\{|\$__|\$[A-Za-z_]|\{env:|#\{|%\{|%\(|<%|var\(|@\{)")
DOTTED_RE = re.compile(r"^[A-Za-z_][A-Za-z_-]*(\.[A-Za-z_][A-Za-z_-]*)+$")
WORD_RE = re.compile(r"^[A-Za-z][A-Za-z_-]*$")
EXAMPLE_KEYS = {
    "AKIAIOSFODNN7EXAMPLE", "AKIAI44QH8DHBEXAMPLE",          # AWS documentation keys
    "ghp_16C7e42F292c6912E7710c838347Ae178B4a",               # GitHub docs example token
}
MASKED_RE = re.compile(r"x{6,}|X{6,}|0{8,}|\*{4,}|EXAMPLE")
# Match only an open value in the prefix before a hit, not a closed earlier field.
PLACEHOLDER_ATTR_RE = re.compile(
    r"""(?<![\w-])placeholder\s*[:=]\s*(?:"[^"]*|'[^']*|\{[^}]*)$""", re.I)


def _value_hint(value, line_prefix=""):
    """Shape hint for a generic `key = "value"` hit (None = looks like a literal credential)."""
    if re.fullmatch(r"\.{3,}", value):
        return "placeholder?"
    if re.search(r"example|changeme|your[_-]|xxx|dummy|placeholder|<|\$\{", value, re.I):
        return "placeholder?"
    if any(ord(c) > 127 for c in value):
        return "non-ascii?"
    if EXPR_RE.match(value):
        return "expression?"
    if DOTTED_RE.match(value):
        return "dotted-name?"
    if MASKED_RE.search(value):
        return "example-key?"
    if WORD_RE.match(value):
        # home-assistant dataset: `ATTR_TOKEN = "long_lived_access_token"`, growatt field names,
        # header names — identifiers, not credentials (random credentials carry digits)
        return "word-like?"
    if PLACEHOLDER_ATTR_RE.search(line_prefix[-40:]):
        return "form-placeholder?"
    return None


def _pattern_hint(matched, line_prefix=""):
    """Shape hint for a fixed-pattern hit (AWS/Slack/GitHub…): documented example or masked value."""
    if matched in EXAMPLE_KEYS or MASKED_RE.search(matched):
        return "example-key?"
    if PLACEHOLDER_ATTR_RE.search(line_prefix[-40:]):
        return "form-placeholder?"
    return None


def _generic_sev(match_value, line_prefix=""):
    note = _value_hint(match_value, line_prefix)
    return ("low", note) if note else ("medium", None)


SECRET_PATTERNS = [
    ("aws-access-key-id", re.compile(r"(?<!\w)AKIA[0-9A-Z]{16}(?!\w)"),
     "high", "AWS access key ID"),
    ("github-token", re.compile(r"(?<!\w)gh[pousr]_[A-Za-z0-9]{36,}(?!\w)"),
     "high", "GitHub token"),
    ("github-pat", re.compile(r"(?<!\w)github_pat_[A-Za-z0-9_]{80,}(?!\w)"),
     "high", "GitHub fine-grained PAT"),
    ("gitlab-pat", re.compile(r"(?<![\w-])glpat-[A-Za-z0-9_-]{20}(?![\w-])"),
     "high", "GitLab personal access token"),
    ("npm-token", re.compile(r"(?<!\w)npm_[A-Za-z0-9]{36}(?!\w)"),
     "high", "npm access token"),
    ("openai-api-key", re.compile(r"(?<![\w-])sk-(?:proj-[A-Za-z0-9_-]{40,}|(?!proj-|ant-)[A-Za-z0-9_-]{40,})(?![\w-])"),
     "high", "OpenAI API key"),
    ("anthropic-api-key", re.compile(r"(?<![\w-])sk-ant-[A-Za-z0-9_-]{40,}(?![\w-])"),
     "high", "Anthropic API key"),
    ("huggingface-token", re.compile(r"(?<!\w)hf_[A-Za-z0-9]{34,}(?!\w)"),
     "medium", "Hugging Face token"),
    ("sendgrid-api-key", re.compile(r"(?<![\w-])SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}(?![\w-])"),
     "high", "SendGrid API key"),
    ("telegram-bot-token", re.compile(r"(?<![\w-])[0-9]+:[A-Za-z0-9_-]{35}(?![\w-])"),
     "high", "Telegram bot token"),
    ("twilio-api-key-sid", re.compile(r"(?<!\w)SK[0-9a-fA-F]{32}(?!\w)"),
     "medium", "Twilio API key SID"),
    ("slack-token", re.compile(r"(?<![\w-])xox[baprs]-[0-9A-Za-z-]{10,}(?![\w-])"),
     "high", "Slack token"),
    ("stripe-live-key", re.compile(r"(?<!\w)sk_live_[0-9a-zA-Z]{24,}(?!\w)"),
     "critical", "Stripe live secret key"),
    ("stripe-restricted-key", re.compile(r"(?<!\w)rk_live_[0-9a-zA-Z]{24,}(?!\w)"),
     "high", "Stripe live restricted key"),
    ("google-api-key", re.compile(r"(?<![\w-])AIza[0-9A-Za-z_-]{35}(?![\w-])"),
     "medium", "Google API key"),
    ("private-key", re.compile(r"-----BEGIN (RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"),
     "critical", "Private key block"),
]
# Unicode alphanumerics extend a name; underscores remain suffix separators.
GENERIC = re.compile(
    r"""(?i)(?<![^\W_])(?P<quote>['"]?)(?P<name>api[_-]?key|secret|password|passwd|token)(?P=quote)"""
    r"""\s*[:=]\s*(?P<value_quote>['"])(?P<value>[^'"\s]{16,})(?P=value_quote)""")
PRIVATE_KEY_BLOCK = re.compile(
    r"^[ \t]*-----BEGIN (?P<label>[A-Z ]*PRIVATE KEY)-----[ \t]*\r?\n"
    r"(?P<body>(?:[ \t]*[A-Za-z0-9+/=_.*-]+[ \t]*\r?\n)+)"
    r"[ \t]*-----END (?P=label)-----[ \t]*\r?$", re.M)


def scan_secrets(root, files, add):
    for path in files:
        base = os.path.basename(path)
        ext = os.path.splitext(base)[1].lower()
        if ext in BIN_EXT or base in LOCKFILES or base.endswith(".min.js"):
            continue
        text = read_text(path)
        if text is None:
            continue
        rel = os.path.relpath(path, root)
        lines = text.splitlines()
        block_headers = set()
        for m in PRIVATE_KEY_BLOCK.finditer(text):
            body_lines = [line.strip() for line in m.group("body").splitlines()]
            body = "".join(body_lines)
            note = _pattern_hint(body) or _value_hint(body)
            # Complete blocks need at least three base64 lines. Recognizable examples
            # may replace that body with a short mask/placeholder; keep them as low hits.
            if not note and (len(body_lines) < 3 or any(
                    not re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", line)
                    for line in body_lines)):
                continue
            lineno = text.count("\n", 0, m.start()) + 1
            block_headers.add(lineno)
            ev = redact(m.group(0).lstrip())
            if note:
                ev += " (%s)" % note
            add("secret", "low" if note else "critical", rel, lineno,
                summary="Multiline private key block detected", evidence=ev)
        for lineno, line in enumerate(lines, 1):
            if len(line) > 4000:
                continue
            for pid, rx, sev, desc in SECRET_PATTERNS:
                for m in rx.finditer(line):
                    if pid == "private-key":
                        if lineno in block_headers:
                            continue  # the complete block supersedes this header-only hit
                        # a real PEM block is followed by a base64 body line; a header inside
                        # source code (regex/validator/test string) is not a leaked key
                        nxt = lines[lineno] if lineno < len(lines) else ""
                        if not re.match(r"^\s*[A-Za-z0-9+/=]{20,}\s*$", nxt):
                            continue
                    ev = redact(m.group(0))
                    match_sev = sev
                    if pid != "private-key":
                        note = _pattern_hint(m.group(0), line[:m.start()])
                        if note:  # v0.4.1: AWS docs key / masked xoxb-xxxx… / form placeholder
                            match_sev = "low"
                            ev += " (%s)" % note
                    add("secret", match_sev, rel, lineno, summary=desc + " detected", evidence=ev)
            for gm in GENERIC.finditer(line):
                if re.match(r"^(https?|wss?)://", gm.group('value'), re.I):
                    continue  # Endpoint URLs are not credentials; check later assignments too.
                sev, note = _generic_sev(gm.group('value'), line[:gm.start('value')])
                ev = redact(gm.group('value'))
                if note:
                    ev += " (%s)" % note
                add("secret", sev, rel, lineno,
                    summary="Hardcoded %s assignment" % gm.group('name').lower(), evidence=ev)


# ---------------------------------------------------------------- config
def _workflow_fields(text):
    """Yield (line, parent path, key, value) for a bounded YAML block subset.

    This is a heuristic, not a YAML loader: no anchors, aliases, multiline quoted
    strings or general flow mappings. Ignore comments and literal/folded bodies
    so shell scripts and examples do not become workflow configuration.
    """
    stack = []
    block_indent = None
    for lineno, raw in enumerate(text.splitlines(), 1):
        indent = len(raw) - len(raw.lstrip(' '))
        if not raw.strip():
            continue
        if block_indent is not None:
            if indent > block_indent:
                continue
            block_indent = None
        # Preserve hashes inside quotes and unspaced hashes in plain scalars.
        line = re.sub(r'''"(?:\\.|[^"\\])*"|'(?:''|[^'])*'|(?<!\S)\#.*''',
                      lambda m: '' if m.group().startswith('#') else m.group(), raw).strip()
        if not line:
            continue
        while stack and stack[-1][0] >= indent:
            stack.pop()
        if line.startswith('- '):
            if tuple(k for _, k in stack) == ('on',):
                event = line[2:].strip().strip("\"'")
                if re.fullmatch(r'[\w-]+', event):
                    yield lineno, ('on',), event, ''
                    continue
            stack.append((indent, '@%d' % lineno))
            indent += 2
            line = line[2:].lstrip()
        match = re.match(r'''(?:"([^"\n]+)"|'([^'\n]+)'|([\w-]+)):\s*(.*)$''', line)
        if not match:
            continue
        key = next(k for k in match.groups()[:3] if k is not None)
        value = match.group(4).strip()
        parent = tuple(k for _, k in stack)
        if re.fullmatch(r'[|>][+\-1-9]{0,2}', value):
            block_indent = indent
            continue
        yield lineno, parent, key, value.strip("\"'")
        stack.append((indent, key))


def scan_workflow(text, rel, add):
    """Check common workflow forms without adding a YAML dependency."""
    fields = list(_workflow_fields(text))
    events = set()
    for _, parent, key, value in fields:
        if parent == ('on',):
            events.add(key)
        elif not parent and key == 'on':
            events.update(re.findall(r'(?:^|[\[{,])\s*[\"\']?'
                                     r'(pull_request_target|pull_request)[\"\']?'
                                     r'(?=\s*(?:[:,\]}]|$))', value))

    checkouts = set()
    for lineno, parent, key, value in fields:
        job = len(parent) == 2 and parent[0] == 'jobs'
        step = (len(parent) == 4 and parent[0] == 'jobs'
                and parent[2] == 'steps' and parent[3].startswith('@'))
        if key == 'uses' and (job or step):
            remote = re.fullmatch(r'([\w.-]+/[\w./-]+)@(.+)', value)
            if remote and not value.startswith(('./', '../')):
                if not re.fullmatch(r'[0-9a-fA-F]{40}', remote.group(2)):
                    add('config', 'low', rel, lineno,
                        summary='Unpinned remote GitHub Action or reusable workflow',
                        evidence='uses: remote reference is not a full commit SHA')
                if step and remote.group(1).lower() == 'actions/checkout':
                    checkouts.add(parent)

    for lineno, parent, key, value in fields:
        if 'pull_request' in events:
            scope = parent[:-1] if parent and parent[-1] == 'permissions' else parent
            permission_scope = not scope or (len(scope) == 2 and scope[0] == 'jobs')
            write = (key == 'permissions' and (value == 'write-all' or
                     re.search(r'''(?:\{|,)\s*[\w"'-]+\s*:\s*["']?write["']?\s*(?:,|\})''', value)))
            write = write or (parent and parent[-1] == 'permissions' and value == 'write')
            if permission_scope and write:
                add('config', 'medium', rel, lineno,
                    summary='PR-triggered workflow requests write permissions',
                    evidence='pull_request + explicit write permission declaration')
        if ('pull_request_target' in events and key == 'ref' and parent
                and parent[-1] == 'with' and parent[:-1] in checkouts
                and re.search(r'\$\{\{\s*github\.(?:event\.pull_request\.head\.(?:sha|ref)'
                              r'|head_ref)\s*\}\}', value)):
            add('config', 'high', rel, lineno,
                summary='pull_request_target checks out PR head',
                evidence='actions/checkout ref uses a pull request head expression')


def scan_config(root, files, add):
    for path in files:
        base = os.path.basename(path)
        rel = os.path.relpath(path, root)
        text = None

        def body():
            nonlocal text
            if text is None:
                text = read_text(path) or ""
            return text

        if (base == ".env" or base.startswith(".env.")) and not re.search(r"\.(example|sample|template|dist)$", base):
            for lineno, line in enumerate(body().splitlines(), 1):
                s = line.strip()
                if s and not s.startswith("#") and re.match(r"^(?:export[ \t]+)?[A-Za-z_][A-Za-z0-9_]*\s*=", s):
                    add("config", "high", rel, lineno,
                        summary="Committed .env file with assignments",
                        evidence=redact(s.split("=", 1)[0]) + "=…")
                    break
        if base == "Dockerfile" or base.startswith("Dockerfile."):
            _scan_dockerfile(body(), rel, add)
        if re.match(r"^docker-compose.*\.ya?ml$", base) or base in ("compose.yml", "compose.yaml"):
            for lineno, line in enumerate(body().splitlines(), 1):
                if re.fullmatch(r'''\s*(["']?)privileged\1:\s*true(?:\s+#.*)?\s*''', line, re.I):
                    add("config", "medium", rel, lineno,
                        summary="docker-compose service runs privileged",
                        evidence="privileged: true")
        if os.path.dirname(rel) == os.path.join('.github', 'workflows') and \
                base.endswith((".yml", ".yaml")):
            scan_workflow(body(), rel, add)
        if base in (".npmrc", ".pypirc"):
            for lineno, line in enumerate(body().splitlines(), 1):
                if line.lstrip().startswith(("#", ";")):
                    continue
                if base == ".npmrc" and re.fullmatch(
                        r"\s*(?://[^\s=]+:)?_authToken[ \t]*=\s*\$\{[A-Za-z_][A-Za-z0-9_]*\}\s*", line):
                    continue  # A standalone environment reference contains no literal credential.
                if re.fullmatch(r"\s*password\s*[:=]\s*", line, re.I):
                    continue  # An empty password field contains no credential.
                if ("_authToken=" in line
                        or re.match(r"^\s*(?://[^\s=]+:)?_authToken[ \t]+=", line)
                        or re.match(r"^\s*password\s*[:=]", line, re.I)):
                    add("config", "high", rel, lineno,
                        summary="Credential committed in %s" % base,
                        evidence=redact(line.strip()))
                    break


def _docker_instructions(text):
    """Yield logical instructions, excluding comments and heredoc bodies.

    Bounded Dockerfile heuristic: supports backslash/backtick continuations and
    simple named heredoc delimiters, not a full Dockerfile or shell parser.
    """
    escape, pending, start, heredocs = '\\', '', 0, []
    for lineno, raw in enumerate(text.splitlines(), 1):
        if heredocs:
            marker, tabs = heredocs[0]
            if (raw.lstrip('\t') if tabs else raw) == marker:
                heredocs.pop(0)
            continue
        line = raw.strip()
        if not line or line.startswith('#'):
            directive = re.fullmatch(r'#\s*escape\s*=\s*([\\`])', line, re.I)
            if directive and not pending:
                escape = directive[1]
            continue
        if not pending:
            start = lineno
        if line.endswith(escape):
            pending += line[:-1] + ' '
            continue
        line = pending + line
        pending = ''
        match = re.match(r'([A-Za-z]+)\s+(.*)', line)
        if not match:
            continue
        instruction, value = match[1].upper(), match[2]
        if instruction in ('RUN', 'COPY', 'ADD'):
            heredocs = [(m[3], bool(m[1])) for m in re.finditer(
                r'''(?:^|\s)<<(-?)(["']?)([A-Za-z_][A-Za-z0-9_]*)\2(?=\s|$)''', value)]
        yield start, instruction, value


def _scan_dockerfile(text, rel, add):
    instructions = list(_docker_instructions(text))
    if not any(op == 'USER' for _, op, _ in instructions):
        add('config', 'low', rel, None,
            summary='Dockerfile has no USER instruction (runs as root)',
            evidence='no USER directive')
    stages = set()
    final_user = None
    for lineno, op, value in instructions:
        if op == 'FROM':
            final_user = None
        elif op == 'USER':
            final_user = (lineno, value.strip())

        def finding(severity, summary, evidence):
            add('config', severity, rel, lineno, summary=summary, evidence=evidence)

        try:
            words = shlex.split(value)
        except ValueError:
            continue
        if op in ('FROM', 'ADD'):
            # Dockerfile options precede the operands and use --name=value.
            operands = re.sub(r'^(?:--\S+\s+)*', '', value)
            try:
                words = json.loads(operands) if operands.startswith('[') else shlex.split(operands)
            except (ValueError, TypeError):
                continue
            if not isinstance(words, list) or not all(isinstance(w, str) for w in words):
                continue
        if op == 'ADD' and any(re.match(r'https?://', w, re.I) for w in words[:-1]):
            finding('low', 'Dockerfile uses ADD with a remote URL', 'ADD remote URL (value omitted)')
        elif op == 'FROM' and words:
            image = words[0]
            if (image.lower() not in stages and image.lower() != 'scratch' and '$' not in image
                    and not re.search(r'@sha256:[0-9a-fA-F]{64}$', image)
                    and (':' not in image.rsplit('/', 1)[-1] or image.endswith(':latest'))):
                finding('low', 'Dockerfile base image uses latest (explicit or implicit)',
                        'FROM unversioned image or :latest (value omitted)')
            if len(words) == 3 and words[1].upper() == 'AS':
                stages.add(words[2].lower())
        elif op in ('ENV', 'ARG') and words:
            if op == 'ENV' and '=' not in words[0]:
                assignments = [(words[0], ' '.join(words[1:]))]
            else:
                assignments = [w.split('=', 1) for w in words if '=' in w]
            for name, assigned in assignments:
                if (re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', name)
                        and re.search(r'(?:^|_)(?:PASSWORD|PASSWD|SECRET|TOKEN|API_KEY|'
                                      r'PRIVATE_KEY|SECRET_KEY|SECRET_ACCESS_KEY)$', name, re.I)
                        and assigned and not re.fullmatch(r'\$[A-Za-z_]\w*|\$\{[A-Za-z_]\w*\}', assigned)):
                    finding('high', 'Dockerfile %s assigns secret-like variable %s' % (op, name), name + '=…')
        elif op == 'RUN' and not value.startswith('['):
            try:
                lexer = shlex.shlex(value, posix=True, punctuation_chars='|;&')
                lexer.whitespace_split = True
                tokens = list(lexer)
            except ValueError:
                continue
            command = []
            for index, token in enumerate(tokens):
                if token == '|' and command and index + 1 < len(tokens):
                    if (os.path.basename(command[0]) == 'curl'
                            and os.path.basename(tokens[index + 1]) in ('sh', 'bash')):
                        finding('medium', 'Dockerfile RUN pipes curl output to a shell', 'curl | shell')
                        break
                if re.fullmatch(r'[|;&]+', token):
                    command = []
                else:
                    command.append(token)

    if final_user and re.fullmatch(r'(?:root|0)(?::[A-Za-z0-9_.-]+)?', final_user[1]):
        add('config', 'low', rel, final_user[0],
            summary='Dockerfile final USER explicitly runs as root',
            evidence='USER root or UID 0 (value omitted)')


# ---------------------------------------------------------------- triage
# Deterministic interpretation layer (the paid "snapshot" value-add, W233).
# It discovers nothing and adds no findings; it only classifies and prioritises
# the deterministic findings above. The raw findings set and manifest_hash stay
# the verifiable trust anchor; triage is a separate, additive section surfaced
# only with --triage. This automates the hand-triage done on the first $49
# fulfilment dry run (mealie, 2026-10-05): fix-status action + secret FP filter.
TEST_PATH_RE = re.compile(
    r"(^|/)(__)?(tests?|spec|specs|fixtures?|test-?data|testing|test-?utils?|testutils?|mocks?|"
    r"snapshots?|examples?|samples?|demos?|e2e|cypress|\.github|docs?|stories|bench|benchmarks?|"
    r"benchmark-apps)(__)?(/|$)", re.I)  # v0.4.1: __fixtures__/__mocks__/testutils (sentry) join
TEST_FILE_RE = re.compile(
    r"(\.(test|spec|stories)\.[a-z0-9]+$|_test\.[a-z0-9]+$|^test_|^test-?utils?\.|^conftest\.py$|"
    r"\.(example|sample|template|dist)$)", re.I)
# v0.4.1: translation catalogues (`config/locales/server.ja.yml: password: "…"`) are UI copy
LOCALE_PATH_RE = re.compile(r"(^|/)(locales?|i18n|lang|langs|translations?|l10n)(/|$)", re.I)


def _secret_false_positive(f):
    """Return (is_fp, reason) for a secret finding from path + evidence heuristics."""
    path = f.get("file") or ""
    base = path.rsplit("/", 1)[-1]
    m = TEST_PATH_RE.search(path)
    if m:
        return True, "in a test/fixture/example path (%s)" % m.group(3).lower()
    if TEST_FILE_RE.search(base):
        return True, "filename marks it as a test/example/template"
    m = LOCALE_PATH_RE.search(path)
    if m:
        return True, "in a localization path (%s): translated UI text, not a credential" % m.group(2).lower()
    ev = f.get("evidence") or ""
    for note, reason in VALUE_HINTS.items():  # written by scan_secrets at detection time
        if "(%s)" % note in ev:
            return True, reason
    return False, None


def _triage_headline(up, mon, sec_review, sec_fp, scaffold=0, config_review=0):
    parts = []
    if up:
        parts.append("%d dependency advisory/ies fixable by upgrade" % up)
    if mon:
        parts.append("%d dependency advisory/ies with no patch yet (monitor/mitigate)" % mon)
    if scaffold:
        parts.append("%d of the dependency hits are in example/fixture/benchmark lockfiles (low priority)" % scaffold)
    if sec_review:
        parts.append("%d secret hit(s) needing review" % sec_review)
    if sec_fp:
        parts.append("%d secret hit(s) classified likely-false-positive" % sec_fp)
    if config_review:
        parts.append("%d configuration finding(s) needing review" % config_review)
    return "; ".join(parts) if parts else "no actionable findings after triage"


def triage_findings(findings):
    """Deterministic interpretation of the raw findings. Returns (per_id, summary)."""
    per_id = {}
    by_action = {"upgrade": 0, "monitor": 0, "review": 0, "informational": 0}
    dep_upgrade = dep_monitor = dep_scaffold = 0
    outside_scaffold = {"upgradeable": 0, "monitor_only": 0}
    sec_total = sec_fp = 0
    sec_review_files = set()
    secret_fp_reasons = {}
    sec_review_by_severity = dict.fromkeys((*SEV_ORDER, "unknown"), 0)
    config_review = 0
    for f in findings:
        cat = f["category"]
        t = {}
        if cat == "dependency-vuln":
            fixed = f.get("fixed_in") or []
            if fixed:
                t = {"action": "upgrade", "upgrade_to": fixed,
                     "note": "Patched release available: upgrade %s to %s."
                             % (f.get("package"), " / ".join(fixed))}
                dep_upgrade += 1
            else:
                t = {"action": "monitor",
                     "note": ("No patched release published for the advisory yet; pin the "
                              "version, monitor the advisory, and apply any documented "
                              "mitigation. Not fixable by upgrade today.")}
                dep_monitor += 1
            lock = f.get("file") or ""
            m = TEST_PATH_RE.search(lock)
            if m:
                # dataset 2026-10-08: react 546/618 and next.js 120/366 vulnerable rows came from
                # lockfiles under fixtures/, tests/, benchmark dirs — scaffolds, not the shipped graph
                dep_scaffold += 1
                t["scaffold"] = True
                t["priority"] = "low"
                t["reason"] = ("lockfile under a %s path: example/fixture/benchmark scaffold, "
                               "not the shipped dependency graph" % m.group(3).lower())
            else:
                outside_scaffold["upgradeable" if fixed else "monitor_only"] += 1
            if lock.endswith("go.sum"):
                t["note"] += (" Source is go.sum without a go.mod beside it: go.sum also lists "
                              "superseded module versions; confirm with govulncheck.")
        elif cat == "secret":
            sec_total += 1
            is_fp, reason = _secret_false_positive(f)
            if is_fp:
                sec_fp += 1
                secret_fp_reasons[reason] = secret_fp_reasons.get(reason, 0) + 1
                t = {"action": "informational", "likely_false_positive": True,
                     "reason": reason,
                     "note": "Likely not a live secret (%s); verify, but low priority." % reason}
            else:
                severity = f.get("severity", "unknown")
                sec_review_by_severity[severity] = sec_review_by_severity.get(severity, 0) + 1
                sec_review_files.add(f["file"])
                t = {"action": "review", "likely_false_positive": False,
                     "note": ("In a non-test path; confirm it is not a live credential and, "
                              "if real, rotate it and purge it from history.")}
        else:  # config / other
            t = {"action": "review"}
            if cat == "config":
                config_review += 1
        per_id[f["id"]] = t
        by_action[t["action"]] += 1
    summary = {
        "by_action": by_action,
        "dependency": {"upgradeable": dep_upgrade, "monitor_only": dep_monitor,
                       "in_scaffold_lockfiles": dep_scaffold},
        "dependency_outside_scaffold_lockfiles": outside_scaffold,
        "secrets": {"total": sec_total, "likely_false_positive": sec_fp,
                    "needs_review": sec_total - sec_fp},
        "config": {"needs_review": config_review},
        "secret_review_by_severity": sec_review_by_severity,
        "secret_files_needing_review": len(sec_review_files),
        "secret_false_positive_reasons": dict(sorted(secret_fp_reasons.items())),
        "headline": _triage_headline(dep_upgrade, dep_monitor, sec_total - sec_fp, sec_fp,
                                     dep_scaffold, config_review),
    }
    return per_id, summary


# ------------------------------------------------------------------ main
def git_head(path):
    try:
        out = subprocess.run(["git", "-C", path, "rev-parse", "HEAD"],
                             capture_output=True, text=True, timeout=30)
        return out.stdout.strip() or None if out.returncode == 0 else None
    except Exception:
        return None


def main(argv):
    ERRORS.clear()
    PARSED_LOCKFILES.clear()
    args = argv[1:]
    if args == ["--version"]:
        print(SCANNER + " " + VERSION)
        return 0
    if not args or args[0] in ("-h", "--help"):
        print(__doc__.strip())
        return 0
    target = args[0]
    out_path, use_osv, fail_on, triage = None, True, None, False
    compact = False
    i = 1
    while i < len(args):
        if args[i] in ("-h", "--help"):
            print(__doc__.strip())
            return 0
        if args[i] == "--json" and i + 1 < len(args):
            out_path = args[i + 1]
            i += 2
        elif args[i] == "--no-osv":
            use_osv = False
            i += 1
        elif args[i] == "--triage":
            triage = True
            i += 1
        elif args[i] == "--compact":
            compact = True
            i += 1
        elif args[i] == "--fail-on" and i + 1 < len(args):
            fail_on = args[i + 1].lower()
            if fail_on == "none":
                fail_on = None
            elif fail_on not in SEV_ORDER:
                sys.stderr.write("--fail-on must be one of critical|high|medium|low|none\n")
                return 2
            i += 2
        else:
            sys.stderr.write("unknown arg: %s\n" % args[i])
            return 2
    if re.match(r"^(https?|git)://|^git@", target):
        root = tempfile.mkdtemp(prefix="fds-clone-")
        try:
            clone_timeout = max(1, int(os.environ.get("FDS_CLONE_TIMEOUT", "600")))
        except ValueError:
            clone_timeout = 600
        env = dict(os.environ, GIT_LFS_SKIP_SMUDGE="1")
        r = subprocess.run(["git", "-c", "core.symlinks=false", "clone", "--depth", "1", target, root],
                           capture_output=True, text=True, timeout=clone_timeout, env=env)
        if r.returncode != 0:
            sys.stderr.write(r.stderr[-2000:])
            return 3
    else:
        root = os.path.abspath(target)
        if not os.path.isdir(root):
            sys.stderr.write("not a directory: %s\n" % root)
            return 2

    skipped = {"non_regular": 0}
    candidate_files = sorted(islice(walk(root, skipped), MAX_FILES + 1))
    files_truncated = len(candidate_files) > MAX_FILES
    files = candidate_files[:MAX_FILES]
    findings = []
    findings_per_file = {}
    findings_truncated = False

    def add(category, severity, file, line, summary, evidence,
            package=None, ecosystem=None, version=None, vuln_ids=None, fixed_in=None):
        nonlocal findings_truncated
        if len(findings) >= MAX_FINDINGS or findings_per_file.get(file, 0) >= MAX_FINDINGS_PER_FILE:
            findings_truncated = True
            return
        findings_per_file[file] = findings_per_file.get(file, 0) + 1
        findings.append({
            "id": None, "category": category, "severity": severity, "file": file,
            "line": line, "package": package, "ecosystem": ecosystem, "version": version,
            "vuln_ids": vuln_ids or [], "summary": summary, "evidence": evidence,
            "fixed_in": fixed_in or [],
        })

    pkgs = collect_packages(root, files)
    vulnerable = set()
    if use_osv and pkgs:
        hits = query_osv(list(pkgs.keys()))
        cache = {}
        # prefetch advisory details concurrently (wall time was dominated by serial GETs)
        from concurrent.futures import ThreadPoolExecutor
        all_ids = sorted({v for ids in hits.values() for v in ids})
        with ThreadPoolExecutor(max_workers=16) as ex:
            list(ex.map(lambda vid: vuln_details(vid, cache), all_ids))
        for key in sorted(hits):
            eco, name, ver = key
            vulnerable.add(key)
            details = [vuln_details(v, cache) for v in hits[key]]
            order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "unknown": 4}
            worst = min((d["severity"] for d in details), key=lambda s: order.get(s, 4))
            fixed = sorted({f for d in details for f in d["fixed_in"]})
            add("dependency-vuln", worst, pkgs[key], None,
                summary="%s %s has %d known vulnerability/ies (%s)"
                        % (name, ver, len(details), details[0]["summary"][:120]),
                evidence=", ".join(hits[key][:5]),
                package=name, ecosystem=eco, version=ver,
                vuln_ids=sorted(hits[key]), fixed_in=fixed)

    scan_secrets(root, files, add)
    scan_config(root, files, add)

    findings.sort(key=lambda f: ({"critical": 0, "high": 1, "medium": 2, "low": 3,
                                  "unknown": 4}.get(f["severity"], 4),
                                 f["category"], f["file"] or "", f["line"] or 0,
                                 f["package"] or "", f["summary"]))
    by_sev = {"critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0}
    files_by_sev = {severity: set() for severity in by_sev}
    by_category = {"dependency-vuln": 0, "secret": 0, "config": 0}
    by_category_severity = {category: dict.fromkeys(by_sev, 0) for category in by_category}
    highest_severity_by_file = {}
    secret_hits_by_rule = {}
    for n, f in enumerate(findings, 1):
        f["id"] = "F-%03d" % n
        by_sev[f["severity"]] = by_sev.get(f["severity"], 0) + 1
        files_by_sev.setdefault(f["severity"], set()).add(f["file"])
        by_category[f["category"]] = by_category.get(f["category"], 0) + 1
        if f["category"] == "secret":
            label = f["summary"]
            secret_hits_by_rule[label] = secret_hits_by_rule.get(label, 0) + 1
        # Findings are already sorted from highest to lowest severity.
        highest_severity_by_file.setdefault(f["file"], f["severity"])
        counts = by_category_severity.setdefault(f["category"], dict.fromkeys(by_sev, 0))
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1

    packages_by_ecosystem = {}
    for ecosystem, _, _ in sorted(pkgs):
        packages_by_ecosystem[ecosystem] = packages_by_ecosystem.get(ecosystem, 0) + 1

    vulnerable_packages_by_ecosystem = {}
    for ecosystem, _, _ in sorted(vulnerable):
        vulnerable_packages_by_ecosystem[ecosystem] = vulnerable_packages_by_ecosystem.get(ecosystem, 0) + 1

    packages_by_manifest = dict.fromkeys(sorted(PARSED_LOCKFILES), 0)
    for manifest in pkgs.values():
        packages_by_manifest[manifest] += 1

    packages_by_path_context = {"scaffold": 0, "other": 0}
    for manifest in pkgs.values():
        context = "scaffold" if TEST_PATH_RE.search(manifest) else "other"
        packages_by_path_context[context] += 1

    config_issues_by_rule = {}
    for f in findings:
        if f["category"] == "config":
            label = f["summary"]
            config_issues_by_rule[label] = config_issues_by_rule.get(label, 0) + 1

    config_files_by_rule = {}
    for f in findings:
        if f["category"] == "config":
            config_files_by_rule.setdefault(f["summary"], set()).add(f["file"])

    commit = git_head(root)
    doc = {
        "scanner": SCANNER, "version": VERSION, "target": target, "commit": commit,
        "scanned_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "summary": {
            "files_scanned": len(files),
            "files_with_findings": len({f["file"] for f in findings}),
            "findings_by_file": dict(sorted(findings_per_file.items())),
            "files_with_findings_by_category": {
                category: len({f["file"] for f in findings if f["category"] == category})
                for category in by_category
            },
            "skipped_non_regular": skipped["non_regular"],
            "packages_found": len(pkgs),
            "packages_by_ecosystem": packages_by_ecosystem,
            "packages_by_path_context": packages_by_path_context,
            "packages_by_manifest": packages_by_manifest,
            "vulnerable_packages": len(vulnerable),
            "dependency_findings_with_fixes": sum(
                1 for f in findings if f["category"] == "dependency-vuln" and f["fixed_in"]),
            "vulnerable_packages_by_ecosystem": vulnerable_packages_by_ecosystem,
            "unique_advisories": len({vid for f in findings
                                      if f["category"] == "dependency-vuln"
                                      for vid in f["vuln_ids"]}),
            "osv_enabled": use_osv,
            "errors_count": len(ERRORS),
            "secret_hits": sum(1 for f in findings if f["category"] == "secret"),
            "secret_lines": len({(f["file"], f["line"]) for f in findings
                                 if f["category"] == "secret"}),
            "secret_hits_by_rule": dict(sorted(secret_hits_by_rule.items())),
            "config_issues": sum(1 for f in findings if f["category"] == "config"),
            "config_files_by_rule": {
                rule: len(paths) for rule, paths in sorted(config_files_by_rule.items())
            },
            "config_issues_by_rule": dict(sorted(config_issues_by_rule.items())),
            "by_severity": by_sev,
            "files_by_severity": {severity: len(paths) for severity, paths in files_by_sev.items()},
            "highest_severity": findings[0]["severity"] if findings else None,
            "highest_severity_by_file": dict(sorted(highest_severity_by_file.items())),
            "by_category": by_category,
            "by_category_severity": by_category_severity,
            "lockfiles_parsed": sorted(PARSED_LOCKFILES),
            "limits": {"files": MAX_FILES, "findings": MAX_FINDINGS,
                       "findings_per_file": MAX_FINDINGS_PER_FILE},
            "truncated": {"findings": findings_truncated, "files": files_truncated},
        },
        "findings": findings,
    }
    gate_matches = 0
    if fail_on is not None:
        gate_matches = sum(1 for f in findings
                           if SEV_ORDER.get(f["severity"], 99) <= SEV_ORDER[fail_on])
        doc["summary"]["gate"] = {
            "threshold": fail_on,
            "matching_findings": gate_matches,
            "passed": gate_matches == 0,
        }
    if not PARSED_LOCKFILES:
        # a zero must not read as "clean" (dataset 2026-10-08: 3 of 25 repos scanned 0 packages)
        doc["summary"]["notes"] = [
            "No supported dependency manifest was parsed, so dependency advisories were NOT assessed. "
            "Supported: package-lock.json, yarn.lock (v1 + Berry), pnpm-lock.yaml, poetry.lock, uv.lock, "
            "Cargo.lock, Gemfile.lock, go.mod (go.sum only without go.mod), requirements*.txt."]
    if findings_truncated or files_truncated:
        doc["summary"].setdefault("notes", []).append(
            "Scan limits reached; results were truncated at the file or finding limit. "
            "Review the summary.truncated flags.")
    canon = json.dumps({"findings": findings, "target": target, "commit": commit},
                       sort_keys=True, separators=(",", ":"))
    doc["manifest_hash"] = hashlib.sha256(canon.encode()).hexdigest()
    if triage:
        per_id, tsummary = triage_findings(findings)
        doc["triage_summary"] = tsummary
        doc["triage"] = per_id
    if ERRORS:
        doc["errors"] = ERRORS
    text = json.dumps(doc, separators=(",", ":")) if compact else json.dumps(doc, indent=2)
    if out_path and out_path != "-":
        with open(out_path, "w") as fh:
            fh.write(text + "\n")
        sys.stderr.write("wrote %s (%d findings)\n" % (out_path, len(findings)))
    else:
        print(text)
    if fail_on is not None and any(
            SEV_ORDER.get(f["severity"], 99) <= SEV_ORDER[fail_on] for f in findings):
        sys.stderr.write("gate: findings at or above %s severity\n" % fail_on)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
