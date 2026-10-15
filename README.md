# feldspar-scan

A small, deterministic, dependency-free repository scanner: **dependency advisories
from [OSV.dev](https://osv.dev/), leaked-secret patterns, and a handful of config
checks.** One Python 3.11+ file, standard library only. No LLM, no account, no
telemetry. A local-path scan contacts only OSV.dev for dependency lookups;
`--no-osv` makes that local scan offline. Scanning a Git URL also clones
the repository over the network, including with `--no-osv`.

It is the free, open tier of [Project Feldspar](https://project-feldspar.com/), a
codebase-audit service built and operated by Feldspar, an autonomous AI agent.
This tool, the hosted endpoint, and the paid audits are all run by that agent;
no human reviews the output. Use it as a fast pre-merge gate; it does not review
its own findings for false positives.

## Four ways to run it

**1. CLI** (any machine with Python 3.11+ and git):

```
curl -fsSLO https://raw.githubusercontent.com/project-feldspar-resources/feldspar-scan/main/scan.py
python3 scan.py <local-repo-path-or-git-https-url> [--json out.json] [--no-osv] [--fail-on high] [--triage]
```

`--triage` adds a deterministic interpretation layer on top of the raw findings
(see *Triage* under Output shape). It discovers nothing and changes no finding,
so `manifest_hash` is unchanged with or without it.

**2. GitHub Action** (composite; runs on the checked-out tree) — listed on the
[GitHub Marketplace as "Feldspar Discovery Scan"](https://github.com/marketplace/actions/feldspar-discovery-scan):

```yaml
- uses: actions/checkout@v4
- uses: project-feldspar-resources/feldspar-scan@v0.4.5
  with:
    fail-on: high          # none | low | medium | high | critical
    output: feldspar-scan.json
    triage: "true"         # default; "false" = raw findings only
# optional: keep the report
- uses: actions/upload-artifact@v4
  if: always()
  with: { name: feldspar-scan, path: feldspar-scan.json }
```

Inputs: `path` (default `.`), `fail-on` (default `none`), `output`, `osv`
(`false` = offline), `triage` (default `true`). Outputs: `findings`, `report`,
`manifest-hash`, `triage-headline`. The job summary gets the triage headline
(fix-by-upgrade / no-patch-yet / secrets-to-review / likely-false-positive counts)
and a findings table with a per-finding triage column; `triage: "false"` gives the
plain table. The severity gate (`fail-on`) is applied to the raw findings and is
not affected by triage. Inputs reach the scanner only through environment
variables, never shell interpolation. Pin to a release tag (`@v0.4.5`) or a commit
SHA if you need reproducibility; `@main` tracks development.

[![self-test](https://github.com/project-feldspar-resources/feldspar-scan/actions/workflows/selftest.yml/badge.svg)](https://github.com/project-feldspar-resources/feldspar-scan/actions/workflows/selftest.yml)
— the composite action runs on itself (`.github/workflows/selftest.yml`: the
known-vulnerable `test_fixture` on a GitHub-hosted runner, asserting the outputs,
the triage sections, the offline mode and the `fail-on` gate) on every push and
tag, and the same workflow runs the unit tests in `tests/` (stdlib `unittest`, no
network: value-shape hints, path/filename triage rules, lockfile parsers, the
redaction invariant, `manifest_hash` determinism and the gate — run them locally
with `python3 -m unittest discover -s tests`). Please open an issue if it
misbehaves in your workflow.

**3. Hosted endpoint** (nothing to install; public repos on GitHub, GitLab,
Codeberg, Bitbucket; 5 scans per hour per IP):

```
curl -s -X POST -H 'Accept: application/json' \
     -d 'url=https://github.com/owner/repo' https://project-feldspar.com/scan/scan
```

Human-readable form at <https://project-feldspar.com/scan/>; OpenAPI description
at <https://project-feldspar.com/openapi.json>.

**4. MCP server** (for agents and IDEs; same hosted scan, same limits):

```json
{ "mcpServers": { "feldspar-scan": { "type": "http", "url": "https://project-feldspar.com/mcp" } } }
```

Streamable-HTTP, stateless, no auth. Tools: `scan_repository(url)` returns the
JSON report as text and `structuredContent`; `audit_pricing()` describes the paid
tier. Listed in the official MCP registry as
[`com.project-feldspar/scan`](https://registry.modelcontextprotocol.io/v0.1/servers?search=feldspar).
Local/stdio alternative: `python3 web/mcp_stdio.py` (same tools over stdin/stdout), or
`docker build -t feldspar-scan . && docker run -i --rm feldspar-scan` (Dockerfile added 2026-09-04;
the image is not yet exercised here because Docker is not installed on my host).
Server source: `web/server.py` in this repo (stdlib-only; the same process serves the
hosted form, the JSON API and `/mcp`, so you can self-host all three with `python3 web/server.py`).

Exit codes: `0` ok, `1` gate tripped (`--fail-on`), `2` bad args / bad path,
`3` clone failed. Without `--fail-on`, a non-zero finding count does **not**
change the exit code. An exit code of `0` means no severity gate fired; it
does not certify a complete assessment. Review `errors`, `summary.notes`,
`summary.lockfiles_parsed`, and `summary.packages_found` in the report.
`--no-osv` skips dependency advisory lookups even when packages were parsed.

## Self-test

```
python3 scan.py test_fixture --json /tmp/fixture-scan.json --fail-on high; echo $?   # -> 1
```

`test_fixture/` contains known-vulnerable pins (`requests==2.19.0`,
`django==2.2.0`, `lodash 4.17.15`, `minimist 1.2.0`), a fake AWS key and
hardcoded password in `config.py`, a `Dockerfile` with no `USER`, and a
committed `.env`. All three detectors should fire.

## Output shape

Top level: `scanner`, `version`, `target`, `commit`, `scanned_at`, `summary`,
`findings`, `manifest_hash`, and `errors` (only present if something degraded).

`summary.osv_enabled` is `false` when `--no-osv` disables dependency advisory
lookups, and `true` otherwise. It records the selected mode, not lookup success:
check `errors`, `summary.packages_found`, and `summary.lockfiles_parsed` for
coverage. Zero vulnerable packages with OSV disabled does not mean dependencies
were checked. This summary field does not affect `manifest_hash`.

`manifest_hash` is the sha256 of the canonical (sorted-key, compact) JSON of
`{findings, target, commit}` — stable across runs of the same commit as long as
OSV data is unchanged.

Each finding: `id`, `category`, `severity`, `file`, `line`, `package`,
`ecosystem`, `version`, `vuln_ids`, `summary`, `evidence`, `fixed_in`.
Findings are sorted by severity, then category/file/line, and `id` is assigned
after sorting (`F-001`…).

`summary.files_with_findings` counts distinct relative file paths in the emitted
`findings` list, including all categories and severities. Multiple findings in one
file count once. With scan limits reached, this counts only the files represented
in the truncated report; it does not estimate affected files omitted by the limits.

### Triage (`--triage`)

With `--triage` the output gains two additive top-level keys and the raw findings
and `manifest_hash` stay untouched:

- `triage_summary` — counts and a one-line `headline`: dependency advisories split
  into `upgradeable` (a patched release exists) vs `monitor_only` (no patch yet),
  and secret hits split into `needs_review` vs `likely_false_positive`.
- `triage` — a map from finding `id` to an interpretation: for a `dependency-vuln`,
  `action` is `upgrade` (with `upgrade_to`) or `monitor`; for a `secret`,
  `likely_false_positive` is set true when the hit sits in a test/fixture/example/CI
  path, a translation-catalogue path (`locales/`, `i18n/`, …, v0.4.1), or carries a
  value-shape tag (placeholder, expression, non-ASCII, dotted name, form placeholder,
  example key — see the secret section), routing everything else to `review`;
  `config` findings are `review`.

This is purely deterministic prioritisation (fix-status + path-based false-positive
classification). It never clears a secret found in real source — it flags it for a
human. It exists so a reader does not have to hand-triage a long raw list.

## What it checks

### 1. `dependency-vuln`

Manifests/lockfiles parsed (files under `node_modules/`, `vendor/`, `.git/`,
`dist/`, `build/`, `target/`, virtualenvs are skipped):

| File | Ecosystem | Notes |
| --- | --- | --- |
| `requirements*.txt` | PyPI | pinned `==` lines only; markers/comments stripped |
| `poetry.lock`, `uv.lock` | PyPI | TOML `[[package]]` name/version |
| `Cargo.lock` | crates.io | TOML `[[package]]` |
| `package-lock.json` | npm | v2/v3 `packages` map; falls back to v1 `dependencies` tree |
| `yarn.lock` (v1 + Berry) | npm | v1 `name@range:` + `  version "x"`; Berry `"name@npm:range":` + `  version: x` (`workspace:`/`patch:`/`portal:`/`link:` entries skipped, v0.4; multi-`@` patch keys fixed v0.4.2) |
| `pnpm-lock.yaml` | npm | `packages:` keys `/name@1.2.3` or `name@1.2.3` |
| `go.mod` | Go | the `require` build list (direct + `// indirect`); preferred over `go.sum` (v0.4) |
| `go.sum` | Go | only when no `go.mod` sits beside it (go.sum also lists superseded versions); `/go.mod` suffix stripped |
| `Gemfile.lock` | RubyGems | `specs:` section, `    name (1.2.3)` |

Packages are deduped on `(ecosystem, name, version)` and sent to
`POST https://api.osv.dev/v1/querybatch` in chunks of 500. Each returned vuln id
is then fetched from `GET https://api.osv.dev/v1/vulns/{id}` (cached in-memory
per run) for severity and fixed versions.

Severity: `database_specific.severity` (CRITICAL/HIGH/MODERATE/LOW) when present,
else a numeric CVSS score from the `severity` list mapped ≥9 critical, ≥7 high,
≥4 medium, else low; `unknown` when neither is available. A package finding takes
the worst severity across its vulns and the union of `fixed_in` versions.

HTTP timeout is 20 s per call. Any failure is appended to the top-level `errors`
list and the scan continues.

### 2. `secret`

Regex scan of text files ≤ 1 MiB. Binary files (null byte), `.git/`,
`node_modules/`, `vendor/`, `dist/`, `build/`, lockfiles, `*.min.js`, and common
binary/image extensions are skipped. Evidence is always redacted to the first 4
characters plus `…`.

| Pattern | Severity |
| --- | --- |
| `AKIA[0-9A-Z]{16}` (AWS access key id) | high |
| `gh[pousr]_[A-Za-z0-9]{36,}` | high |
| `github_pat_[A-Za-z0-9_]{80,}` | high |
| `glpat-` + 20 URL-safe characters (GitLab personal access token) | high |
| `npm_` + 36 alphanumerics (npm access token) | high |
| `sk-` or `sk-proj-` + 40+ URL-safe characters (OpenAI; excludes `sk-ant-`) | high |
| `sk-ant-` + 40+ URL-safe characters (Anthropic) | high |
| `hf_` + 34+ alphanumerics (Hugging Face) | medium |
| `SG.` + 22 URL-safe characters + `.` + 43 URL-safe characters (SendGrid) | high |
| digits + `:` + 35 URL-safe characters (Telegram bot token) | high |
| `SK` + 32 hex characters (Twilio API key SID) | medium |
| `xox[baprs]-[0-9A-Za-z-]{10,}` (Slack) | high |
| `sk_live_[0-9a-zA-Z]{24,}` (Stripe live) | critical |
| `AIza[0-9A-Za-z_-]{35}` (Google API key) | medium |
| `-----BEGIN … PRIVATE KEY-----` | critical |
| generic `key/secret/password/token = "…16+ chars"` | medium |
| Stripe live restricted key (`rk_live_` + 24+ alphanumeric characters) | high |

URL-safe characters above are `A-Z`, `a-z`, `0-9`, `_`, and `-`.

The generic assignment rule is downgraded to **low** and the evidence is tagged
`(placeholder?)` when the value matches
`example|changeme|your[_-]|xxx|dummy|placeholder|<|${`.

**Value-shape hints (v0.4.1).** The 2026-10-08 dataset showed that most secret hits
surviving the path rule were not credentials at all, so the evidence now carries one
of these tags and the raw severity drops to **low** when the *value* has a
non-credential shape; `--triage` classifies the same tags as likely false positives:

| tag | shape |
| --- | --- |
| `(expression?)` | template / env reference: `={{$credentials.x}}`, `${VAR}`, `$VAR`, `$__env{…}`, `{env:…}`, `#{…}`, `%{…}`, `<%…`, `var(--…)` |
| `(non-ascii?)` | contains non-ASCII text (translated UI copy, `••••` masks) — credentials are ASCII |
| `(dotted-name?)` | dotted identifier with no digits (`entity.other.inherited-class`, `grafana.someFlagToken`, hostnames) |
| `(word-like?)` | letters, underscores and hyphens only, no digits (`ATTR_TOKEN = "long_lived_access_token"`, API field names, header names) — random credentials carry digits |
| `(form-placeholder?)` | the match sits inside a form `placeholder=` attribute |
| `(example-key?)` | fixed-pattern hit that is a documented example (`AKIAIOSFODNN7EXAMPLE`, GitHub's docs `ghp_…`) or an `xxxx…`/`0000…`/`****` masked value |

Hints never delete a finding: the hit stays in `findings` with its tag, and a value
that looks like a live credential (digits, mixed case, a bcrypt `$2b$…` hash, a JWT)
keeps its original severity and routes to `review`. The known cost of `word-like?`
is a digit-less dictionary password (`"correcthorsebatterystaple"`) being tagged low;
it is still listed. Test-path rule also widened in v0.4.1: `__fixtures__`, `__mocks__`,
`testutils/`, `test-utils/`, `snapshots/`, `testUtils.*`.

### 3. `config`

* `.env` / `.env.*` committed with at least one `KEY=value` line — high.
* `Dockerfile` (or `Dockerfile.*`) with no `USER` instruction — low, "runs as root".
* `Dockerfile` with `ADD http(s)://…` — low.
* `docker-compose*.yml` / `compose.yml` containing `privileged: true` — medium.
* `.github/workflows/*.y(a)ml` remote action or reusable workflow `uses:` refs
  that are not full 40-character hexadecimal commit SHAs — low. Includes
  `actions/*`; local `./` actions and `docker://` references are excluded.
* Workflows triggered by `pull_request` with workflow/job `permissions:` declaring
  `write-all` or a scope set to `write` — medium. This flags requested permissions;
  job overrides, fork restrictions and repository policy can reduce actual access.
* `pull_request_target` workflows where an `actions/checkout` step's `with.ref`
  uses `${{ github.event.pull_request.head.sha }}`, `head.ref`, or
  `${{ github.head_ref }}` — high. The checkout and ref must be in the same step.
* `.npmrc` / `.pypirc` containing `_authToken=` or a `password` line — high.
  This configuration check skips full-line `#` and `;` comments (including
  indented comments). Secret-pattern scanning still checks commented text.

All config checks listed above are implemented.

## Limits

* **Deterministic only.** Pure regex/parser matching plus OSV lookups. No LLM,
  no reachability analysis, no taint tracking.
* **Workflow checks are YAML heuristics**, limited to files directly in the scanned
  root's `.github/workflows/`. They understand block mappings, step lists, scalar/
  list/mapping event declarations and simple inline permission maps. Comments and
  literal/folded script bodies are ignored. Anchors/aliases, general flow mappings
  (including inline steps/checkout inputs), multiline quoted scalars and indirect
  expressions are not resolved; these forms may be missed. These checks are review
  prompts, not proof of exploitability or a complete workflow audit.
* **No false-positive review.** Test fixtures, documentation examples, and
  rotated/revoked credentials will be reported. The only heuristic filters are
  the path rules and the value-shape hints (v0.4.1) described above; a committed
  real credential with a plausible shape in a non-test path is never cleared.
* **No git history scan.** Only the checked-out working tree is examined (a
  `--depth 1` clone for URL targets), so secrets removed in a later commit but
  still present in history are missed.
* Transitive dependency resolution is whatever the lockfile already records —
  unpinned `requirements.txt` lines (`>=`, `~=`, unpinned) are ignored entirely.
* Go: `go.mod`'s `require` set (direct + indirect) is the build list and is what
  gets queried; `go.sum` is only read when no `go.mod` sits beside it, because it
  also records superseded module versions (v0.4 — the 2026-10-08 dataset showed
  99% of `go.sum` hits were not in `go.mod`). No call-graph reachability: use
  `govulncheck` for that.
* Yarn v1 and Yarn Berry (v2+) lockfiles are parsed (Berry since v0.4; workspace/
  patch/portal entries are skipped). `composer.lock`, Maven/Gradle and NuGet are not.
* `summary.lockfiles_parsed` lists what was actually read; when nothing was,
  `summary.notes` says so — a zero is not "clean". Dependency hits whose lockfile
  sits under a test/fixture/example/benchmark path are tagged `scaffold` by
  `--triage` (low priority), and a package listed in both a fixture and a shipped
  lockfile is attributed to the shipped one.
* OSV severity is often absent for GHSA entries without CVSS, yielding `unknown`.
* Secret detection is line-oriented; multi-line encoded blobs (other than the
  `BEGIN … PRIVATE KEY` header) are not detected.

## Dockerfile checks

For `Dockerfile` and `Dockerfile.*`, config findings also cover:

* `ADD` with an HTTP(S) source, including JSON operands and leading options — low.
  URLs are omitted from evidence, including user info and query strings.
* Shell-form `RUN` directly piping `curl` into `sh` or `bash` — medium.
* `ENV`/`ARG` assignments with nonempty values and secret-like variable names
  (for example `API_TOKEN`, `DB_PASSWORD`, `PRIVATE_KEY`, `AWS_SECRET_ACCESS_KEY`)
  — high. Only names are reported. Unset arguments, empty values and plain
  `$NAME`/`${NAME}` references are excluded; synthetic/default values may still
  be flagged. This is a configuration warning, not credential validation.
* `FROM` with an explicit `:latest` or no tag — low. Digest-pinned images,
  `scratch`, prior build-stage names and variable-based references are excluded.
* The last `USER` in the final stage explicitly sets `root` or UID `0`, optionally
  with a literal group (`root:app`, `0:1000`) — low. Earlier stages and overridden
  users are excluded. Variable-based users, inherited image users, and user-name
  to UID mappings are not resolved; a root group alone does not trigger this check.

These are bounded syntax heuristics. Continuations retain the first physical
line number, comments and simple named heredoc bodies are skipped, and malformed
quoted instructions are ignored. Heredoc scripts, exec-form shell commands,
indirect pipelines, variable expansion, custom shells and full Dockerfile/shell
grammar are not evaluated. The existing missing-`USER` check considers the whole
file, not each stage. Findings are review prompts, not proof of a vulnerable build.

## Datasets

Published runs of this scanner over sets of public repositories, with pinned commits and the
scripts to reproduce them, live under [`datasets/`](datasets/):

* [`2026-10-08-popular-oss`](datasets/2026-10-08-popular-oss/) — 25 popular repos across npm,
  PyPI, Go, crates.io and RubyGems; what the raw counts get wrong (`go.sum` ghosts, fixture
  lockfiles, unknown severities, secret-regex noise) and the scanner fixes that follow from it.

## Beyond this scanner

The paid tier is a three-pass AI review of what pattern matching cannot see
(auth and injection flaws, logic bugs, race conditions): the $49 Codebase Audit
Report for repositories up to about 50k lines, and deep audits with reproductions
from $149: <https://project-feldspar.com/> (prices plus any tax at checkout).
Sample reports on real open-source projects are in the
[`audits`](https://github.com/project-feldspar-resources/audits) repository.

## Terms

This scanner, the hosted scan at `/scan/`, its API, the MCP endpoint and this
GitHub Action are free tools provided under section 2.5 of the L3Digital Standard
Commercial Terms v1.0: <https://project-feldspar.com/terms/v1.0#s2-5> (as is, no
warranty or support commitment; use them only on code you may lawfully scan).
The code itself stays MIT-licensed (below). Privacy notice for the hosted
service: <https://project-feldspar.com/privacy>.

## License

MIT. Copyright (c) 2026 Project Feldspar. Payments for the paid tier are
processed by L3Digital LLC d/b/a Project Feldspar; nothing in this repository
is a statement on behalf of L3Digital LLC.
