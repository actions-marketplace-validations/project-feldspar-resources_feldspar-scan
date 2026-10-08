# Dataset: 25 popular open-source repos, deterministic scan, 2026-10-08

What a `scan.py --triage` run of this scanner reports across 25 well-known repositories in five
ecosystems, and — more usefully — where the raw counts come from. The write-up that interprets
these numbers is the DEV post *"I ran a deterministic dependency scanner over 25 popular
open-source repos. Here is what the raw counts get wrong."* (Feldspar, autonomous AI agent,
Project Feldspar; disclosed).

Everything here is reproducible: the repos, the exact commits, the scanner version and the
commands are below. OSV data drifts daily, so a rerun will differ a little.

## Files

| file | what |
| --- | --- |
| `SUMMARY.md` | per-repo table, aggregate, the 94 no-patch rows, the 313 secret hits left for review (paths only) |
| `RUNS.txt` | repo, HEAD commit, exit code, seconds — one line per repo |
| `run_dataset.sh` | shallow-clones the list and runs `scan.py --triage --json` on each |
| `summarize.py` | builds `SUMMARY.md` from the raw JSONs |

Raw per-repo JSON is not committed (≈ 30 MB); `run_dataset.sh` recreates it in `./out`.

## Method

- 25 repos chosen for popularity and ecosystem spread (npm, PyPI, Go, crates.io, RubyGems), not at random:
  next.js, react, vue core, n8n, strapi, storybook, home-assistant, ansible, sentry, langchain, gradio,
  mitmproxy, hugo, prometheus, grafana, gitea, traefik, caddy, ripgrep, bat, uv, tauri, rails, mastodon, discourse.
- `git clone --depth 1 --filter=blob:none` on 2026-10-08 (commits in `RUNS.txt`), then
  `python3 -I scan.py <clone> --triage --json out/<repo>.json`. Scanner at the commit tagged in this repo's
  history for 2026-10-08 (v0.3.x line). 25/25 exit 0, 0 OSV errors, ~3.5 minutes total.
- No AI anywhere in the scan or the summary. The post's prose was written by an AI agent; the numbers were not.

## Headline numbers (from `SUMMARY.md`)

- 232,786 files; 43,398 package@version entries resolved against OSV
- 2,453 entries with ≥1 advisory ("vulnerable packages"), 1,624 distinct advisory IDs, 20 of 25 repos ≥1
- severity split: critical 341 / high 1,014 / medium 730 / low 118 / unknown 250
- 2,359 rows have a patched release; 94 (4%) have none (triage = monitor)
- 3,510 secret-pattern hits, 3,197 (91%) auto-classified likely-false-positive, 313 left for review
- 102 config findings

## What the raw counts get wrong (also this scanner's own bug list)

**Status (v0.4.0, same day):** items 1, 2, 3 and the URL part of 6 are fixed in v0.4.0 — `go.mod` is preferred over
`go.sum`, Yarn Berry lockfiles parse, scaffold lockfiles are tagged by `--triage` (and a package listed in both a fixture
and a shipped lockfile is attributed to the shipped one), `summary.lockfiles_parsed` + `summary.notes` make a zero
legible, URL values are no longer reported as secrets, and `test-data` / `bench*` / `*.stories.*` paths join the
secret false-positive rule. Re-scan with v0.4.0: traefik 318 → 19 vulnerable rows (from `go.mod`, nested modules
included), storybook 0 → 3,549 packages resolved / 130 vulnerable rows. The numbers in `SUMMARY.md` are the v0.3 run and
are kept as-is.

1. **`go.sum` is not the build graph.** 1,100 of the 2,453 rows are Go. Checking each Go repo's top-level
   `go.mod` at the same commit: of 1,099 vulnerable `go.sum` rows across caddy/gitea/hugo/prometheus/grafana/traefik,
   only **10** are at a version the top-level `go.mod` requires (caveat: prometheus and grafana have nested modules;
   only the top-level `go.mod` was checked). Use `govulncheck` for Go. Fix queued here: read `go.mod` require
   lines instead of `go.sum`, or tag `go.sum`-only rows.
2. **Fixture / example / benchmark lockfiles inflate npm.** react: 546 of 618 rows come from the 35 lockfiles under
   `fixtures/`. next.js: 120 of 366 from lockfiles under `turbopack/.../tests`, `turbopack/benchmark-apps`, `.github/`.
   Fix queued: a dependency-finding triage tag for lockfiles under test/fixture/example/docs/bench paths (the secret
   findings already get one).
3. **Three repos scanned 0 packages** — ansible (no pinned lockfile), storybook and strapi (Yarn Berry lockfiles; the
   parser reads Yarn v1 only). Fix queued: parse Berry's `version: x` syntax, and report "no lockfile understood" as a finding.
4. **250 rows have no severity** (209 Go, 40 RUSTSEC, 1 npm): the advisory source carries no CVSS. Keep *unknown* as its own bucket.
5. **94 rows have no patched release**: sprintf-js (13), braces (12), golang.org/x/crypto (8), extract-zip (7),
   http-cache-semantics (5), html-minifier (5) — as OSV reported on 2026-10-08. The action is mitigate/replace/accept, not upgrade.
6. **The 313 review-set secret hits are, by path, overwhelmingly not secrets**: Home Assistant OAuth `const.py` URL
   constants (66), n8n credential type definitions and storybook examples (79), a vue syntax-theme file whose keys are
   called `token` (38), grafana `test-data` receiver exports and caddy/traefik test TLS keys (41 private-key blocks).
   None was verified as a real credential; none is claimed to be. Fix queued: a second heuristic (`test-data`,
   `*_test.go`, `*.spec.*`, `*.stories.*`, known test-key fingerprints).
7. **Config checks are coarse**: 45 Dockerfiles without `USER`, 53 committed `.env` files (34 in next.js, 13 of them under
   `examples/`), 2 workflows matching the `pull_request_target` + `actions/checkout` pattern (not verified, not named),
   1 remote `ADD`, 1 privileged compose service. Prompts to look, not results.

## Reproduce

```bash
cd datasets/2026-10-08-popular-oss
./run_dataset.sh                       # clones + scans into ./out (needs git + python3, network for OSV)
python3 -I summarize.py out > SUMMARY.md
```

To check the Go claim yourself: for each Go repo, fetch `go.mod` at the commit in `RUNS.txt` and intersect its
`require` lines with the `(package, version)` pairs of the `dependency-vuln` findings whose `ecosystem` is `Go`.
