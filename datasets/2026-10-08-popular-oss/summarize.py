#!/usr/bin/env python3
"""Build SUMMARY.md for this dataset from the raw scan JSONs written by run_dataset.sh.

Usage: python3 summarize.py [raw_dir] > SUMMARY.md
Deterministic; no network. Numbers only — the narrative is written by hand in the post.
"""
import glob
import json
import os
import sys
from collections import Counter, defaultdict

WS = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
RAW = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(os.path.abspath(__file__)), "out")

rows = []
agg = Counter()
no_patch = []          # (repo, package, ecosystem, version, vuln_ids, severity)
sec_review_rows = []   # (repo, file, severity, pattern-ish summary)
eco_counter = Counter()
sev_pkgs = Counter()
config_kinds = Counter()
errors_total = 0

for path in sorted(glob.glob(os.path.join(RAW, "*.json"))):
    try:
        d = json.load(open(path))
    except Exception as e:  # noqa: BLE001
        print(f"<!-- unreadable {path}: {e} -->", file=sys.stderr)
        continue
    repo = os.path.basename(path)[:-5].replace("__", "/")
    s = d.get("summary", {})
    ts = d.get("triage_summary", {}) or {}
    tr = d.get("triage", {}) or {}
    dep = ts.get("dependency", {})
    sec = ts.get("secrets", {})
    errs = len(d.get("errors", []) or [])
    errors_total += errs
    by = s.get("by_severity", {})
    rows.append({
        "repo": repo, "commit": (d.get("commit") or "")[:9],
        "files": s.get("files_scanned", 0), "pkgs": s.get("packages_found", 0),
        "vuln_pkgs": s.get("vulnerable_packages", 0),
        "crit": by.get("critical", 0), "high": by.get("high", 0), "med": by.get("medium", 0), "low": by.get("low", 0),
        "up": dep.get("upgradeable", 0), "mon": dep.get("monitor_only", 0),
        "sec": sec.get("total", 0), "sec_fp": sec.get("likely_false_positive", 0), "sec_rev": sec.get("needs_review", 0),
        "cfg": s.get("config_issues", 0), "errs": errs,
    })
    for k in ("files", "pkgs", "vuln_pkgs", "up", "mon", "sec", "sec_fp", "sec_rev", "cfg"):
        agg[k] += rows[-1][k]
    for f in d.get("findings", []):
        cat = f.get("category")
        t = tr.get(f.get("id"), {})
        if cat == "dependency-vuln":
            eco_counter[f.get("ecosystem")] += 1
            sev_pkgs[f.get("severity")] += 1
            if t.get("action") == "monitor":
                no_patch.append((repo, f.get("package"), f.get("ecosystem"), f.get("version"),
                                 ",".join(f.get("vuln_ids", [])[:3]), f.get("severity")))
        elif cat == "secret" and t.get("action") == "review":
            sec_review_rows.append((repo, f.get("file"), f.get("severity"), (f.get("summary") or "")[:70]))
        elif cat == "config":
            config_kinds[(f.get("summary") or "")[:60]] += 1

print(f"# Deterministic scan dataset — {len(rows)} popular OSS repos (scanned 2026-10-08, OSV live, `scan.py --triage`)\n")
print("| repo | commit | files | packages | vuln pkgs | crit/high/med/low (all findings) | dep upgradeable | dep no-patch | secret hits | likely-FP | needs review | config | errors |")
print("| --- | --- | ---: | ---: | ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |")
for r in rows:
    print(f"| {r['repo']} | `{r['commit']}` | {r['files']} | {r['pkgs']} | {r['vuln_pkgs']} | {r['crit']}/{r['high']}/{r['med']}/{r['low']} | {r['up']} | {r['mon']} | {r['sec']} | {r['sec_fp']} | {r['sec_rev']} | {r['cfg']} | {r['errs']} |")

n = len(rows) or 1
print(f"\n## Aggregate\n")
print(f"- repos: {len(rows)}; files scanned: {agg['files']}; packages resolved against OSV: {agg['pkgs']}")
print(f"- vulnerable packages: {agg['vuln_pkgs']} ({agg['vuln_pkgs']/n:.1f} per repo); repos with ≥1: {sum(1 for r in rows if r['vuln_pkgs'])}")
print(f"- dependency advisories with a patched release available (upgrade): {agg['up']}; with NO patched release yet (monitor/mitigate): {agg['mon']}"
      + (f" → {100*agg['mon']/(agg['up']+agg['mon']):.0f}% of vulnerable packages have nothing to upgrade to" if agg['up']+agg['mon'] else ""))
print(f"- vulnerable-package severity split: {dict(sev_pkgs)}")
print(f"- vulnerable packages by ecosystem: {dict(eco_counter)}")
print(f"- secret-pattern hits: {agg['sec']}; auto-classified likely false positive (test/fixture/example/CI path or placeholder): {agg['sec_fp']}; left for human review: {agg['sec_rev']}"
      + (f" → {100*agg['sec_fp']/agg['sec']:.0f}% noise by path/placeholder alone" if agg['sec'] else ""))
print(f"- config findings: {agg['cfg']}; kinds: {dict(config_kinds)}")
print(f"- scanner errors (OSV timeouts etc.): {errors_total}")

print(f"\n## Vulnerable packages with NO patched release (triage = monitor) — {len(no_patch)}\n")
print("| repo | package | ecosystem | version | vuln ids | severity |")
print("| --- | --- | --- | --- | --- | --- |")
for r in sorted(no_patch):
    print("| " + " | ".join(str(x) for x in r) + " |")

print(f"\n## Secret hits left for human review — {len(sec_review_rows)} (evidence redacted by the scanner; paths only)\n")
print("| repo | file | severity | summary |")
print("| --- | --- | --- | --- |")
for r in sorted(sec_review_rows):
    print("| " + " | ".join(str(x) for x in r) + " |")
