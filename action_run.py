#!/usr/bin/env python3
"""Composite-action driver for scan.py. Reads inputs from FDS_* environment
variables (never from shell interpolation), runs the scanner, writes the
GitHub step outputs and a Markdown step summary, and applies the severity gate.
Runs anywhere: if GITHUB_OUTPUT / GITHUB_STEP_SUMMARY are unset it prints instead."""
import json
import os
import re
import subprocess
import sys

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
MAX_ROWS = 50


def out(name, value):
    path = os.environ.get("GITHUB_OUTPUT")
    line = "%s=%s\n" % (name, value)
    if path:
        with open(path, "a") as fh:
            fh.write(line)
    else:
        sys.stdout.write("output " + line)


def summary(md):
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if path:
        with open(path, "a") as fh:
            fh.write(md)
    else:
        sys.stdout.write(md)


def _vtuple(v):
    m = re.match(r"^v?(\d+(?:\.\d+)*)$", v)
    return tuple(int(x) for x in m.group(1).split(".")) if m else None


def triage_cell(t):
    """Short Markdown cell for one finding's triage entry (empty dict -> '')."""
    action = t.get("action") or ""
    if action == "upgrade":
        fixed = [v for v in (t.get("upgrade_to") or []) if not re.match(r"^[0-9a-f]{40}$", v)]
        numeric = [v for v in fixed if _vtuple(v)]
        if numeric:
            newest = max(numeric, key=_vtuple)
            cell = "upgrade (newest fixed release %s" % newest
            cell += "; %d fixed releases in the report)" % len(fixed) if len(fixed) > 1 else ")"
        elif fixed:
            cell = "upgrade to %s" % " / ".join(fixed[:3])
        else:
            cell = "upgrade (see report)"
        return cell.replace("|", "\\|")
    if action == "monitor":
        return "no patch yet: monitor/mitigate"
    if t.get("likely_false_positive"):
        return "likely false positive"
    if action == "review":
        return "review"
    return action


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    target = os.environ.get("FDS_PATH") or "."
    fail_on = (os.environ.get("FDS_FAIL_ON") or "none").strip().lower()
    report = os.environ.get("FDS_OUTPUT") or "feldspar-scan.json"
    use_osv = (os.environ.get("FDS_OSV") or "true").strip().lower() not in ("false", "0", "no")
    use_triage = (os.environ.get("FDS_TRIAGE") or "true").strip().lower() not in ("false", "0", "no")
    if fail_on != "none" and fail_on not in SEV_ORDER:
        sys.stderr.write("fail-on must be critical, high, medium, low or none (got %r)\n" % fail_on)
        return 2

    argv = [sys.executable, os.path.join(here, "scan.py"), target, "--json", report]
    if not use_osv:
        argv.append("--no-osv")
    if use_triage:
        argv.append("--triage")
    r = subprocess.run(argv)
    if r.returncode != 0 or not os.path.exists(report):
        sys.stderr.write("scan failed (exit %d)\n" % r.returncode)
        return r.returncode or 1

    with open(report) as fh:
        doc = json.load(fh)
    findings = doc.get("findings") or []
    by_sev = (doc.get("summary") or {}).get("by_severity") or {}
    triage = doc.get("triage") or {}
    tsum = doc.get("triage_summary") or {}
    out("findings", len(findings))
    out("report", report)
    out("manifest_hash", doc.get("manifest_hash", ""))
    out("triage_headline", (tsum.get("headline") or "") if use_triage else "")

    md = ["## Feldspar discovery scan\n",
          "**%d finding(s)** — " % len(findings)
          + ", ".join("%s: %d" % (k, by_sev.get(k, 0)) for k in ("critical", "high", "medium", "low", "unknown"))
          + "\n\n",
          "Scanned %d files, %d packages (%d with advisories). Commit `%s`. Report: `%s`. Manifest hash `%s`.\n\n" % (
              (doc.get("summary") or {}).get("files_scanned", 0),
              (doc.get("summary") or {}).get("packages_found", 0),
              (doc.get("summary") or {}).get("vulnerable_packages", 0),
              (doc.get("commit") or "")[:12], report, (doc.get("manifest_hash") or "")[:16])]
    if use_triage and tsum:
        dep = tsum.get("dependency") or {}
        sec = tsum.get("secrets") or {}
        md.append("**Triage:** %s\n\n" % (tsum.get("headline") or ""))
        md.append("Fix by upgrade: %d · no patch yet (monitor): %d · secret hits to review: %d · likely false positive: %d\n\n" % (
            dep.get("upgradeable", 0), dep.get("monitor_only", 0),
            sec.get("needs_review", 0), sec.get("likely_false_positive", 0)))
    if findings:
        if use_triage:
            md.append("| id | severity | category | file | summary | triage |\n|---|---|---|---|---|---|\n")
        else:
            md.append("| id | severity | category | file | summary |\n|---|---|---|---|---|\n")
        for f in findings[:MAX_ROWS]:
            loc = f.get("file") or ""
            if f.get("line"):
                loc += ":%s" % f["line"]
            row = "| %s | %s | %s | `%s` | %s |" % (
                f["id"], f["severity"], f["category"], loc.replace("|", "\\|"),
                (f.get("summary") or "").replace("|", "\\|")[:160])
            if use_triage:
                row += " %s |" % triage_cell(triage.get(f["id"]) or {})
            md.append(row + "\n")
        if len(findings) > MAX_ROWS:
            md.append("\n…and %d more in the JSON report.\n" % (len(findings) - MAX_ROWS))
    if doc.get("errors"):
        md.append("\n**Degraded:** %d lookup error(s); see `errors` in the report.\n" % len(doc["errors"]))
    md.append("\n<sub>Deterministic scan by <a href=\"https://github.com/project-feldspar-resources/feldspar-scan\">feldspar-scan</a> "
              "(an autonomous AI agent's tool; no LLM in this step). "
              + ("Triage is deterministic prioritisation (fix status + path heuristics), not a review. "
                 if use_triage else "Findings are not reviewed for false positives. ")
              + "Deeper, reviewed audits: https://project-feldspar.com/</sub>\n")
    summary("".join(md))

    if fail_on != "none" and any(SEV_ORDER.get(f["severity"], 99) <= SEV_ORDER[fail_on] for f in findings):
        sys.stderr.write("gate: findings at or above %s severity\n" % fail_on)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
