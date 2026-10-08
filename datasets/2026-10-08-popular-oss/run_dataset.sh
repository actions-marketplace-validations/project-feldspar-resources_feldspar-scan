#!/usr/bin/env bash
# Dataset 2026-10-08-popular-oss: shallow-clones the fixed repo list below and runs the deterministic
# scanner with --triage on each. Raw JSON + RUNS.txt (repo, HEAD, rc, seconds) go to $OUT (default ./out);
# then: python3 -I summarize.py out > SUMMARY.md. Clones are untrusted data in their own dir, removed after each scan.
set -u
WS=$(cd "$(dirname "$0")/../.." && pwd)
SCAN=$WS/scan.py
OUT=${OUT:-$PWD/out}
CLONES=${CLONES:-$PWD/clones}
mkdir -p "$OUT" "$CLONES"
REPOS="
vercel/next.js
facebook/react
vuejs/core
n8n-io/n8n
strapi/strapi
storybookjs/storybook
home-assistant/core
ansible/ansible
getsentry/sentry
langchain-ai/langchain
gradio-app/gradio
mitmproxy/mitmproxy
gohugoio/hugo
prometheus/prometheus
grafana/grafana
go-gitea/gitea
traefik/traefik
caddyserver/caddy
BurntSushi/ripgrep
sharkdp/bat
astral-sh/uv
tauri-apps/tauri
rails/rails
mastodon/mastodon
discourse/discourse
"
for r in $REPOS; do
  name=${r//\//__}
  if [ -s "$OUT/$name.json" ]; then echo "skip $r (done)"; continue; fi
  echo "=== $r $(date -u +%H:%M:%S)"
  rm -rf "$CLONES/$name"
  if ! timeout 600 git clone -q --depth 1 --filter=blob:none "https://github.com/$r.git" "$CLONES/$name" 2>"$OUT/$name.clone.err"; then
    echo "clone FAILED $r"; continue
  fi
  # blob:none filter leaves lockfiles lazily fetched on checkout; checkout already materialises the tree.
  head=$(git -C "$CLONES/$name" rev-parse HEAD)
  start=$(date +%s)
  timeout 900 python3 -I "$SCAN" "$CLONES/$name" --triage --json "$OUT/$name.json" >"$OUT/$name.log" 2>&1
  rc=$?
  echo "$r $head rc=$rc $(( $(date +%s) - start ))s" | tee -a "$OUT/RUNS.txt"
  rm -rf "$CLONES/$name"
done
echo "ALL DONE $(date -u +%H:%M:%S)"
