# Deterministic scan dataset — 25 popular OSS repos (scanned 2026-10-08, OSV live, `scan.py --triage`)

| repo | commit | files | packages | vuln pkgs | crit/high/med/low (all findings) | dep upgradeable | dep no-patch | secret hits | likely-FP | needs review | config | errors |
| --- | --- | ---: | ---: | ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| BurntSushi/ripgrep | `3fce3b5bb` | 236 | 84 | 0 | 0/0/0/0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| ansible/ansible | `bf2610eb3` | 5855 | 0 | 0 | 1/0/30/7 | 0 | 0 | 38 | 37 | 1 | 0 | 0 |
| astral-sh/uv | `301799d97` | 1838 | 940 | 17 | 3/4/13/2 | 13 | 4 | 10 | 9 | 1 | 2 | 0 |
| caddyserver/caddy | `221ebc450` | 705 | 367 | 53 | 11/11/10/0 | 52 | 1 | 3 | 1 | 2 | 0 | 0 |
| discourse/discourse | `f7814d5bc` | 26176 | 2021 | 29 | 3/773/302/1 | 26 | 3 | 1049 | 1016 | 33 | 1 | 0 |
| facebook/react | `b618bbb44` | 7252 | 7641 | 618 | 90/307/168/59 | 603 | 15 | 5 | 4 | 1 | 2 | 0 |
| getsentry/sentry | `99b4c2b07` | 21457 | 2221 | 6 | 3/49/136/8 | 4 | 2 | 190 | 175 | 15 | 0 | 0 |
| go-gitea/gitea | `89ec271d9` | 6331 | 1440 | 69 | 11/23/43/3 | 67 | 2 | 21 | 21 | 0 | 1 | 0 |
| gohugoio/hugo | `ac62c804c` | 2599 | 666 | 133 | 23/50/46/1 | 132 | 1 | 1 | 1 | 0 | 1 | 0 |
| gradio-app/gradio | `ff0dfca07` | 3093 | 1669 | 49 | 2/30/12/26 | 47 | 2 | 16 | 16 | 0 | 5 | 0 |
| grafana/grafana | `53d30de5c` | 23317 | 3373 | 469 | 130/189/280/43 | 463 | 6 | 222 | 160 | 62 | 33 | 0 |
| home-assistant/core | `767937bef` | 28735 | 1260 | 1 | 0/2/577/11 | 1 | 0 | 586 | 520 | 66 | 3 | 0 |
| langchain-ai/langchain | `1f587e3f4` | 3173 | 679 | 3 | 1/2/4/2 | 1 | 2 | 6 | 6 | 0 | 0 | 0 |
| mastodon/mastodon | `320d1342b` | 10071 | 346 | 0 | 3/3/3/1 | 0 | 0 | 6 | 6 | 0 | 4 | 0 |
| mitmproxy/mitmproxy | `5253dcbd1` | 1292 | 924 | 43 | 24/25/16/6 | 41 | 2 | 26 | 26 | 0 | 2 | 0 |
| n8n-io/n8n | `60ad29f24` | 30407 | 3970 | 67 | 14/96/1005/33 | 57 | 10 | 1077 | 994 | 83 | 4 | 0 |
| prometheus/prometheus | `d4467eede` | 1685 | 2466 | 117 | 13/52/35/5 | 111 | 6 | 11 | 11 | 0 | 2 | 0 |
| rails/rails | `ecd4dce48` | 5002 | 1042 | 56 | 1/35/48/6 | 53 | 3 | 33 | 30 | 3 | 1 | 0 |
| sharkdp/bat | `d9559c69f` | 910 | 335 | 8 | 1/2/1/2 | 5 | 3 | 0 | 0 | 0 | 3 | 0 |
| storybookjs/storybook | `a532e8a27` | 8658 | 0 | 0 | 0/1/6/0 | 0 | 0 | 6 | 6 | 0 | 1 | 0 |
| strapi/strapi | `51e508879` | 7049 | 0 | 0 | 0/5/71/1 | 0 | 0 | 76 | 75 | 1 | 1 | 0 |
| tauri-apps/tauri | `a225a18e6` | 1079 | 2196 | 17 | 1/6/5/2 | 7 | 10 | 4 | 0 | 4 | 1 | 0 |
| traefik/traefik | `bb4bdd60c` | 2345 | 1577 | 318 | 101/100/133/2 | 315 | 3 | 68 | 66 | 2 | 1 | 0 |
| vercel/next.js | `a32ddfdfd` | 32819 | 7539 | 366 | 51/193/119/34 | 348 | 18 | 18 | 17 | 1 | 34 | 0 |
| vuejs/core | `4ab865a84` | 702 | 642 | 14 | 1/10/41/0 | 13 | 1 | 38 | 0 | 38 | 0 | 0 |

## Aggregate

- repos: 25; files scanned: 232786; packages resolved against OSV: 43398
- vulnerable packages: 2453 (98.1 per repo); repos with ≥1: 20
- dependency advisories with a patched release available (upgrade): 2359; with NO patched release yet (monitor/mitigate): 94 → 4% of vulnerable packages have nothing to upgrade to
- vulnerable-package severity split: {'critical': 341, 'high': 1014, 'medium': 730, 'unknown': 250, 'low': 118}
- vulnerable packages by ecosystem: {'PyPI': 44, 'crates.io': 65, 'Go': 1100, 'npm': 1201, 'RubyGems': 43}
- secret-pattern hits: 3510; auto-classified likely false positive (test/fixture/example/CI path or placeholder): 3197; left for human review: 313 → 91% noise by path/placeholder alone
- config findings: 102; kinds: {'Dockerfile has no USER instruction (runs as root)': 45, 'pwn request pattern: pull_request_target checks out PR head': 2, 'Committed .env file with assignments': 53, 'Dockerfile uses ADD with a remote URL': 1, 'docker-compose service runs privileged': 1}
- scanner errors (OSV timeouts etc.): 0

## Vulnerable packages with NO patched release (triage = monitor) — 94

| repo | package | ecosystem | version | vuln ids | severity |
| --- | --- | --- | --- | --- | --- |
| astral-sh/uv | proc-macro-error2 | crates.io | 2.0.1 | RUSTSEC-2026-0173 | unknown |
| astral-sh/uv | rsa | crates.io | 0.9.10 | RUSTSEC-2023-0071 | unknown |
| astral-sh/uv | rustybuzz | crates.io | 0.20.1 | RUSTSEC-2026-0206 | unknown |
| astral-sh/uv | ttf-parser | crates.io | 0.25.1 | RUSTSEC-2026-0192 | unknown |
| caddyserver/caddy | golang.org/x/crypto | Go | v0.57.0 | GO-2026-5932 | unknown |
| discourse/discourse | braces | npm | 3.0.3 | GHSA-vfj7-8cjw-p6xm | high |
| discourse/discourse | http-cache-semantics | npm | 4.1.1 | GHSA-ch52-4w7c-c8xp | high |
| discourse/discourse | sprintf-js | npm | 1.1.3 | GHSA-hp3w-g68c-fv3c | medium |
| facebook/react | braces | npm | 3.0.3 | GHSA-vfj7-8cjw-p6xm | high |
| facebook/react | elliptic | npm | 6.6.1 | GHSA-848j-6mx2-7j84 | low |
| facebook/react | eslint-plugin-react-internal | npm | 0.0.0 | MAL-2025-19860 | unknown |
| facebook/react | extract-zip | npm | 1.6.7 | GHSA-7pqw-9j4j-h8q3,GHSA-jmr9-qjv8-65gv | high |
| facebook/react | extract-zip | npm | 2.0.1 | GHSA-7pqw-9j4j-h8q3,GHSA-jmr9-qjv8-65gv | high |
| facebook/react | html-minifier | npm | 3.2.3 | GHSA-pfq8-rq6v-vf5m | high |
| facebook/react | html-minifier | npm | 3.5.21 | GHSA-pfq8-rq6v-vf5m | high |
| facebook/react | html-minifier | npm | 3.5.3 | GHSA-pfq8-rq6v-vf5m | high |
| facebook/react | html-minifier | npm | 3.5.6 | GHSA-pfq8-rq6v-vf5m | high |
| facebook/react | http-cache-semantics | npm | 4.1.1 | GHSA-ch52-4w7c-c8xp | high |
| facebook/react | ip | npm | 1.1.9 | GHSA-2p57-rm9w-gvfp | high |
| facebook/react | node-forge | npm | 1.4.0 | GHSA-86w9-cpqp-85rv | high |
| facebook/react | sprintf-js | npm | 1.0.3 | GHSA-hp3w-g68c-fv3c | medium |
| facebook/react | sprintf-js | npm | 1.1.2 | GHSA-hp3w-g68c-fv3c | medium |
| facebook/react | sprintf-js | npm | 1.1.3 | GHSA-hp3w-g68c-fv3c | medium |
| getsentry/sentry | braces | npm | 3.0.3 | GHSA-vfj7-8cjw-p6xm | high |
| getsentry/sentry | sprintf-js | npm | 1.0.3 | GHSA-hp3w-g68c-fv3c | medium |
| go-gitea/gitea | braces | npm | 3.0.3 | GHSA-vfj7-8cjw-p6xm | high |
| go-gitea/gitea | golang.org/x/crypto | Go | v0.57.0 | GO-2026-5932 | unknown |
| gohugoio/hugo | golang.org/x/crypto | Go | v0.57.0 | GO-2026-5932 | unknown |
| gradio-app/gradio | braces | npm | 3.0.3 | GHSA-vfj7-8cjw-p6xm | high |
| gradio-app/gradio | sprintf-js | npm | 1.0.3 | GHSA-hp3w-g68c-fv3c | medium |
| grafana/grafana | github.com/aws/aws-sdk-go | Go | v1.38.35 | GO-2022-0635,GO-2022-0646 | unknown |
| grafana/grafana | github.com/aws/aws-sdk-go | Go | v1.55.5 | GO-2022-0635,GO-2022-0646 | unknown |
| grafana/grafana | github.com/aws/aws-sdk-go | Go | v1.55.8 | GO-2022-0635,GO-2022-0646 | unknown |
| grafana/grafana | golang.org/x/crypto | Go | v0.56.0 | GO-2026-5932 | unknown |
| grafana/grafana | golang.org/x/crypto | Go | v0.57.0 | GO-2026-5932 | unknown |
| grafana/grafana | rsc.io/pdf | Go | v0.1.1 | GO-2026-5781 | unknown |
| langchain-ai/langchain | chromadb | PyPI | 1.5.9 | GHSA-2wm9-hf6c-p5cr,GHSA-36p7-vc44-83pf,GHSA-f4j7-r4q5-qw2c | critical |
| langchain-ai/langchain | nltk | PyPI | 3.10.3 | GHSA-8mgp-746c-j5xp | high |
| mitmproxy/mitmproxy | braces | npm | 3.0.3 | GHSA-vfj7-8cjw-p6xm | high |
| mitmproxy/mitmproxy | sprintf-js | npm | 1.0.3 | GHSA-hp3w-g68c-fv3c | medium |
| n8n-io/n8n | braces | npm | 3.0.3 | GHSA-vfj7-8cjw-p6xm | high |
| n8n-io/n8n | element-plus | npm | 2.4.3 | GHSA-5m5x-9j46-h678 | medium |
| n8n-io/n8n | extract-zip | npm | 2.0.1 | GHSA-7pqw-9j4j-h8q3,GHSA-jmr9-qjv8-65gv | high |
| n8n-io/n8n | html-minifier | npm | 4.0.0 | GHSA-pfq8-rq6v-vf5m | high |
| n8n-io/n8n | http-cache-semantics | npm | 4.1.1 | GHSA-ch52-4w7c-c8xp | high |
| n8n-io/n8n | http-cache-semantics | npm | 4.2.0 | GHSA-ch52-4w7c-c8xp | high |
| n8n-io/n8n | node-forge | npm | 1.4.0 | GHSA-86w9-cpqp-85rv | high |
| n8n-io/n8n | showdown | npm | 2.1.0 | GHSA-22g5-r2x5-97cx,GHSA-cr32-g25g-vxjj,GHSA-rmmh-p597-ppvv | medium |
| n8n-io/n8n | sprintf-js | npm | 1.0.3 | GHSA-hp3w-g68c-fv3c | medium |
| n8n-io/n8n | sprintf-js | npm | 1.1.3 | GHSA-hp3w-g68c-fv3c | medium |
| prometheus/prometheus | braces | npm | 3.0.3 | GHSA-vfj7-8cjw-p6xm | high |
| prometheus/prometheus | github.com/aws/aws-sdk-go | Go | v1.55.8 | GO-2022-0635,GO-2022-0646 | unknown |
| prometheus/prometheus | golang.org/x/crypto | Go | v0.56.0 | GO-2026-5932 | unknown |
| prometheus/prometheus | golang.org/x/crypto | Go | v0.57.0 | GO-2026-5932 | unknown |
| prometheus/prometheus | node-forge | npm | 1.4.0 | GHSA-86w9-cpqp-85rv | high |
| prometheus/prometheus | sprintf-js | npm | 1.0.3 | GHSA-hp3w-g68c-fv3c | medium |
| rails/rails | braces | npm | 3.0.3 | GHSA-vfj7-8cjw-p6xm | high |
| rails/rails | extract-zip | npm | 2.0.1 | GHSA-7pqw-9j4j-h8q3,GHSA-jmr9-qjv8-65gv | high |
| rails/rails | http-cache-semantics | npm | 4.2.0 | GHSA-ch52-4w7c-c8xp | high |
| sharkdp/bat | bincode | crates.io | 1.3.3 | RUSTSEC-2025-0141 | unknown |
| sharkdp/bat | proc-macro-error2 | crates.io | 2.0.1 | RUSTSEC-2026-0173 | unknown |
| sharkdp/bat | yaml-rust | crates.io | 0.4.5 | RUSTSEC-2024-0320 | unknown |
| tauri-apps/tauri | braces | npm | 3.0.3 | GHSA-vfj7-8cjw-p6xm | high |
| tauri-apps/tauri | difference | crates.io | 2.0.0 | RUSTSEC-2020-0095 | unknown |
| tauri-apps/tauri | extract-zip | npm | 2.0.1 | GHSA-7pqw-9j4j-h8q3,GHSA-jmr9-qjv8-65gv | high |
| tauri-apps/tauri | fxhash | crates.io | 0.2.1 | RUSTSEC-2025-0057 | unknown |
| tauri-apps/tauri | paste | crates.io | 1.0.15 | RUSTSEC-2024-0436 | unknown |
| tauri-apps/tauri | proc-macro-error | crates.io | 1.0.4 | RUSTSEC-2024-0370 | unknown |
| tauri-apps/tauri | rsa | crates.io | 0.9.10 | RUSTSEC-2023-0071 | unknown |
| tauri-apps/tauri | rustls-pemfile | crates.io | 2.2.0 | RUSTSEC-2025-0134 | unknown |
| tauri-apps/tauri | rustybuzz | crates.io | 0.20.1 | RUSTSEC-2026-0206 | unknown |
| tauri-apps/tauri | ttf-parser | crates.io | 0.25.1 | RUSTSEC-2026-0192 | unknown |
| traefik/traefik | github.com/aws/aws-sdk-go | Go | v1.40.45 | GO-2022-0635,GO-2022-0646 | unknown |
| traefik/traefik | golang.org/x/crypto | Go | v0.57.0 | GO-2026-5932 | unknown |
| traefik/traefik | rsc.io/pdf | Go | v0.1.1 | GO-2026-5781 | unknown |
| vercel/next.js | adler | crates.io | 1.0.2 | RUSTSEC-2025-0056 | unknown |
| vercel/next.js | ansi_term | crates.io | 0.12.1 | RUSTSEC-2021-0139 | unknown |
| vercel/next.js | atomic-polyfill | crates.io | 0.1.11 | RUSTSEC-2023-0089 | unknown |
| vercel/next.js | aws-sdk | npm | 2.1240.0 | GHSA-j965-2qgj-vjmq | low |
| vercel/next.js | bincode | crates.io | 2.0.1 | RUSTSEC-2025-0141 | unknown |
| vercel/next.js | braces | npm | 3.0.3 | GHSA-vfj7-8cjw-p6xm | high |
| vercel/next.js | difference | crates.io | 2.0.0 | RUSTSEC-2020-0095 | unknown |
| vercel/next.js | extract-zip | npm | 1.7.0 | GHSA-7pqw-9j4j-h8q3,GHSA-jmr9-qjv8-65gv | high |
| vercel/next.js | extract-zip | npm | 2.0.1 | GHSA-7pqw-9j4j-h8q3,GHSA-jmr9-qjv8-65gv | high |
| vercel/next.js | json | crates.io | 0.12.4 | RUSTSEC-2022-0081 | unknown |
| vercel/next.js | parseuri | npm | 0.0.6 | GHSA-6fx8-h7jm-663j | medium |
| vercel/next.js | paste | crates.io | 1.0.15 | RUSTSEC-2024-0436 | unknown |
| vercel/next.js | proc-macro-error | crates.io | 1.0.4 | RUSTSEC-2024-0370 | unknown |
| vercel/next.js | smartstring | crates.io | 1.0.1 | RUSTSEC-2026-0249 | unknown |
| vercel/next.js | sprintf-js | npm | 1.0.3 | GHSA-hp3w-g68c-fv3c | medium |
| vercel/next.js | sprintf-js | npm | 1.1.2 | GHSA-hp3w-g68c-fv3c | medium |
| vercel/next.js | sprintf-js | npm | 1.1.3 | GHSA-hp3w-g68c-fv3c | medium |
| vercel/next.js | swig | npm | 1.4.2 | GHSA-2rq5-699j-x7p6 | high |
| vuejs/core | braces | npm | 3.0.3 | GHSA-vfj7-8cjw-p6xm | high |

## Secret hits left for human review — 313 (evidence redacted by the scanner; paths only)

| repo | file | severity | summary |
| --- | --- | --- | --- |
| ansible/ansible | lib/ansible/modules/expect.py | medium | Hardcoded password assignment |
| astral-sh/uv | crates/uv-auth/src/credentials.rs | medium | Hardcoded token assignment |
| caddyserver/caddy | caddytest/a.caddy.localhost.key | critical | Private key block detected |
| caddyserver/caddy | caddytest/caddy.localhost.key | critical | Private key block detected |
| discourse/discourse | config/locales/client.ja.yml | medium | Hardcoded password assignment |
| discourse/discourse | config/locales/client.ja.yml | medium | Hardcoded password assignment |
| discourse/discourse | config/locales/client.ja.yml | medium | Hardcoded password assignment |
| discourse/discourse | config/locales/client.ja.yml | medium | Hardcoded password assignment |
| discourse/discourse | config/locales/client.ja.yml | medium | Hardcoded password assignment |
| discourse/discourse | config/locales/client.zh_CN.yml | medium | Hardcoded password assignment |
| discourse/discourse | config/locales/client.zh_CN.yml | medium | Hardcoded password assignment |
| discourse/discourse | config/locales/client.zh_TW.yml | medium | Hardcoded password assignment |
| discourse/discourse | config/locales/client.zh_TW.yml | medium | Hardcoded password assignment |
| discourse/discourse | config/locales/server.ja.yml | medium | Hardcoded password assignment |
| discourse/discourse | config/locales/server.ja.yml | medium | Hardcoded password assignment |
| discourse/discourse | config/locales/server.ja.yml | medium | Hardcoded password assignment |
| discourse/discourse | config/locales/server.ja.yml | medium | Hardcoded password assignment |
| discourse/discourse | config/locales/server.ja.yml | medium | Hardcoded secret assignment |
| discourse/discourse | config/locales/server.ja.yml | medium | Hardcoded token assignment |
| discourse/discourse | config/locales/server.zh_CN.yml | medium | Hardcoded password assignment |
| discourse/discourse | config/locales/server.zh_CN.yml | medium | Hardcoded secret assignment |
| discourse/discourse | config/locales/server.zh_TW.yml | medium | Hardcoded password assignment |
| discourse/discourse | config/locales/server.zh_TW.yml | medium | Hardcoded secret assignment |
| discourse/discourse | lib/auth/default_current_user_provider.rb | medium | Hardcoded api_key assignment |
| discourse/discourse | lib/auth/default_current_user_provider.rb | medium | Hardcoded token assignment |
| discourse/discourse | lib/backup_restore/creator.rb | medium | Hardcoded password assignment |
| discourse/discourse | lib/backup_restore/database_restorer.rb | medium | Hardcoded password assignment |
| discourse/discourse | plugins/discourse-ai/config/locales/client.de.yml | medium | Hardcoded secret assignment |
| discourse/discourse | plugins/discourse-ai/config/locales/client.nl.yml | medium | Hardcoded secret assignment |
| discourse/discourse | plugins/discourse-ai/config/locales/server.zh_TW.yml | medium | Hardcoded secret assignment |
| discourse/discourse | plugins/discourse-ai/config/locales/server.zh_TW.yml | medium | Hardcoded secret assignment |
| discourse/discourse | plugins/discourse-chat-integration/config/locales/server.ja.yml | medium | Hardcoded token assignment |
| discourse/discourse | plugins/discourse-chat-integration/config/locales/server.ja.yml | medium | Hardcoded token assignment |
| discourse/discourse | plugins/discourse-openid-connect/config/locales/server.de.yml | medium | Hardcoded secret assignment |
| discourse/discourse | script/import_scripts/quandora/README.md | medium | Hardcoded password assignment |
| discourse/discourse | script/import_scripts/socialcast/README.md | medium | Hardcoded password assignment |
| discourse/discourse | script/profile_db_generator.rb | medium | Hardcoded password assignment |
| facebook/react | compiler/packages/react-mcp-server/src/utils/algolia.ts | medium | Hardcoded apikey assignment |
| getsentry/sentry | src/sentry/conf/server.py | medium | Hardcoded secret assignment |
| getsentry/sentry | src/sentry/integrations/github/client.py | medium | Hardcoded token assignment |
| getsentry/sentry | src/sentry/testutils/cases.py | high | Slack token detected |
| getsentry/sentry | src/sentry/testutils/factories.py | high | Slack token detected |
| getsentry/sentry | src/sentry/testutils/helpers/backups.py | medium | Hardcoded secret assignment |
| getsentry/sentry | src/sentry/testutils/helpers/github.py | medium | Hardcoded secret assignment |
| getsentry/sentry | src/sentry/testutils/helpers/slack.py | high | Slack token detected |
| getsentry/sentry | static/app/components/modals/debugFileCustomRepository/objectStorage.tsx | high | AWS access key ID detected |
| getsentry/sentry | static/app/components/onboarding/gettingStartedDoc/onboardingCodeSnippet.tsx | medium | Hardcoded token assignment |
| getsentry/sentry | static/app/components/tours/testUtils.tsx | medium | Hardcoded password assignment |
| getsentry/sentry | static/app/components/tours/tour.stories.tsx | medium | Hardcoded password assignment |
| getsentry/sentry | static/app/components/tours/tour.stories.tsx | medium | Hardcoded password assignment |
| getsentry/sentry | static/app/views/settings/organizationDataForwarding/components/projectOverrideForm.tsx | high | AWS access key ID detected |
| getsentry/sentry | static/app/views/settings/organizationDataForwarding/util/sqsForm.tsx | high | AWS access key ID detected |
| getsentry/sentry | static/gsApp/__fixtures__/previewData.tsx | medium | Hardcoded token assignment |
| grafana/grafana | conf/ldap.toml | medium | Hardcoded password assignment |
| grafana/grafana | devenv/docker/blocks/auth/authentik/key.pem | critical | Private key block detected |
| grafana/grafana | devenv/docker/blocks/auth/prometheus_oauth2_proxy_azure/oauth2-proxy.example.cfg | medium | Hardcoded secret assignment |
| grafana/grafana | pkg/login/social/connectors/azuread_oauth.go | medium | Hardcoded apikey assignment |
| grafana/grafana | pkg/services/authn/authn.go | medium | Hardcoded apikey assignment |
| grafana/grafana | pkg/services/authz/README.md | medium | Hardcoded token assignment |
| grafana/grafana | pkg/services/featuremgmt/toggles_gen.go | medium | Hardcoded token assignment |
| grafana/grafana | pkg/services/frontend/index.html | medium | Hardcoded token assignment |
| grafana/grafana | pkg/services/ngalert/api/test-data/receiver-exports/redacted/all-integrations.yaml | critical | Private key block detected |
| grafana/grafana | pkg/services/ngalert/api/test-data/receiver-exports/redacted/all-integrations.yaml | critical | Private key block detected |
| grafana/grafana | pkg/services/ngalert/api/test-data/receiver-exports/redacted/all-integrations.yaml | critical | Private key block detected |
| grafana/grafana | pkg/services/ngalert/api/test-data/receiver-exports/redacted/all-integrations.yaml | critical | Private key block detected |
| grafana/grafana | pkg/services/ngalert/api/test-data/receiver-exports/redacted/all-integrations.yaml | critical | Private key block detected |
| grafana/grafana | pkg/services/ngalert/api/test-data/receiver-exports/redacted/all-integrations.yaml | critical | Private key block detected |
| grafana/grafana | pkg/services/ngalert/api/test-data/receiver-exports/redacted/all-integrations.yaml | critical | Private key block detected |
| grafana/grafana | pkg/services/ngalert/api/test-data/receiver-exports/redacted/all-integrations.yaml | critical | Private key block detected |
| grafana/grafana | pkg/services/ngalert/api/test-data/receiver-exports/redacted/all-integrations.yaml | critical | Private key block detected |
| grafana/grafana | pkg/services/ngalert/api/test-data/receiver-exports/redacted/all-integrations.yaml | critical | Private key block detected |
| grafana/grafana | pkg/services/ngalert/api/test-data/receiver-exports/redacted/all-integrations.yaml | critical | Private key block detected |
| grafana/grafana | pkg/services/ngalert/api/test-data/receiver-exports/redacted/all-integrations.yaml | critical | Private key block detected |
| grafana/grafana | pkg/services/ngalert/api/test-data/receiver-exports/redacted/all-integrations.yaml | critical | Private key block detected |
| grafana/grafana | pkg/services/ngalert/api/test-data/receiver-exports/redacted/all-integrations.yaml | critical | Private key block detected |
| grafana/grafana | pkg/services/ngalert/api/test-data/receiver-exports/redacted/all-integrations.yaml | critical | Private key block detected |
| grafana/grafana | pkg/services/ngalert/api/test-data/receiver-exports/redacted/all-integrations.yaml | critical | Private key block detected |
| grafana/grafana | pkg/services/ngalert/api/test-data/receiver-exports/redacted/all-integrations.yaml | critical | Private key block detected |
| grafana/grafana | pkg/services/ngalert/api/test-data/receiver-exports/unredacted/all-integrations.hcl | medium | Hardcoded secret assignment |
| grafana/grafana | pkg/services/ngalert/api/test-data/receiver-exports/unredacted/all-integrations.hcl | medium | Hardcoded secret assignment |
| grafana/grafana | pkg/services/ngalert/api/test-data/receiver-exports/unredacted/all-integrations.yaml | critical | Private key block detected |
| grafana/grafana | pkg/services/ngalert/api/test-data/receiver-exports/unredacted/all-integrations.yaml | critical | Private key block detected |
| grafana/grafana | pkg/services/ngalert/api/test-data/receiver-exports/unredacted/all-integrations.yaml | critical | Private key block detected |
| grafana/grafana | pkg/services/ngalert/api/test-data/receiver-exports/unredacted/all-integrations.yaml | critical | Private key block detected |
| grafana/grafana | pkg/services/ngalert/api/test-data/receiver-exports/unredacted/all-integrations.yaml | critical | Private key block detected |
| grafana/grafana | pkg/services/ngalert/api/test-data/receiver-exports/unredacted/all-integrations.yaml | critical | Private key block detected |
| grafana/grafana | pkg/services/ngalert/api/test-data/receiver-exports/unredacted/all-integrations.yaml | critical | Private key block detected |
| grafana/grafana | pkg/services/ngalert/api/test-data/receiver-exports/unredacted/all-integrations.yaml | critical | Private key block detected |
| grafana/grafana | pkg/services/ngalert/api/test-data/receiver-exports/unredacted/all-integrations.yaml | critical | Private key block detected |
| grafana/grafana | pkg/services/ngalert/api/test-data/receiver-exports/unredacted/all-integrations.yaml | critical | Private key block detected |
| grafana/grafana | pkg/services/ngalert/api/test-data/receiver-exports/unredacted/all-integrations.yaml | critical | Private key block detected |
| grafana/grafana | pkg/services/ngalert/api/test-data/receiver-exports/unredacted/all-integrations.yaml | critical | Private key block detected |
| grafana/grafana | pkg/services/ngalert/api/test-data/receiver-exports/unredacted/all-integrations.yaml | critical | Private key block detected |
| grafana/grafana | pkg/services/ngalert/api/test-data/receiver-exports/unredacted/all-integrations.yaml | critical | Private key block detected |
| grafana/grafana | pkg/services/ngalert/api/test-data/receiver-exports/unredacted/all-integrations.yaml | critical | Private key block detected |
| grafana/grafana | pkg/services/ngalert/api/test-data/receiver-exports/unredacted/all-integrations.yaml | critical | Private key block detected |
| grafana/grafana | pkg/services/ngalert/api/test-data/receiver-exports/unredacted/all-integrations.yaml | critical | Private key block detected |
| grafana/grafana | pkg/services/ngalert/api/test-data/receiver-exports/unredacted/all-integrations.yaml | critical | Private key block detected |
| grafana/grafana | pkg/services/ngalert/api/test-data/receiver-exports/unredacted/all-integrations.yaml | critical | Private key block detected |
| grafana/grafana | public/app/dev-utils.ts | medium | Hardcoded api_key assignment |
| grafana/grafana | public/app/plugins/datasource/cloudwatch/language/cloudwatch-logs-sql/language.ts | medium | Hardcoded token assignment |
| grafana/grafana | public/app/plugins/datasource/cloudwatch/language/cloudwatch-logs-sql/language.ts | medium | Hardcoded token assignment |
| grafana/grafana | public/app/plugins/datasource/cloudwatch/language/cloudwatch-ppl/language.ts | medium | Hardcoded token assignment |
| grafana/grafana | public/app/plugins/datasource/cloudwatch/language/cloudwatch-sql/language.ts | medium | Hardcoded token assignment |
| grafana/grafana | public/app/plugins/datasource/cloudwatch/language/cloudwatch-sql/language.ts | medium | Hardcoded token assignment |
| grafana/grafana | public/app/plugins/datasource/cloudwatch/language/cloudwatch-sql/language.ts | medium | Hardcoded token assignment |
| grafana/grafana | public/app/plugins/datasource/cloudwatch/language/cloudwatch-sql/language.ts | medium | Hardcoded token assignment |
| grafana/grafana | public/app/plugins/datasource/cloudwatch/language/cloudwatch-sql/language.ts | medium | Hardcoded token assignment |
| grafana/grafana | public/app/plugins/datasource/cloudwatch/language/cloudwatch-sql/language.ts | medium | Hardcoded token assignment |
| grafana/grafana | public/app/plugins/datasource/cloudwatch/language/logs/language.ts | medium | Hardcoded token assignment |
| grafana/grafana | public/app/plugins/datasource/cloudwatch/language/logs/language.ts | medium | Hardcoded token assignment |
| grafana/grafana | public/app/plugins/datasource/cloudwatch/language/metric-math/language.ts | medium | Hardcoded token assignment |
| grafana/grafana | public/app/plugins/datasource/cloudwatch/language/metric-math/language.ts | medium | Hardcoded token assignment |
| grafana/grafana | public/app/plugins/datasource/cloudwatch/language/metric-math/language.ts | medium | Hardcoded token assignment |
| grafana/grafana | public/app/plugins/datasource/cloudwatch/language/metric-math/language.ts | medium | Hardcoded token assignment |
| home-assistant/core | homeassistant/auth/mfa_modules/totp.py | medium | Hardcoded secret assignment |
| home-assistant/core | homeassistant/auth/models.py | medium | Hardcoded token assignment |
| home-assistant/core | homeassistant/components/aladdin_connect/api.py | medium | Hardcoded api_key assignment |
| home-assistant/core | homeassistant/components/aladdin_connect/const.py | medium | Hardcoded token assignment |
| home-assistant/core | homeassistant/components/august/application_credentials.py | medium | Hardcoded token assignment |
| home-assistant/core | homeassistant/components/awair/config_flow.py | medium | Hardcoded token assignment |
| home-assistant/core | homeassistant/components/comfoconnect/__init__.py | medium | Hardcoded token assignment |
| home-assistant/core | homeassistant/components/dropbox/const.py | medium | Hardcoded token assignment |
| home-assistant/core | homeassistant/components/ekeybionyx/const.py | medium | Hardcoded token assignment |
| home-assistant/core | homeassistant/components/electric_kiwi/const.py | medium | Hardcoded token assignment |
| home-assistant/core | homeassistant/components/enphase_envoy/const.py | medium | Hardcoded token assignment |
| home-assistant/core | homeassistant/components/facebook/notify.py | medium | Hardcoded token assignment |
| home-assistant/core | homeassistant/components/fitbit/const.py | medium | Hardcoded secret assignment |
| home-assistant/core | homeassistant/components/fitbit/const.py | medium | Hardcoded token assignment |
| home-assistant/core | homeassistant/components/google_health/const.py | medium | Hardcoded token assignment |
| home-assistant/core | homeassistant/components/google_photos/const.py | medium | Hardcoded token assignment |
| home-assistant/core | homeassistant/components/google_tasks/const.py | medium | Hardcoded token assignment |
| home-assistant/core | homeassistant/components/growatt_server/number.py | medium | Hardcoded api_key assignment |
| home-assistant/core | homeassistant/components/growatt_server/number.py | medium | Hardcoded api_key assignment |
| home-assistant/core | homeassistant/components/growatt_server/number.py | medium | Hardcoded api_key assignment |
| home-assistant/core | homeassistant/components/growatt_server/number.py | medium | Hardcoded api_key assignment |
| home-assistant/core | homeassistant/components/growatt_server/number.py | medium | Hardcoded api_key assignment |
| home-assistant/core | homeassistant/components/growatt_server/sensor/mix.py | medium | Hardcoded api_key assignment |
| home-assistant/core | homeassistant/components/growatt_server/sensor/mix.py | medium | Hardcoded api_key assignment |
| home-assistant/core | homeassistant/components/growatt_server/sensor/mix.py | medium | Hardcoded api_key assignment |
| home-assistant/core | homeassistant/components/growatt_server/sensor/sph.py | medium | Hardcoded api_key assignment |
| home-assistant/core | homeassistant/components/growatt_server/sensor/sph.py | medium | Hardcoded api_key assignment |
| home-assistant/core | homeassistant/components/growatt_server/sensor/storage.py | medium | Hardcoded api_key assignment |
| home-assistant/core | homeassistant/components/growatt_server/sensor/storage.py | medium | Hardcoded api_key assignment |
| home-assistant/core | homeassistant/components/growatt_server/sensor/storage.py | medium | Hardcoded api_key assignment |
| home-assistant/core | homeassistant/components/growatt_server/sensor/storage.py | medium | Hardcoded api_key assignment |
| home-assistant/core | homeassistant/components/growatt_server/sensor/tlx.py | medium | Hardcoded api_key assignment |
| home-assistant/core | homeassistant/components/growatt_server/sensor/tlx.py | medium | Hardcoded api_key assignment |
| home-assistant/core | homeassistant/components/growatt_server/sensor/tlx.py | medium | Hardcoded api_key assignment |
| home-assistant/core | homeassistant/components/growatt_server/sensor/tlx.py | medium | Hardcoded api_key assignment |
| home-assistant/core | homeassistant/components/hassio/const.py | medium | Hardcoded token assignment |
| home-assistant/core | homeassistant/components/husqvarna_automower/const.py | medium | Hardcoded token assignment |
| home-assistant/core | homeassistant/components/iotty/application_credentials.py | medium | Hardcoded token assignment |
| home-assistant/core | homeassistant/components/litellm/const.py | medium | Hardcoded api_key assignment |
| home-assistant/core | homeassistant/components/llama_cpp/const.py | medium | Hardcoded api_key assignment |
| home-assistant/core | homeassistant/components/lyric/const.py | medium | Hardcoded token assignment |
| home-assistant/core | homeassistant/components/microbees/const.py | medium | Hardcoded token assignment |
| home-assistant/core | homeassistant/components/mobile_app/const.py | medium | Hardcoded token assignment |
| home-assistant/core | homeassistant/components/mobile_app/const.py | medium | Hardcoded token assignment |
| home-assistant/core | homeassistant/components/monzo/application_credentials.py | medium | Hardcoded token assignment |
| home-assistant/core | homeassistant/components/mqtt/config_flow.py | medium | Hardcoded password assignment |
| home-assistant/core | homeassistant/components/myuplink/const.py | medium | Hardcoded token assignment |
| home-assistant/core | homeassistant/components/nest/const.py | medium | Hardcoded token assignment |
| home-assistant/core | homeassistant/components/netatmo/const.py | medium | Hardcoded token assignment |
| home-assistant/core | homeassistant/components/ondilo_ico/const.py | medium | Hardcoded token assignment |
| home-assistant/core | homeassistant/components/peblar/services.py | medium | Hardcoded token assignment |
| home-assistant/core | homeassistant/components/peblar/services.py | medium | Hardcoded token assignment |
| home-assistant/core | homeassistant/components/peblar/services.py | medium | Hardcoded token assignment |
| home-assistant/core | homeassistant/components/point/const.py | medium | Hardcoded token assignment |
| home-assistant/core | homeassistant/components/ruckus_unleashed/const.py | medium | Hardcoded token assignment |
| home-assistant/core | homeassistant/components/tedee/const.py | medium | Hardcoded token assignment |
| home-assistant/core | homeassistant/components/tessie/config_flow.py | medium | Hardcoded token assignment |
| home-assistant/core | homeassistant/components/tibber/config_flow.py | medium | Hardcoded token assignment |
| home-assistant/core | homeassistant/components/twitch/const.py | medium | Hardcoded token assignment |
| home-assistant/core | homeassistant/components/twitter/notify.py | medium | Hardcoded secret assignment |
| home-assistant/core | homeassistant/components/wake_on_lan/const.py | medium | Hardcoded password assignment |
| home-assistant/core | homeassistant/components/watts/const.py | medium | Hardcoded token assignment |
| home-assistant/core | homeassistant/components/willow/const.py | medium | Hardcoded token assignment |
| home-assistant/core | homeassistant/components/xbox/const.py | medium | Hardcoded token assignment |
| home-assistant/core | homeassistant/components/yale/application_credentials.py | medium | Hardcoded token assignment |
| home-assistant/core | homeassistant/helpers/config_entry_oauth2_flow.py | medium | Hardcoded secret assignment |
| n8n-io/n8n | .agents/skills/create-instance-ai-eval/running-evals.md | medium | Hardcoded api_key assignment |
| n8n-io/n8n | .devcontainer/codespaces/agent-worker.mjs | medium | Hardcoded apikey assignment |
| n8n-io/n8n | .devcontainer/codespaces/opencode-server.mjs | medium | Hardcoded apikey assignment |
| n8n-io/n8n | packages/@n8n/agents/vitest.integration.setup.ts | medium | Hardcoded api_key assignment |
| n8n-io/n8n | packages/@n8n/agents/vitest.integration.setup.ts | medium | Hardcoded api_key assignment |
| n8n-io/n8n | packages/@n8n/api-types/src/dto/credentials/credential-public.dto.ts | medium | Hardcoded token assignment |
| n8n-io/n8n | packages/@n8n/instance-ai/README.md | medium | Hardcoded api_key assignment |
| n8n-io/n8n | packages/@n8n/instance-ai/evaluations/credentials/seeder.ts | medium | Hardcoded secret assignment |
| n8n-io/n8n | packages/@n8n/instance-ai/scripts/run-eval-lanes.sh | medium | Hardcoded api_key assignment |
| n8n-io/n8n | packages/@n8n/node-cli/src/template/templates/shared/credentials/basicAuth.credentials.ts | medium | Hardcoded password assignment |
| n8n-io/n8n | packages/@n8n/node-cli/src/template/templates/shared/credentials/custom.credentials.ts | medium | Hardcoded token assignment |
| n8n-io/n8n | packages/@n8n/node-cli/src/template/templates/shared/credentials/custom.credentials.ts | medium | Hardcoded token assignment |
| n8n-io/n8n | packages/@n8n/node-cli/src/template/templates/shared/default/.agents/credentials.md | medium | Hardcoded password assignment |
| n8n-io/n8n | packages/@n8n/nodes-langchain/credentials/SerpApi.credentials.ts | medium | Hardcoded api_key assignment |
| n8n-io/n8n | packages/@n8n/nodes-langchain/credentials/WolframAlphaApi.credentials.ts | medium | Hardcoded api_key assignment |
| n8n-io/n8n | packages/@n8n/nodes-langchain/nodes/embeddings/EmbeddingsDatabricks/EmbeddingsDatabricks.node.ts | medium | Hardcoded apikey assignment |
| n8n-io/n8n | packages/@n8n/nodes-langchain/nodes/llms/LmChatDatabricks/LmChatDatabricks.node.ts | medium | Hardcoded apikey assignment |
| n8n-io/n8n | packages/@n8n/task-runner-python/src/constants.py | medium | Hardcoded token assignment |
| n8n-io/n8n | packages/core/src/execution-engine/eval-mock-helpers.ts | medium | Hardcoded token assignment |
| n8n-io/n8n | packages/core/src/execution-engine/eval-mock-helpers.ts | medium | Hardcoded token assignment |
| n8n-io/n8n | packages/frontend/@n8n/design-system/src/components/N8nSettingsLayout/Examples.stories.ts | medium | Hardcoded apikey assignment |
| n8n-io/n8n | packages/frontend/@n8n/design-system/src/components/N8nSettingsLayout/Examples.stories.ts | medium | Hardcoded apikey assignment |
| n8n-io/n8n | packages/frontend/@n8n/design-system/src/components/N8nSettingsLayout/Examples.stories.ts | medium | Hardcoded apikey assignment |
| n8n-io/n8n | packages/frontend/@n8n/design-system/src/components/N8nSettingsLayout/Examples.stories.ts | medium | Hardcoded apikey assignment |
| n8n-io/n8n | packages/frontend/@n8n/design-system/src/components/N8nSettingsLayout/Examples.stories.ts | medium | Hardcoded token assignment |
| n8n-io/n8n | packages/frontend/@n8n/design-system/src/components/N8nSettingsLayout/SettingsLayout.stories.ts | medium | Hardcoded apikey assignment |
| n8n-io/n8n | packages/frontend/@n8n/design-system/src/components/N8nSettingsLayout/SettingsLayout.stories.ts | medium | Hardcoded apikey assignment |
| n8n-io/n8n | packages/frontend/@n8n/design-system/src/components/N8nSettingsLayout/SettingsLayout.stories.ts | medium | Hardcoded apikey assignment |
| n8n-io/n8n | packages/frontend/@n8n/design-system/src/components/N8nSettingsLayout/SettingsLayout.stories.ts | medium | Hardcoded apikey assignment |
| n8n-io/n8n | packages/frontend/@n8n/design-system/src/styleguide/components/ShadowExamples.vue | medium | Hardcoded token assignment |
| n8n-io/n8n | packages/frontend/@n8n/design-system/src/styleguide/components/ShadowExamples.vue | medium | Hardcoded token assignment |
| n8n-io/n8n | packages/frontend/@n8n/design-system/src/styleguide/components/ShadowExamples.vue | medium | Hardcoded token assignment |
| n8n-io/n8n | packages/frontend/@n8n/design-system/src/styleguide/components/ShadowExamples.vue | medium | Hardcoded token assignment |
| n8n-io/n8n | packages/frontend/@n8n/design-system/src/styleguide/components/ShadowExamples.vue | medium | Hardcoded token assignment |
| n8n-io/n8n | packages/frontend/@n8n/design-system/src/styleguide/components/ShadowExamples.vue | medium | Hardcoded token assignment |
| n8n-io/n8n | packages/frontend/@n8n/design-system/src/styleguide/components/TypeExamples.vue | medium | Hardcoded token assignment |
| n8n-io/n8n | packages/frontend/@n8n/design-system/src/styleguide/components/TypeExamples.vue | medium | Hardcoded token assignment |
| n8n-io/n8n | packages/frontend/@n8n/design-system/src/styleguide/components/TypeExamples.vue | medium | Hardcoded token assignment |
| n8n-io/n8n | packages/frontend/@n8n/design-system/src/styleguide/components/TypeExamples.vue | medium | Hardcoded token assignment |
| n8n-io/n8n | packages/frontend/@n8n/design-system/src/styleguide/components/TypeExamples.vue | medium | Hardcoded token assignment |
| n8n-io/n8n | packages/frontend/@n8n/frontend-constants/src/views.ts | medium | Hardcoded password assignment |
| n8n-io/n8n | packages/frontend/@n8n/frontend-constants/src/views.ts | medium | Hardcoded password assignment |
| n8n-io/n8n | packages/frontend/editor-ui/src/app/utils/rbacUtils.ts | medium | Hardcoded secret assignment |
| n8n-io/n8n | packages/frontend/editor-ui/src/features/credentials/components/CredentialPicker/CredentialPicker.test.constants.ts | medium | Hardcoded apikey assignment |
| n8n-io/n8n | packages/frontend/editor-ui/src/features/roles/instance/instanceRoleScopes.ts | medium | Hardcoded apikey assignment |
| n8n-io/n8n | packages/frontend/editor-ui/src/features/settings/apiKeys/views/SettingsApiView.vue | medium | Hardcoded api-key assignment |
| n8n-io/n8n | packages/frontend/editor-ui/src/features/settings/apiKeys/views/SettingsApiView.vue | medium | Hardcoded api-key assignment |
| n8n-io/n8n | packages/nodes-base/credentials/AirtableApi.credentials.ts | medium | Hardcoded api_key assignment |
| n8n-io/n8n | packages/nodes-base/credentials/BeeminderApi.credentials.ts | medium | Hardcoded token assignment |
| n8n-io/n8n | packages/nodes-base/credentials/ElasticsearchApi.credentials.ts | medium | Hardcoded password assignment |
| n8n-io/n8n | packages/nodes-base/credentials/F5BigIpApi.credentials.ts | medium | Hardcoded password assignment |
| n8n-io/n8n | packages/nodes-base/credentials/FacebookGraphApi.credentials.ts | medium | Hardcoded token assignment |
| n8n-io/n8n | packages/nodes-base/credentials/FortiGateApi.credentials.ts | medium | Hardcoded token assignment |
| n8n-io/n8n | packages/nodes-base/credentials/GumroadApi.credentials.ts | medium | Hardcoded token assignment |
| n8n-io/n8n | packages/nodes-base/credentials/HubspotApi.credentials.ts | medium | Hardcoded apikey assignment |
| n8n-io/n8n | packages/nodes-base/credentials/IterableApi.credentials.ts | medium | Hardcoded api_key assignment |
| n8n-io/n8n | packages/nodes-base/credentials/JinaAiApi.credentials.ts | medium | Hardcoded api_key assignment |
| n8n-io/n8n | packages/nodes-base/credentials/JiraSoftwareCloudApi.credentials.ts | medium | Hardcoded password assignment |
| n8n-io/n8n | packages/nodes-base/credentials/JiraSoftwareServerApi.credentials.ts | medium | Hardcoded password assignment |
| n8n-io/n8n | packages/nodes-base/credentials/KibanaApi.credentials.ts | medium | Hardcoded password assignment |
| n8n-io/n8n | packages/nodes-base/credentials/MailgunApi.credentials.ts | medium | Hardcoded password assignment |
| n8n-io/n8n | packages/nodes-base/credentials/MailjetEmailApi.credentials.ts | medium | Hardcoded password assignment |
| n8n-io/n8n | packages/nodes-base/credentials/MalcoreApi.credentials.ts | medium | Hardcoded apikey assignment |
| n8n-io/n8n | packages/nodes-base/credentials/MauticApi.credentials.ts | medium | Hardcoded password assignment |
| n8n-io/n8n | packages/nodes-base/credentials/NasaApi.credentials.ts | medium | Hardcoded api_key assignment |
| n8n-io/n8n | packages/nodes-base/credentials/PipedriveApi.credentials.ts | medium | Hardcoded token assignment |
| n8n-io/n8n | packages/nodes-base/credentials/PostHogApi.credentials.ts | medium | Hardcoded api_key assignment |
| n8n-io/n8n | packages/nodes-base/credentials/QualysApi.credentials.ts | medium | Hardcoded password assignment |
| n8n-io/n8n | packages/nodes-base/credentials/ServiceNowBasicApi.credentials.ts | medium | Hardcoded password assignment |
| n8n-io/n8n | packages/nodes-base/credentials/SolarWindsIpamApi.credentials.ts | medium | Hardcoded password assignment |
| n8n-io/n8n | packages/nodes-base/credentials/SupabaseApi.credentials.ts | medium | Hardcoded apikey assignment |
| n8n-io/n8n | packages/nodes-base/credentials/TogglApi.credentials.ts | medium | Hardcoded password assignment |
| n8n-io/n8n | packages/nodes-base/credentials/TrellixEpoApi.credentials.ts | medium | Hardcoded password assignment |
| n8n-io/n8n | packages/nodes-base/credentials/UptimeRobotApi.credentials.ts | medium | Hardcoded api_key assignment |
| n8n-io/n8n | packages/nodes-base/credentials/VerticaApi.credentials.ts | medium | Hardcoded password assignment |
| n8n-io/n8n | packages/nodes-base/credentials/WhatsAppTriggerApi.credentials.ts | medium | Hardcoded secret assignment |
| n8n-io/n8n | packages/nodes-base/credentials/WordpressApi.credentials.ts | medium | Hardcoded password assignment |
| n8n-io/n8n | packages/quality/environments/containers/services/engine-postgres.ts | medium | Hardcoded password assignment |
| n8n-io/n8n | packages/quality/environments/containers/services/sandbox.ts | medium | Hardcoded api_key assignment |
| n8n-io/n8n | packages/quality/testing/playwright/config/constants.ts | medium | Hardcoded password assignment |
| n8n-io/n8n | packages/quality/testing/playwright/config/test-users.ts | medium | Hardcoded secret assignment |
| n8n-io/n8n | packages/quality/testing/playwright/services/dynamic-credential-api-helper.ts | medium | Hardcoded token assignment |
| n8n-io/n8n | scripts/codespace-preview/preview-labels.mjs | medium | Hardcoded secret assignment |
| rails/rails | actionpack/lib/action_controller/metal/request_forgery_protection.rb | medium | Hardcoded token assignment |
| rails/rails | actionview/lib/action_view/helpers/form_tag_helper.rb | medium | Hardcoded token assignment |
| rails/rails | guides/source/security.md | medium | Hardcoded password assignment |
| strapi/strapi | packages/core/admin/admin/src/components/GuidedTour/utils/constants.ts | medium | Hardcoded token assignment |
| tauri-apps/tauri | crates/tauri-build/src/lib.rs | medium | Hardcoded token assignment |
| tauri-apps/tauri | crates/tauri-build/src/lib.rs | medium | Hardcoded token assignment |
| tauri-apps/tauri | crates/tauri-build/src/windows-app-manifest.xml | medium | Hardcoded token assignment |
| tauri-apps/tauri | packages/api/src/core.ts | medium | Hardcoded password assignment |
| traefik/traefik | integration/resources/tls/consul.key | critical | Private key block detected |
| traefik/traefik | integration/resources/tls/local.key | critical | Private key block detected |
| vercel/next.js | bench/basic-app/app/dashboard/page.js | medium | Hardcoded token assignment |
| vuejs/core | packages-private/template-explorer/src/theme.ts | medium | Hardcoded token assignment |
| vuejs/core | packages-private/template-explorer/src/theme.ts | medium | Hardcoded token assignment |
| vuejs/core | packages-private/template-explorer/src/theme.ts | medium | Hardcoded token assignment |
| vuejs/core | packages-private/template-explorer/src/theme.ts | medium | Hardcoded token assignment |
| vuejs/core | packages-private/template-explorer/src/theme.ts | medium | Hardcoded token assignment |
| vuejs/core | packages-private/template-explorer/src/theme.ts | medium | Hardcoded token assignment |
| vuejs/core | packages-private/template-explorer/src/theme.ts | medium | Hardcoded token assignment |
| vuejs/core | packages-private/template-explorer/src/theme.ts | medium | Hardcoded token assignment |
| vuejs/core | packages-private/template-explorer/src/theme.ts | medium | Hardcoded token assignment |
| vuejs/core | packages-private/template-explorer/src/theme.ts | medium | Hardcoded token assignment |
| vuejs/core | packages-private/template-explorer/src/theme.ts | medium | Hardcoded token assignment |
| vuejs/core | packages-private/template-explorer/src/theme.ts | medium | Hardcoded token assignment |
| vuejs/core | packages-private/template-explorer/src/theme.ts | medium | Hardcoded token assignment |
| vuejs/core | packages-private/template-explorer/src/theme.ts | medium | Hardcoded token assignment |
| vuejs/core | packages-private/template-explorer/src/theme.ts | medium | Hardcoded token assignment |
| vuejs/core | packages-private/template-explorer/src/theme.ts | medium | Hardcoded token assignment |
| vuejs/core | packages-private/template-explorer/src/theme.ts | medium | Hardcoded token assignment |
| vuejs/core | packages-private/template-explorer/src/theme.ts | medium | Hardcoded token assignment |
| vuejs/core | packages-private/template-explorer/src/theme.ts | medium | Hardcoded token assignment |
| vuejs/core | packages-private/template-explorer/src/theme.ts | medium | Hardcoded token assignment |
| vuejs/core | packages-private/template-explorer/src/theme.ts | medium | Hardcoded token assignment |
| vuejs/core | packages-private/template-explorer/src/theme.ts | medium | Hardcoded token assignment |
| vuejs/core | packages-private/template-explorer/src/theme.ts | medium | Hardcoded token assignment |
| vuejs/core | packages-private/template-explorer/src/theme.ts | medium | Hardcoded token assignment |
| vuejs/core | packages-private/template-explorer/src/theme.ts | medium | Hardcoded token assignment |
| vuejs/core | packages-private/template-explorer/src/theme.ts | medium | Hardcoded token assignment |
| vuejs/core | packages-private/template-explorer/src/theme.ts | medium | Hardcoded token assignment |
| vuejs/core | packages-private/template-explorer/src/theme.ts | medium | Hardcoded token assignment |
| vuejs/core | packages-private/template-explorer/src/theme.ts | medium | Hardcoded token assignment |
| vuejs/core | packages-private/template-explorer/src/theme.ts | medium | Hardcoded token assignment |
| vuejs/core | packages-private/template-explorer/src/theme.ts | medium | Hardcoded token assignment |
| vuejs/core | packages-private/template-explorer/src/theme.ts | medium | Hardcoded token assignment |
| vuejs/core | packages-private/template-explorer/src/theme.ts | medium | Hardcoded token assignment |
| vuejs/core | packages-private/template-explorer/src/theme.ts | medium | Hardcoded token assignment |
| vuejs/core | packages-private/template-explorer/src/theme.ts | medium | Hardcoded token assignment |
| vuejs/core | packages-private/template-explorer/src/theme.ts | medium | Hardcoded token assignment |
| vuejs/core | packages-private/template-explorer/src/theme.ts | medium | Hardcoded token assignment |
| vuejs/core | packages-private/template-explorer/src/theme.ts | medium | Hardcoded token assignment |
