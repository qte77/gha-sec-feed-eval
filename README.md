# gha-sec-feed-eval

![Version](https://img.shields.io/badge/version-0.0.0-blue)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)
[![CodeQL](https://github.com/qte77/gha-sec-feed-eval/actions/workflows/codeql.yaml/badge.svg)](https://github.com/qte77/gha-sec-feed-eval/actions/workflows/codeql.yaml)
[![validate](https://github.com/qte77/gha-sec-feed-eval/actions/workflows/validate.yaml/badge.svg)](https://github.com/qte77/gha-sec-feed-eval/actions/workflows/validate.yaml)

Evaluator that consumes the [`qte77/gha-sec-feed`](https://github.com/qte77/gha-sec-feed)
C1 JSONL feed, scores rows on a locked 0–10 priority formula
(adapted from
[`jcastanedacano/cve-sentry`](https://github.com/jcastanedacano/cve-sentry)),
enriches with MITRE ATT&CK + D3FEND, and emits a C2 JSONL output plus a
Markdown report. Ships as a reusable GitHub Actions workflow and a
standalone CLI.

## What it does

```text
C1 feed.jsonl (gha-sec-feed)
   │
   ▼ filter (categories) → score (0–10) → enrich (ATT&CK + D3FEND)
   │
   ▼
data/priority.jsonl       — C2 rows (one JSON object per line)
data/priority-meta.json   — counts, last_run, schema_version
data/REPORT.md            — Act-Now / This-Week / Monitor view
```

## Quickstart

```bash
make setup_dev   # uv sync (default groups: dev + test)
make help        # canonical command list
make validate    # lint + types + complexity + lint_md + lint_links + test_cov
make smoke       # CLI run against tests/fixtures/feed-min.jsonl (after 2b)
```

## Reusable workflow

Pin to a released tag — `v0.1.0` lands at phase 2d.

```yaml
jobs:
  eval:
    uses: qte77/gha-sec-feed-eval/.github/workflows/eval.yaml@v0.1.0
    with:
      feed_url: https://raw.githubusercontent.com/qte77/gha-sec-feed/main/data/feed.jsonl
      categories_file: ""                       # optional override; empty = defaults
      output_dir: ./data
      eval_ref: v0.1.0                          # must match @vX.Y.Z above
```

See [`docs/consumer-guide.md`](docs/consumer-guide.md) for the full
integration recipe (lands in 2d).

## Standalone CLI

```bash
python -m gha_sec_feed_eval \
  --feed-url https://raw.githubusercontent.com/qte77/gha-sec-feed/main/data/feed.jsonl \
  --output-dir ./data
```

CLI lands in phase 2b — see [`docs/architecture.md`](docs/architecture.md).

## Contracts

| Contract | Version | Spec |
|---|---|---|
| **C1** (Contract 1) - input from `gha-sec-feed` | `1.0.0` (pinned) | [`docs/contracts.md`](docs/contracts.md) |
| **C2** (Contract 2) - output of this evaluator | `1.0.0` | [`docs/contracts.md`](docs/contracts.md) |

Abbreviations used across the project (C1 / C2 / CVE / CVSS / KEV / EPSS /
ATT&CK / D3FEND / SBOM / SPDX / SARIF / GSFE_ / ...) are defined in
[`docs/GLOSSARY.md`](docs/GLOSSARY.md).

## Docs

- [Architecture](docs/architecture.md) — module map, data flow, boundary
  failure policy
- [Contracts](docs/contracts.md) — C1 + C2 schemas
- [Scoring](docs/scoring.md) — formula + cve-sentry citation
- [Categories](docs/categories.md) — default ecosystems + consumer override
- [Consumer guide](docs/consumer-guide.md) — wiring the reusable workflow
  (lands 2d)
- [Refresh vendored data](docs/refresh-vendored-data.md) — ATT&CK + D3FEND
  refresh runbook (lands 2b)
- [Glossary](docs/GLOSSARY.md) — abbreviations used across the project
- [Changelog](CHANGELOG.md) — semver, scriv-managed fragments

## License

[Apache-2.0](LICENSE). See [`NOTICE`](NOTICE) for vendored data attribution
(MITRE ATT&CK + D3FEND).
