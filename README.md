# gha-sec-feed-eval

> Ranks a security-advisory feed against your stack and tells you what to fix
> now — as a reusable GitHub Actions workflow or a standalone CLI.

[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)
[![Version](https://img.shields.io/badge/version-0.0.0-blue)](CHANGELOG.md)
[![CodeQL](https://github.com/qte77/gha-sec-feed-eval/actions/workflows/codeql.yaml/badge.svg)](https://github.com/qte77/gha-sec-feed-eval/actions/workflows/codeql.yaml)
[![validate](https://github.com/qte77/gha-sec-feed-eval/actions/workflows/validate.yaml/badge.svg)](https://github.com/qte77/gha-sec-feed-eval/actions/workflows/validate.yaml)

## What

- Reads the [`qte77/gha-sec-feed`](https://github.com/qte77/gha-sec-feed) C1
  JSONL feed (NVD, GHSA, OSV, CISA KEV)
- Keeps only rows that match your ecosystems (Python, TypeScript, Rust, Go,
  Docker, GitHub Actions by default; overridable)
- Scores each row 0–10 from KEV listing, exploit evidence, EPSS, recency and
  CVSS
- Adds MITRE ATT&CK techniques and D3FEND countermeasures from vendored data
- Buckets rows into Act-Now / This-Week / Monitor
- Writes `priority.jsonl` (C2), `priority-meta.json` and a `REPORT.md`

## How

```yaml
jobs:
  eval:
    uses: qte77/gha-sec-feed-eval/.github/workflows/eval.yaml@v0.1.0
    with:
      eval_ref: v0.1.0   # must match the @ref above
```

Or locally: `make setup_dev && make smoke` (offline fixture run). Full recipe,
inputs and outputs: [`docs/consumer-guide.md`](docs/consumer-guide.md);
commands: `make help`.

## Why

Raw advisory feeds are high-volume and unranked, and scanners flag everything
in a dependency tree. This evaluator narrows a feed to your stack, ranks it
with a published formula adapted from
[`jcastanedacano/cve-sentry`](https://github.com/jcastanedacano/cve-sentry),
and adds ATT&CK + D3FEND context so each row says what to defend, not only
what is broken.

## Refs

- [Architecture](docs/architecture.md)
- [Contracts (C1 + C2)](docs/contracts.md)
- [Scoring](docs/scoring.md)
- [Categories](docs/categories.md)
- [Consumer guide](docs/consumer-guide.md)
- [Refresh vendored data](docs/refresh-vendored-data.md)
- [Glossary](docs/GLOSSARY.md)
- [Changelog](CHANGELOG.md)

## License

[Apache-2.0](LICENSE). See [`NOTICE`](NOTICE) for vendored data attribution
(MITRE ATT&CK + D3FEND).
