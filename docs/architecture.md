---
title: Architecture
purpose: Module map, data flow, boundary failure policy, contract pins
created: 2026-06-01
updated: 2026-06-01
category: technical
---

## Core idea

Consume the `gha-sec-feed` C1 JSONL feed, score each row 0–10 on a locked
priority formula, enrich with MITRE ATT&CK + D3FEND, emit the C2 JSONL
output and a Markdown report. Ships as both a reusable GHA workflow
(`workflow_call`) and a standalone CLI (`python -m gha_sec_feed_eval`).
Both surfaces share the same package code; the workflow is a thin
wrapper.

## Module map (lands in 2b)

```text
src/gha_sec_feed_eval/
  __init__.py            __version__ via importlib.metadata
  __main__.py            python -m gha_sec_feed_eval → cli.main
  config.py              AppSettings(BaseSettings) — GSFE_ env prefix
  models.py              pydantic strict: FeedRow (C1), PriorityRow (C2), Meta
  loader.py              fetch + validate C1 (schema_version pinned to 1.0.0)
  filter.py              apply categories/default.yaml
  scoring.py             priority_score() + priority_category() per locked spec
  enrich/
    attack.py            CVE → ATT&CK technique IDs (vendored STIX)
    d3fend.py            ATT&CK → D3FEND countermeasure IDs (vendored)
    epss.py              EPSS lookup (fallback when C1.epss is null)
  writer.py              C2 priority.jsonl + priority-meta.json + REPORT.md
  http_client.py         5-host allowlist; only egress chokepoint
  cli.py                 argparse → settings → loader → filter → score → enrich → writer
```

## Data flow

```text
C1 feed.jsonl
   │
   ▼ loader.parse() — pydantic strict; accept schema_version in {"1.0.0", "1.1.0"} (see SUPPORTED_C1_SCHEMA_VERSIONS)
   │
   ▼ filter.apply() — categories/default.yaml; matched_categories per row
   │
   ▼ scoring.priority_score() — KEV +2 / active-exploit +2 / EPSS×2 / recency / CVSS≥9 +2
   │
   ▼ enrich.attack + enrich.d3fend + enrich.epss
   │
   ▼ writer:
       • data/priority.jsonl           (C2 rows, one per line)
       • data/priority-meta.json       (counts, last_run, schema_version)
       • data/REPORT.md                (Act-Now / This-Week / Monitor sections)
```

## Boundary failure policy

- **Network errors at boundary (`http_client`)** — fail loud. Log + raise.
  CI surfaces via non-zero exit. No silent fallback to empty results.
- **Schema mismatch on C1 input** — `loader` raises `SchemaVersionError`
  with the observed vs expected version. CI fails fast.
- **Missing vendored STIX/D3FEND data** — `enrich.attack` / `enrich.d3fend`
  fail loud at import time with refresh-procedure pointer to
  [`docs/refresh-vendored-data.md`](refresh-vendored-data.md).
- **Empty C1 feed** — emit empty C2 + meta with `total: 0`. Not an error;
  the producer may not have shipped data yet.
- **Offline mode** (`GSFE_OFFLINE=1`) — `http_client.get()` raises before
  any network call. Used by tests to guarantee no live HTTP.

## Contracts

See [`docs/contracts.md`](contracts.md). C1 input is pinned at
`schema_version: "1.0.0"`; C2 output emitted at `1.0.0`. Any producer
schema bump (e.g., to 2.0.0) is a stop-and-ask trigger.

## Reusable workflow shape

See [`docs/consumer-guide.md`](consumer-guide.md) for the
`workflow_call` integration pattern. Load-bearing details:

- `eval_ref: required: true` self-checkout — caller pins the same SHA they
  invoke the reusable at (do NOT derive from `github.workflow_ref`).
- Output values written to `${output_dir}/.workflow_outputs` then
  `cat >> $GITHUB_OUTPUT` in a final step (works across reusable boundaries).
- `permissions: {}` at workflow scope; `contents: read` on the eval job.

## Vendored data

ATT&CK + D3FEND are committed to `vendor/` as static JSON snapshots, not
runtime-fetched. Reasons: reproducibility, no runtime network dep, one
fewer allowlist host. Refresh procedure in
[`docs/refresh-vendored-data.md`](refresh-vendored-data.md).
