---
title: Consumer integration guide
purpose: How a consumer wires the reusable eval.yaml workflow into its own scheduled workflow and consumes the C2 output.
created: 2026-06-01
updated: 2026-10-24
category: technical
---

> **Status:** `v0.1.0` is not tagged yet (tracked in issue #5). Until it
> is, pin `uses:` and `eval_ref:` to a commit SHA on `main` instead of
> `v0.1.0`.

## Minimal caller

```yaml
name: security-triage

on:
  schedule:
    - cron: "0 6 * * *"
  workflow_dispatch:

permissions: {}

jobs:
  eval:
    uses: qte77/gha-sec-feed-eval/.github/workflows/eval.yaml@v0.1.0
    permissions:
      contents: read
    with:
      eval_ref: v0.1.0   # REQUIRED — must equal the @ref in `uses:` above
```

All other inputs are optional:

| Input | Default | Meaning |
|---|---|---|
| `feed_url` | `https://raw.githubusercontent.com/qte77/gha-sec-feed/main/data/feed.jsonl` | C1 JSONL feed to evaluate |
| `categories_file` | `""` (shipped defaults) | Categories YAML path — see [Categories override](#categories-override) |
| `output_dir` | `./data` | Where the C2 files are written before upload |
| `eval_ref` | — (required) | Ref of this repo to check out and run |

## Why `eval_ref` must match `uses:`

The reusable workflow checks out `qte77/gha-sec-feed-eval` at `eval_ref`
and runs the evaluator from that checkout. It can't infer its own ref:
inside a reusable workflow, `github.workflow_ref` resolves to the
*caller's* ref, so deriving it would run a stale or wrong evaluator.
Keep both refs identical — when Dependabot or a human bumps one, bump
the other in the same commit.

## Outputs

| Output | Meaning |
|---|---|
| `relevant_count` | Number of C2 rows (lines in `priority.jsonl`) |
| `priority_artifact` | Artifact ID of the uploaded `priority-output` artifact |

The `priority-output` artifact contains `priority.jsonl` (C2 rows),
`priority-meta.json` (run metadata) and `REPORT.md` (Act-Now /
This-Week / Monitor view). Schemas: [`docs/contracts.md`](contracts.md).

## Consuming the artifact downstream

```yaml
  triage:
    needs: eval
    if: needs.eval.outputs.relevant_count != '0'
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - uses: actions/download-artifact@v4
        with:
          name: priority-output
          path: ./priority
      - name: Show Act-Now rows
        run: jq -c 'select(.priority_category == "act_now")' ./priority/priority.jsonl
```

Pin third-party actions to a full commit SHA in real workflows; the tag
above keeps the example short.

## Categories override

`categories_file` is a path resolved inside the job workspace, which
holds the **evaluator's** checkout at `eval_ref` — not the caller's
repo. A file that lives only in the consumer repo is therefore not
reachable from the reusable workflow today. Options:

- Use the shipped defaults (leave `categories_file` empty).
- Run the standalone CLI in your own job, where your checkout is
  present, and pass `--categories-file path/to/yours.yaml`.

File shape and override patterns: [`docs/categories.md`](categories.md).

## Compatibility

- Pin to a released tag (or SHA); `main` may change without notice.
- The C2 schema version is declared per run in
  `priority-meta.json.schema_version`; additive changes bump the minor,
  breaking changes the major.
- Accepted C1 schema versions are listed in
  [`docs/contracts.md`](contracts.md).
