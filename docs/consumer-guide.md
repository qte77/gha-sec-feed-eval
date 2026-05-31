---
title: Consumer integration guide
purpose: Stub — full integration recipe lands in 2d.
created: 2026-06-01
updated: 2026-06-01
category: technical
---

> **Status:** Stub. Full content lands in phase 2d alongside the v0.1.0
> release. Once `v0.1.0` is tagged, this document will cover:

- How to wire `qte77/gha-sec-feed-eval/.github/workflows/eval.yaml@v0.1.0`
  into a consumer scheduled workflow.
- The `eval_ref:` pin pattern (load-bearing self-checkout — pin matches
  the `uses:` SHA).
- How to consume the `priority-output` artifact in a downstream triage step
  (e.g., `qte77/repo-baseline` opens GitHub Issues per Act-Now row).
- Categories override via `categories_file:` input — see
  [`docs/categories.md`](categories.md).
- Sample consumer workflow YAML, end-to-end.
- Schema compatibility guarantees: C2 stays at `1.0.0`; breaking changes
  require a major bump.
