---
title: Default categories and override guide
purpose: Explains the default ecosystem keywords shipped in categories/default.yaml and how consumers override them.
created: 2026-06-01
updated: 2026-06-01
category: technical
---

## Why defaults

Defaults are deliberately broad — Python, TypeScript, Rust, Go, Docker,
GitHub Actions — so that any user evaluating this tool out-of-the-box sees
useful output on first run. Consumer-specific narrowing happens via
override.

The shipped defaults live in
[`categories/default.yaml`](../categories/default.yaml).

## File shape

```yaml
stack_keywords:
  python:
    - pip
    - poetry
    # ...
  typescript:
    - "@typescript-eslint/*"   # wildcard supported
    # ...
priority_thresholds:
  act_now: 8.0
  this_week: 5.0
match_strategy: "keyword-in-refs-or-affected-products"
```

- `stack_keywords` — ecosystem slug → keyword list. Keywords match
  case-insensitively against `refs` URLs and affected-product fields.
  Wildcard `*` supported at end of token.
- `priority_thresholds` — bucket cutoffs. Defaults match brief §"Default
  categories" (Act-Now ≥ 8.0, This-Week ≥ 5.0).
- `match_strategy` — currently only `keyword-in-refs-or-affected-products`
  is supported. Reserved for future extensibility.

## How filtering works

For each C1 row:

1. Lowercase all `refs[*]` URLs and affected-product fields.
2. For each `(slug, keywords)` pair in `stack_keywords`, if ANY keyword
   matches, add `slug` to the row's `matched_categories`.
3. If `matched_categories` is empty, the row is dropped from C2 output.
4. If non-empty, the row proceeds to scoring + enrichment.

## How to override (consumers)

Consumers point `--categories-file` (CLI) or `categories_file` (reusable
workflow input) at their own YAML file matching the same shape. Common
patterns:

- **Narrow** to one ecosystem (e.g., Python-only at a Python shop).
- **Replace** keyword lists with internal package names.
- **Tighten thresholds** (e.g., `act_now: 7.0`) to widen the Act-Now
  bucket for a smaller security team.
- **Loosen thresholds** to reduce alert volume.

Example consumer override:

```yaml
stack_keywords:
  internal-services:
    - acme-billing
    - acme-payments
  python:
    - fastapi
    - sqlalchemy
priority_thresholds:
  act_now: 7.5
  this_week: 5.0
match_strategy: "keyword-in-refs-or-affected-products"
```

Run with override:

```bash
python -m gha_sec_feed_eval \
  --feed-url https://raw.githubusercontent.com/qte77/gha-sec-feed/main/data/feed.jsonl \
  --categories-file /path/to/consumer-categories.yaml \
  --output-dir ./data
```

Or in a reusable workflow caller:

```yaml
uses: qte77/gha-sec-feed-eval/.github/workflows/eval.yaml@v0.1.0
with:
  categories_file: categories/consumer.yaml
  eval_ref: v0.1.0
```

See [`docs/consumer-guide.md`](consumer-guide.md) for the full
integration recipe.
