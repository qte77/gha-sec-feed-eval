---
title: Contracts (C1 input + C2 output)
purpose: Authoritative schemas for the C1 feed we consume and the C2 output we emit. Pinned at schema_version 1.0.0 for both.
created: 2026-06-01
updated: 2026-06-01
category: technical
---

## C1 — Input (consumed from `qte77/gha-sec-feed`)

**Source:** `https://raw.githubusercontent.com/qte77/gha-sec-feed/main/data/feed.jsonl`
**Format:** JSONL (one JSON object per line).
**Pinned:** `schema_version: "1.0.0"`. Producer bump to 2.0.0 is a
stop-and-ask trigger — adapt explicitly, not silently.

```json
{
  "id": "CVE-2026-12345",
  "source": "nvd",
  "published": "2026-05-31T00:00:00Z",
  "severity": "critical",
  "cvss": 9.8,
  "epss": 0.87,
  "kev": true,
  "refs": ["https://..."],
  "schema_version": "1.0.0"
}
```

### Fields

| Field | Type | Notes |
|---|---|---|
| `id` | string | CVE / IOC identifier |
| `source` | enum | `nvd`, `cisa-kev`, `epss`, `ghsa`, `osv`, `redhat`, `ubuntu`, `urlhaus`, `threatfox`, `malwarebazaar` |
| `published` | string | ISO-8601 with `Z` suffix |
| `severity` | enum | `critical`, `high`, `medium`, `low`, `unknown` (lowercase) |
| `cvss` | float \| null | CVSS v3 base score. Missing → treat as 0 for scoring. |
| `epss` | float \| null | EPSS probability [0, 1]. Missing → fall back to live fetch (off by default in tests). |
| `kev` | bool | Listed in CISA Known Exploited Vulnerabilities |
| `refs` | string[] | Reference URLs (advisory, PoC, vendor) |
| `schema_version` | string | Pinned to `"1.0.0"` |

## C2 — Output (emitted to `data/priority.jsonl`)

**Format:** JSONL. One C2 object per row that passed the category filter.
**Locked:** `schema_version: "1.0.0"`.

```json
{
  "id": "CVE-2026-12345",
  "source": "nvd",
  "published": "2026-05-31T00:00:00Z",
  "severity": "critical",
  "cvss": 9.8,
  "epss": 0.87,
  "kev": true,
  "refs": ["..."],
  "priority_score": 9.0,
  "priority_category": "act_now",
  "attack_techniques": ["T1190", "T1078.004"],
  "d3fend_countermeasures": ["D3-NTA", "D3-MFA"],
  "matched_categories": ["python", "github-actions"],
  "schema_version": "1.0.0"
}
```

### Fields added beyond C1

| Field | Type | Notes |
|---|---|---|
| `priority_score` | float | Range 0.0–10.0, rounded to 2 decimals |
| `priority_category` | enum | `act_now` (≥ 8.0), `this_week` (5.0–7.9), `monitor` (< 5.0) |
| `attack_techniques` | string[] | MITRE ATT&CK IDs (e.g., `T1190`). Empty if no mapping. |
| `d3fend_countermeasures` | string[] | MITRE D3FEND IDs. Empty if no mapping. |
| `matched_categories` | string[] | Ecosystem slugs from `categories/default.yaml` that matched |

## Sibling — `data/priority-meta.json`

Single JSON object (not JSONL) with run metadata.

```json
{
  "schema_version": "1.0.0",
  "input_schema_version": "1.0.0",
  "input_source": "https://raw.githubusercontent.com/qte77/gha-sec-feed/main/data/feed.jsonl",
  "last_run": "2026-05-31T12:00:00Z",
  "total": 234,
  "by_category": {"act_now": 5, "this_week": 28, "monitor": 201},
  "by_source": {"nvd": 100, "cisa-kev": 5, "ghsa": 50, "osv": 79},
  "categories_used": "categories/default.yaml"
}
```

## Sibling — `data/REPORT.md`

Human-readable Markdown rendered by `writer.py`. Sections: Act-Now,
This-Week, Monitor (each capped at 50 rows; link to raw `priority.jsonl`),
Top ATT&CK techniques, By source, Methodology. Frontmatter satisfies
markdownlint MD041.
