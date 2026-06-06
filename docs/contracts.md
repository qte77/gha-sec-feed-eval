---
title: Contracts (C1 input + C2 output)
purpose: Authoritative schemas for the C1 feed we consume and the C2 output we emit. C1 accepts schema_version 1.0.0 or 1.1.0; C2 emits 1.0.0.
created: 2026-06-01
updated: 2026-06-05
category: technical
---

## C1 — Input (consumed from `qte77/gha-sec-feed`)

**Source:** [raw.githubusercontent.com/qte77/gha-sec-feed/main/data/feed.jsonl](https://raw.githubusercontent.com/qte77/gha-sec-feed/main/data/feed.jsonl)
**Format:** JSONL (one JSON object per line).
**Accepted versions:** `schema_version` in `{"1.0.0", "1.1.0"}` (see `SUPPORTED_C1_SCHEMA_VERSIONS` in [`src/gha_sec_feed_eval/models.py`](../src/gha_sec_feed_eval/models.py)). The 1.1.0 bump is **additive**: `cwes` + `description` are new with safe defaults so 1.0.0 callers remain valid (per producer's [`docs/SOURCES.md` §"Schema + filter capability"](https://github.com/qte77/gha-sec-feed/blob/main/docs/SOURCES.md)). Any version outside this set is a stop-and-ask trigger — the loader rejects loudly.

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
  "cwes": ["CWE-89"],
  "description": "SQL injection in /api/v1/users",
  "schema_version": "1.1.0"
}
```

### Fields

| Field | Type | Since | Notes |
|---|---|---|---|
| `id` | string | 1.0.0 | CVE / IOC identifier |
| `source` | enum | 1.0.0 | `nvd`, `cisa-kev`, `epss`, `ghsa`, `osv`, `redhat`, `ubuntu`, `urlhaus`, `threatfox`, `malwarebazaar` |
| `published` | string | 1.0.0 | ISO-8601 with `Z` suffix |
| `severity` | enum | 1.0.0 | `critical`, `high`, `medium`, `low`, `unknown` (lowercase) |
| `cvss` | float \| null | 1.0.0 | CVSS v3 base score. Missing → treat as 0 for scoring. |
| `epss` | float \| null | 1.0.0 | EPSS probability [0, 1]. Missing → fall back to live fetch (off by default in tests). |
| `kev` | bool | 1.0.0 | Listed in CISA Known Exploited Vulnerabilities |
| `refs` | string[] | 1.0.0 | Reference URLs (advisory, PoC, vendor) |
| `cwes` | string[] | **1.1.0** | CWE-prefixed weakness identifiers. Default `[]`. |
| `description` | string | **1.1.0** | English free text. Default `""`. |
| `schema_version` | string | 1.0.0 | One of `SUPPORTED_C1_SCHEMA_VERSIONS`. |

## C2 — Output (emitted to `data/priority.jsonl`)

**Format:** JSONL. One C2 object per row that passed the category filter.
**Schema:** C2 inherits every C1 field (so `schema_version` is **forwarded** from the input row) and adds the enrichment fields below. The C2 schema itself — i.e. the set of enrichment fields — is locked at `1.0.0`; the eval's compat range is published per-run in `priority-meta.json.accepted_c1_schema_versions`.

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
  "cwes": ["CWE-89"],
  "description": "SQL injection in /api/v1/users",
  "priority_score": 9.0,
  "priority_category": "act_now",
  "attack_techniques": ["T1190", "T1078.004"],
  "d3fend_countermeasures": ["D3-NTA", "D3-MFA"],
  "matched_categories": ["python", "github-actions"],
  "schema_version": "1.1.0"
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

Single JSON object (not JSONL) with run metadata. `accepted_c1_schema_versions` is the **load-bearing self-declaration** of the eval's C1 compat range — consumers read this field to learn which feeds are safe to plug in.

```json
{
  "schema_version": "1.0.0",
  "input_schema_version": "1.0.0",
  "accepted_c1_schema_versions": ["1.0.0", "1.1.0"],
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
