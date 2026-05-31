---
title: Priority scoring formula
purpose: Locked 0–10 priority score and act_now/this_week/monitor bucketing, with cve-sentry attribution.
created: 2026-06-01
updated: 2026-06-01
category: technical
---

## Locked formula

Locked at v1.0.0. Modifying this is a stop-and-ask trigger; bump C2
schema if the change is non-trivial.

```python
def priority_score(row: FeedRow) -> float:
    score = 0.0
    if row.kev:
        score += 2.0
    if has_active_exploit(row):
        score += 2.0
    if row.epss is not None:
        score += row.epss * 2.0
    days_old = (now() - row.published).days
    score += max(0.0, 2.0 - (days_old / 7.0) * 2.0)
    if row.cvss is not None and row.cvss >= 9.0:
        score += 2.0
    return round(min(score, 10.0), 2)


def priority_category(score: float) -> str:
    if score >= 8.0:
        return "act_now"
    if score >= 5.0:
        return "this_week"
    return "monitor"
```

## Factor table

| Factor | Points | Rationale |
|---|---|---|
| CISA KEV | +2.0 | Listed in Known Exploited Vulnerabilities |
| Active exploit | +2.0 | Public PoC / Metasploit / Exploit-DB indicators in `refs` |
| EPSS | up to +2.0 | `epss_score × 2.0` — probabilistic exploit forecast |
| Recency | up to +2.0 | `max(0, 2.0 − (days_old / 7) × 2.0)` |
| CVSS ≥ 9.0 | +2.0 | Critical-severity bump |

Categories from total:

- **Act-Now** (≥ 8.0)
- **This-Week** (5.0 – 7.9)
- **Monitor** (< 5.0)

## Active-exploit heuristic

`has_active_exploit(row)` returns True if any of:

- `row.source == "cisa-kev"` (implies operational exploitation)
- Any `ref` URL host matches `exploit-db.com`, `packetstormsecurity.com`,
  or `metasploit-framework`
- Any `ref` URL path contains `/poc/` or ends in `/exploit`

The heuristic is intentionally conservative — false negatives bias the
score downward into `this_week`, which is the correct safe default.

## Mandatory sanity test

`CVSS 10.0 + KEV true + EPSS null + recency = 0 days` must score
`≥ 8.0` (Act-Now). If the formula ever fails this floor, stop and ask
the user. Encoded as a unit test in 2b.

## Citation

The formula shape is adapted from
[`jcastanedacano/cve-sentry`](https://github.com/jcastanedacano/cve-sentry)'s
Sentry Priority Score — a security-practitioner-developed formula
validated empirically against multiple sources and triage decisions.
This project borrows the formula shape without forking the code:
cve-sentry is AGPL-3.0 and Azure/M365-focused; our scope and licensing
diverge. See
[the cve-sentry README](https://github.com/jcastanedacano/cve-sentry#readme)
for the original treatment.
