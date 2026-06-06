---
title: Refresh vendored MITRE ATT&CK + D3FEND data
purpose: Operational runbook for refreshing the curated subsets at vendor/attack-stix.json and vendor/d3fend-mappings.json.
created: 2026-06-01
updated: 2026-06-05
category: technical
---

## What's vendored

Two hand-curated JSON subsets, **not** the full upstream bundles:

| File | Shape | Current size |
|---|---|---|
| [`vendor/attack-stix.json`](../vendor/attack-stix.json) | `{"version": str, "generated_at": ISO-8601, "mappings": dict[CVE-ID, list[technique-ID]]}` | 10 CVEs |
| [`vendor/d3fend-mappings.json`](../vendor/d3fend-mappings.json) | `{"version": str, "generated_at": ISO-8601, "mappings": dict[technique-ID, list[countermeasure-ID]]}` | 9 techniques |

The full [MITRE/cti STIX bundle](https://github.com/mitre/cti) is ~30 MB and the [D3FEND ontology](https://d3fend.mitre.org/) ships as OWL/Turtle — neither shape matches what [`enrich/attack.py`](../src/gha_sec_feed_eval/enrich/attack.py) and [`enrich/d3fend.py`](../src/gha_sec_feed_eval/enrich/d3fend.py) consume. The vendored files are intentionally minimal: only CVEs the evaluator scores against, and only techniques those CVEs reference.

`AttackMapping` and `D3fendMapping` (pydantic, `extra="forbid"`) reject unknown top-level fields. See [`docs/GLOSSARY.md`](GLOSSARY.md) for [ATT&CK](https://attack.mitre.org/) / [D3FEND](https://d3fend.mitre.org/) / [STIX](https://oasis-open.github.io/cti-documentation/stix/intro) term expansions.

## Sources

| Source | URL | Use |
|---|---|---|
| MITRE ATT&CK | [`mitre/cti`](https://github.com/mitre/cti), file `enterprise-attack/enterprise-attack.json` | Canonical technique IDs + names |
| CVE → ATT&CK | [`center-for-threat-informed-defense/attack_to_cve`](https://github.com/center-for-threat-informed-defense/attack_to_cve) | Authoritative CVE-to-technique mappings |
| MITRE D3FEND | [`d3fend.mitre.org`](https://d3fend.mitre.org/) (ontology export under `/resources/`) | ATT&CK-to-D3FEND counter-mapping table |
| NVD → CWE → ATT&CK | Per-CVE [NVD detail page](https://nvd.nist.gov/vuln/search) → CWE → manual ATT&CK lookup via [MITRE's CWE-to-ATT&CK guide](https://attack.mitre.org/resources/working-with-attack/) | Fallback when `attack_to_cve` doesn't cover a CVE |

## Extraction recipe

### Add a CVE → ATT&CK technique mapping

1. Look up the CVE in [`attack_to_cve`](https://github.com/center-for-threat-informed-defense/attack_to_cve). If absent, derive from the CVE's CWE via the [MITRE CWE-to-ATT&CK guide](https://attack.mitre.org/resources/working-with-attack/).
2. Validate each technique ID against the canonical bundle:

   ```bash
   curl -fsSL https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json \
     | jq -r '.objects[]
              | select(.type=="attack-pattern")
              | (.external_references[]
                 | select(.source_name=="mitre-attack")
                 | .external_id) + "\t" + .name' \
     | grep -E '^T1190\b'   # replace with the technique you're adding
   ```

3. Append to `vendor/attack-stix.json`:

   ```json
   "CVE-YYYY-NNNNN": ["T1190", "T1078.004"]
   ```

4. Bump `generated_at` to today's UTC ISO-8601 (e.g. `2026-06-05T00:00:00Z`). Bump `version` only when the upstream ATT&CK release changes (e.g. `v17.1 → v17.2`).

### Add an ATT&CK → D3FEND countermeasure mapping

If a CVE addition introduces a previously-unmapped technique ID, the [cross-coverage rule](#cross-vendor-coverage-rule) below fails CI until you also add the D3FEND row.

1. Look up the technique on [`d3fend.mitre.org`](https://d3fend.mitre.org/) — each technique page lists D3FEND counter-techniques.
2. Append to `vendor/d3fend-mappings.json`:

   ```json
   "T1190": ["D3-NTA", "D3-WAFC", "D3-IRA"]
   ```

3. Bump `generated_at`; bump `version` only when D3FEND ships a new release.

## Verification

```bash
make test    # pins schema validators + the cross-vendor coverage invariant
make smoke   # offline end-to-end run; produces data/priority.jsonl + data/REPORT.md
git diff data/REPORT.md   # inspect enrichment changes
```

The shipped-data load tests in [`tests/test_enrich_attack.py`](../tests/test_enrich_attack.py) and [`tests/test_enrich_d3fend.py`](../tests/test_enrich_d3fend.py) (`test_shipped_vendored_file_loads_cleanly`) parse the live vendor files and reject any schema drift.

## Cross-vendor coverage rule

Every ATT&CK technique referenced anywhere in `vendor/attack-stix.json` must have ≥1 D3FEND mapping in `vendor/d3fend-mappings.json`. Enforced verbatim by [`tests/test_enrich_d3fend.py::test_shipped_d3fend_covers_techniques_referenced_by_shipped_attack`](../tests/test_enrich_d3fend.py):

```python
referenced_techniques = {
    tid for technique_list in attack.mappings.values() for tid in technique_list
}
missing = sorted(t for t in referenced_techniques if not d3fend.lookup(t))
assert not missing, f"techniques without D3FEND coverage: {missing}"
```

**Refresh both files in the same PR.** Adding an ATT&CK technique without a matching D3FEND entry fails CI.

## Cadence

Quarterly is sufficient. [ATT&CK ships ~2 major releases per year](https://attack.mitre.org/resources/updates/); D3FEND moves more slowly. Refresh sooner when:

- a new CVE you want the evaluator to score isn't covered;
- an upstream release retires a technique ID you reference (rare; check the [ATT&CK changelog](https://attack.mitre.org/resources/updates/) at refresh time).

## License acknowledgements

See [`NOTICE`](../NOTICE) — MITRE ATT&CK (Apache-2.0) and MITRE D3FEND (MIT).
