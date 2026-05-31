---
title: Refresh vendored MITRE ATT&CK + D3FEND data
purpose: Stub — full refresh runbook lands in 2b once the initial STIX/D3FEND bundles are vendored.
created: 2026-06-01
updated: 2026-06-01
category: technical
---

> **Status:** Stub. Full runbook lands in phase 2b alongside the initial
> commit of `vendor/attack-stix.json` and `vendor/d3fend-mappings.json`.
> Will cover:

- Source URLs for the canonical bundles
  ([MITRE/cti](https://github.com/mitre/cti) for ATT&CK;
  [d3fend.mitre.org](https://d3fend.mitre.org/) for D3FEND).
- Curl + jq commands to fetch + minify into the vendored shapes used
  by `enrich/attack.py` and `enrich/d3fend.py`.
- Cadence recommendation (quarterly is sufficient; ATT&CK ships ~2
  major releases per year).
- How to verify the refreshed bundle didn't break existing enrichment:
  `make smoke` against a known CVE fixture and diff
  `data/priority.jsonl`.
- License acknowledgements (see [`NOTICE`](../NOTICE)).
