---
title: Glossary
purpose: Expansions for every abbreviation used across this repo. Single source of truth - other docs link here instead of re-defining inline.
created: 2026-06-01
updated: 2026-06-01
category: technical
---

## Project-specific

| Abbrev | Expansion |
|---|---|
| **C1** | Contract 1 - the input feed format we consume from [`qte77/gha-sec-feed`](https://github.com/qte77/gha-sec-feed). Pinned at `schema_version: "1.0.0"`. See [`docs/contracts.md`](contracts.md). |
| **C2** | Contract 2 - the enriched + scored output this evaluator emits. Pinned at `schema_version: "1.0.0"`. See [`docs/contracts.md`](contracts.md). |
| **GSFE_** | Env var prefix consumed by `AppSettings` (e.g. `GSFE_OFFLINE=1`, `GSFE_FEED_URL=...`). Defined in [`docs/architecture.md`](architecture.md). |
| **REPORT.md** | Human-readable Markdown report rendered by `writer.py`. Sections: Act-Now / This-Week / Monitor / Top ATT&CK / By source / Methodology. |

## Vulnerability data

| Abbrev | Expansion |
|---|---|
| **CVE** | Common Vulnerabilities and Exposures - standard vulnerability identifier (`CVE-YYYY-NNNNN`). |
| **CVSS** | Common Vulnerability Scoring System - 0.0-10.0 base severity score. We score-bump on `cvss >= 9.0`. See [`docs/scoring.md`](scoring.md). |
| **CISA KEV** | [CISA Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) catalogue - vulns observed in active exploitation. We score-bump when `kev: true`. |
| **EPSS** | [Exploit Prediction Scoring System](https://www.first.org/epss/) (FIRST.org) - probabilistic forecast of exploitation in the next 30 days. We weight `epss_score * 2.0` into the priority score. |
| **GHSA** | GitHub Security Advisory identifier - one of the `source` enum values in C1. |
| **NVD** | National Vulnerability Database (NIST) - one of the `source` enum values in C1. |
| **OSV** | Open Source Vulnerabilities database (Google) - one of the `source` enum values in C1 *and* the data source for our `osv-scanner.yaml` workflow. |
| **PoC** | Proof-of-Concept exploit code. Used in the `has_active_exploit()` heuristic in [`docs/scoring.md`](scoring.md). |

## MITRE frameworks

| Abbrev | Expansion |
|---|---|
| **MITRE ATT&CK** | [Adversary tactics, techniques, and procedures](https://attack.mitre.org/) (TTPs). We map each CVE to ATT&CK technique IDs (e.g. `T1190` "Exploit Public-Facing Application"). |
| **MITRE D3FEND** | [Defensive countermeasures](https://d3fend.mitre.org/) matched to ATT&CK techniques. We map each ATT&CK ID to D3FEND IDs (e.g. `D3-NTA` "Network Traffic Analysis"). |
| **STIX** | [Structured Threat Information Expression](https://oasis-open.github.io/cti-documentation/stix/intro) - JSON serialisation we use for the vendored ATT&CK bundle under `vendor/`. |
| **TTP** | Tactics, Techniques, and Procedures - what ATT&CK catalogues. |

## Formats

| Abbrev | Expansion |
|---|---|
| **JSONL** | JSON Lines - one JSON object per line. Used for both C1 input and C2 output. |
| **SBOM** | Software Bill of Materials. Produced by `sbom.yaml` (qte77/gha-sbom-action) and at release by Syft (`publish-release.yaml`). |
| **SPDX** | [Software Package Data Exchange](https://spdx.dev/) - SBOM format we emit (`sbom.spdx.json`). |
| **SARIF** | [Static Analysis Results Interchange Format](https://sarifweb.azurewebsites.net/) - what we upload to GitHub Code Scanning. |
| **YAML** | YAML Ain't Markup Language - config + GitHub Actions workflow file format. |
| **TOML** | Tom's Obvious Minimal Language - `pyproject.toml` config format. |
