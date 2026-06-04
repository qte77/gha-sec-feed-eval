"""Enrichment modules — attach ATT&CK / D3FEND / live-EPSS context to FeedRow.

Each submodule loads a vendored data snapshot and exposes a lookup that
returns the relevant identifiers for a given input. Vendoring (rather
than runtime fetch) is the Phase 2b decision per
`docs/refresh-vendored-data.md`.
"""
