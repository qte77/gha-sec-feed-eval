"""MITRE D3FEND enrichment — ATT&CK technique → countermeasure-ID lookup.

Loads the vendored subset at `vendor/d3fend-mappings.json`. Mirrors the
shape used by `enrich/attack.py`; both share `VendoredDataError`.

Refresh procedure: see `docs/refresh-vendored-data.md`.
"""

from __future__ import annotations

import json
from pathlib import Path

from pydantic import AwareDatetime, BaseModel, ConfigDict, ValidationError

from gha_sec_feed_eval.enrich.attack import VendoredDataError


class D3fendMapping(BaseModel):
    """In-memory ATT&CK technique → D3FEND countermeasure-ID mapping."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    version: str
    generated_at: AwareDatetime
    mappings: dict[str, list[str]]

    def lookup(self, technique_id: str) -> list[str]:
        """Return a fresh list of D3FEND IDs for `technique_id` (or [])."""
        return list(self.mappings.get(technique_id, []))


def load_d3fend_mapping(path: str | Path) -> D3fendMapping:
    """Read + validate the vendored D3FEND subset.

    All failure modes (missing file, malformed JSON, schema drift) are
    surfaced as VendoredDataError with a pointer to the refresh runbook.
    """
    p = Path(path)
    try:
        text = p.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        msg = f"vendored D3FEND data missing at {p}; refresh per docs/refresh-vendored-data.md"
        raise VendoredDataError(msg) from exc

    try:
        payload = json.loads(text)
    except json.JSONDecodeError as exc:
        msg = f"vendored D3FEND data at {p} is not valid JSON: {exc.msg}"
        raise VendoredDataError(msg) from exc

    try:
        return D3fendMapping.model_validate(payload)
    except ValidationError as exc:
        msg = f"vendored D3FEND data at {p} failed schema validation"
        raise VendoredDataError(msg) from exc
