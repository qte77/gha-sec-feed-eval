"""MITRE ATT&CK enrichment — CVE → technique-ID lookup.

Loads the vendored subset at `vendor/attack-stix.json` (NOT the full
STIX bundle, per the Phase 2b decisions memo). The bundle is a JSON
document with a `mappings` dict of `CVE-ID → [technique_id, ...]`.

Refresh procedure: see `docs/refresh-vendored-data.md`.
"""

from __future__ import annotations

import json
from pathlib import Path

from pydantic import AwareDatetime, BaseModel, ConfigDict, ValidationError


class VendoredDataError(Exception):
    """Vendored ATT&CK / D3FEND data is missing, corrupt, or malformed."""


class AttackMapping(BaseModel):
    """In-memory CVE → ATT&CK technique-ID mapping."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    version: str
    generated_at: AwareDatetime
    mappings: dict[str, list[str]]

    def lookup(self, cve_id: str) -> list[str]:
        """Return a fresh list of ATT&CK technique IDs for `cve_id` (or [])."""
        return list(self.mappings.get(cve_id, []))


def load_attack_mapping(path: str | Path) -> AttackMapping:
    """Read + validate the vendored ATT&CK subset.

    All failure modes (missing file, malformed JSON, schema drift) are
    surfaced as VendoredDataError with a pointer to the refresh runbook.
    """
    p = Path(path)
    try:
        text = p.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        msg = (
            f"vendored ATT&CK data missing at {p}; "
            f"refresh per docs/refresh-vendored-data.md"
        )
        raise VendoredDataError(msg) from exc

    try:
        payload = json.loads(text)
    except json.JSONDecodeError as exc:
        msg = f"vendored ATT&CK data at {p} is not valid JSON: {exc.msg}"
        raise VendoredDataError(msg) from exc

    try:
        return AttackMapping.model_validate(payload)
    except ValidationError as exc:
        msg = f"vendored ATT&CK data at {p} failed schema validation"
        raise VendoredDataError(msg) from exc
