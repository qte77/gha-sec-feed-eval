"""Pydantic v2 strict contracts for C1 input, C2 output, and run meta.

C1 and C2 schemas are pinned at `schema_version: "1.0.0"`. See
`docs/contracts.md` for the authoritative spec and `docs/scoring.md`
for the locked priority formula. Strict mode (`extra="forbid"` +
typed validators) ensures inbound rows fail loudly on schema drift
rather than silently downgrading.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Literal

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, StrictBool, StrictFloat, StrictStr

# C1 schema versions the eval accepts. Producer's 1.1.0 adds `cwes` + `description`
# additively (gha-sec-feed/docs/SOURCES.md §"Schema + filter capability"); 1.2.0 adds
# `vendors` + `keywords_matched` additively (§"Schema 1.2.0"). Loader gates on this
# set; FeedRow.schema_version stays unconstrained so the validation error surfaces at
# the loader boundary, not as a pydantic Literal-mismatch.
SUPPORTED_C1_SCHEMA_VERSIONS: tuple[str, ...] = ("1.0.0", "1.1.0", "1.2.0")

# We deliberately do NOT enable `strict=True` at model scope because it
# would reject ISO-8601 strings → datetime and string-value → enum
# coercion (both of which we want from JSON input). Strict typing is
# applied per-field: StrictBool blocks 1 → True coercion on `kev`,
# StrictFloat blocks "9.8" → 9.8 coercion on cvss/epss/priority_score,
# and `extra="forbid"` blocks unknown fields.
_STRICT = ConfigDict(extra="forbid", frozen=False)


class Source(StrEnum):
    """C1 `source` enum — the 10 documented feed origins."""

    nvd = "nvd"
    cisa_kev = "cisa-kev"
    epss = "epss"
    ghsa = "ghsa"
    osv = "osv"
    redhat = "redhat"
    ubuntu = "ubuntu"
    urlhaus = "urlhaus"
    threatfox = "threatfox"
    malwarebazaar = "malwarebazaar"


class Severity(StrEnum):
    """C1 `severity` enum — lowercase, no NONE/INFO bucket."""

    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    unknown = "unknown"


class PriorityCategory(StrEnum):
    """C2 `priority_category` bucket — score-derived in scoring.py."""

    act_now = "act_now"
    this_week = "this_week"
    monitor = "monitor"


Cvss = Annotated[StrictFloat, Field(ge=0.0, le=10.0)]
Epss = Annotated[StrictFloat, Field(ge=0.0, le=1.0)]
PriorityScore = Annotated[StrictFloat, Field(ge=0.0, le=10.0)]


class FeedRow(BaseModel):
    """C1 — one row from `gha-sec-feed`'s feed.jsonl. See `docs/contracts.md`."""

    model_config = _STRICT

    id: StrictStr
    source: Source
    published: AwareDatetime
    severity: Severity
    cvss: Cvss | None
    epss: Epss | None
    kev: StrictBool
    refs: list[StrictStr]
    cwes: list[StrictStr] = []
    description: StrictStr = ""
    vendors: list[StrictStr] = []
    keywords_matched: list[StrictStr] = []
    schema_version: StrictStr


class PriorityRow(FeedRow):
    """C2 — `FeedRow` enriched with priority score, category, ATT&CK/D3FEND."""

    model_config = _STRICT

    priority_score: PriorityScore
    priority_category: PriorityCategory
    attack_techniques: list[StrictStr]
    d3fend_countermeasures: list[StrictStr]
    matched_categories: list[StrictStr]
    matched_keywords: list[StrictStr] = []


class Meta(BaseModel):
    """`priority-meta.json` — run metadata sibling to `priority.jsonl`."""

    model_config = _STRICT

    schema_version: Literal["1.1.0"]
    input_schema_version: Literal["1.0.0"]
    accepted_c1_schema_versions: list[StrictStr] = Field(
        default_factory=lambda: list(SUPPORTED_C1_SCHEMA_VERSIONS),
    )
    input_source: str
    last_run: AwareDatetime
    total: Annotated[int, Field(ge=0)]
    by_category: dict[str, int]
    by_source: dict[str, int]
    categories_used: str
