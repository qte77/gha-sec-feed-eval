"""Red-phase tests for `gha_sec_feed_eval.models`.

Strict pydantic v2 contracts for C1 (FeedRow), C2 (PriorityRow), and
priority-meta.json (Meta). Phase 2b — module 1. See
docs/contracts.md for the canonical schemas.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from hypothesis import given
from hypothesis import strategies as st
from pydantic import ValidationError

from gha_sec_feed_eval.models import (
    FeedRow,
    Meta,
    PriorityCategory,
    PriorityRow,
    Severity,
    Source,
)

# Brief-canonical C1 fixture (docs/contracts.md verbatim).
C1_EXAMPLE: dict = {
    "id": "CVE-2026-12345",
    "source": "nvd",
    "published": "2026-05-31T00:00:00Z",
    "severity": "critical",
    "cvss": 9.8,
    "epss": 0.87,
    "kev": True,
    "refs": ["https://nvd.nist.gov/vuln/detail/CVE-2026-12345"],
    "schema_version": "1.0.0",
}

# Brief-canonical C2 fixture.
C2_EXAMPLE: dict = {
    **C1_EXAMPLE,
    "priority_score": 9.0,
    "priority_category": "act_now",
    "attack_techniques": ["T1190", "T1078.004"],
    "d3fend_countermeasures": ["D3-NTA", "D3-MFA"],
    "matched_categories": ["python", "github-actions"],
}

META_EXAMPLE: dict = {
    "schema_version": "1.0.0",
    "input_schema_version": "1.0.0",
    "input_source": "https://raw.githubusercontent.com/qte77/gha-sec-feed/main/data/feed.jsonl",
    "last_run": "2026-05-31T12:00:00Z",
    "total": 234,
    "by_category": {"act_now": 5, "this_week": 28, "monitor": 201},
    "by_source": {"nvd": 100, "cisa-kev": 5, "ghsa": 50, "osv": 79},
    "categories_used": "categories/default.yaml",
}


# MARK: round-trip


def test_c1_example_round_trips_through_json():
    """Brief's C1 example decodes, re-encodes, and re-decodes identically."""
    row = FeedRow.model_validate(C1_EXAMPLE)
    rt = FeedRow.model_validate_json(row.model_dump_json())
    assert rt == row


def test_c2_example_round_trips_through_json():
    """Brief's C2 example decodes, re-encodes, and re-decodes identically."""
    row = PriorityRow.model_validate(C2_EXAMPLE)
    rt = PriorityRow.model_validate_json(row.model_dump_json())
    assert rt == row


def test_meta_example_round_trips_through_json():
    """Brief's priority-meta.json example decodes + re-encodes identically."""
    meta = Meta.model_validate(META_EXAMPLE)
    rt = Meta.model_validate_json(meta.model_dump_json())
    assert rt == meta


# MARK: strict mode (no coercion, no extras)


def test_feedrow_rejects_unknown_field():
    """Strict mode: forbids fields not in the schema."""
    payload = {**C1_EXAMPLE, "unexpected_field": "value"}
    with pytest.raises(ValidationError):
        FeedRow.model_validate(payload)


def test_feedrow_rejects_string_for_cvss():
    """Strict mode: no string-to-float coercion on cvss."""
    payload = {**C1_EXAMPLE, "cvss": "9.8"}
    with pytest.raises(ValidationError):
        FeedRow.model_validate(payload)


def test_feedrow_rejects_int_for_kev():
    """Strict mode: no int-to-bool coercion on kev (1 is not True)."""
    payload = {**C1_EXAMPLE, "kev": 1}
    with pytest.raises(ValidationError):
        FeedRow.model_validate(payload)


def test_feedrow_rejects_non_list_refs():
    payload = {**C1_EXAMPLE, "refs": "https://example.com"}
    with pytest.raises(ValidationError):
        FeedRow.model_validate(payload)


# MARK: enums


@pytest.mark.parametrize(
    "source",
    [
        "nvd",
        "cisa-kev",
        "epss",
        "ghsa",
        "osv",
        "redhat",
        "ubuntu",
        "urlhaus",
        "threatfox",
        "malwarebazaar",
    ],
)
def test_feedrow_accepts_documented_sources(source: str):
    payload = {**C1_EXAMPLE, "source": source}
    row = FeedRow.model_validate(payload)
    assert row.source == Source(source)


def test_feedrow_rejects_undocumented_source():
    payload = {**C1_EXAMPLE, "source": "kaggle"}
    with pytest.raises(ValidationError):
        FeedRow.model_validate(payload)


@pytest.mark.parametrize("severity", ["critical", "high", "medium", "low", "unknown"])
def test_feedrow_accepts_documented_severities(severity: str):
    payload = {**C1_EXAMPLE, "severity": severity}
    row = FeedRow.model_validate(payload)
    assert row.severity == Severity(severity)


@pytest.mark.parametrize("severity", ["CRITICAL", "info", "none", ""])
def test_feedrow_rejects_undocumented_or_miscased_severity(severity: str):
    payload = {**C1_EXAMPLE, "severity": severity}
    with pytest.raises(ValidationError):
        FeedRow.model_validate(payload)


@pytest.mark.parametrize("category", ["act_now", "this_week", "monitor"])
def test_priorityrow_accepts_documented_categories(category: str):
    payload = {**C2_EXAMPLE, "priority_category": category}
    row = PriorityRow.model_validate(payload)
    assert row.priority_category == PriorityCategory(category)


def test_priorityrow_rejects_undocumented_category():
    payload = {**C2_EXAMPLE, "priority_category": "Act-Now"}
    with pytest.raises(ValidationError):
        PriorityRow.model_validate(payload)


# MARK: published timestamp


def test_feedrow_parses_iso_8601_z_suffix_to_utc():
    """ISO-8601 with Z suffix is parsed to a UTC-aware datetime."""
    row = FeedRow.model_validate(C1_EXAMPLE)
    assert row.published == datetime(2026, 5, 31, 0, 0, tzinfo=UTC)
    assert row.published.tzinfo is not None


def test_feedrow_rejects_naive_datetime_string():
    """Naive timestamps (no offset) are rejected — C1 mandates the Z suffix."""
    payload = {**C1_EXAMPLE, "published": "2026-05-31T00:00:00"}
    with pytest.raises(ValidationError):
        FeedRow.model_validate(payload)


# MARK: optional fields (nullable cvss/epss)


def test_feedrow_accepts_null_cvss_and_epss():
    """C1 spec: cvss + epss are nullable; missing fields treated as 0 in scoring."""
    payload = {**C1_EXAMPLE, "cvss": None, "epss": None}
    row = FeedRow.model_validate(payload)
    assert row.cvss is None
    assert row.epss is None


def test_feedrow_rejects_negative_cvss():
    """CVSS is a 0.0-10.0 base score — negative values are invalid."""
    payload = {**C1_EXAMPLE, "cvss": -1.0}
    with pytest.raises(ValidationError):
        FeedRow.model_validate(payload)


def test_feedrow_rejects_cvss_above_10():
    payload = {**C1_EXAMPLE, "cvss": 10.1}
    with pytest.raises(ValidationError):
        FeedRow.model_validate(payload)


def test_feedrow_rejects_epss_above_1():
    """EPSS is a probability in [0, 1]."""
    payload = {**C1_EXAMPLE, "epss": 1.5}
    with pytest.raises(ValidationError):
        FeedRow.model_validate(payload)


def test_feedrow_rejects_negative_epss():
    payload = {**C1_EXAMPLE, "epss": -0.1}
    with pytest.raises(ValidationError):
        FeedRow.model_validate(payload)


# MARK: priority_score range (C2)


def test_priorityrow_rejects_score_below_0():
    payload = {**C2_EXAMPLE, "priority_score": -0.1}
    with pytest.raises(ValidationError):
        PriorityRow.model_validate(payload)


def test_priorityrow_rejects_score_above_10():
    payload = {**C2_EXAMPLE, "priority_score": 10.1}
    with pytest.raises(ValidationError):
        PriorityRow.model_validate(payload)


# MARK: ATT&CK + D3FEND lists


def test_priorityrow_accepts_empty_attack_techniques():
    """Empty lists are valid — CVE may have no ATT&CK mapping."""
    payload = {**C2_EXAMPLE, "attack_techniques": [], "d3fend_countermeasures": []}
    row = PriorityRow.model_validate(payload)
    assert row.attack_techniques == []
    assert row.d3fend_countermeasures == []


def test_priorityrow_rejects_non_string_attack_technique():
    payload = {**C2_EXAMPLE, "attack_techniques": ["T1190", 42]}
    with pytest.raises(ValidationError):
        PriorityRow.model_validate(payload)


# MARK: property tests


@given(
    cvss=st.one_of(st.none(), st.floats(min_value=0.0, max_value=10.0)),
    epss=st.one_of(st.none(), st.floats(min_value=0.0, max_value=1.0)),
    kev=st.booleans(),
)
def test_feedrow_round_trips_for_any_valid_cvss_epss_kev(
    cvss: float | None, epss: float | None, kev: bool
):
    """Property: any valid (cvss, epss, kev) round-trips through JSON unchanged."""
    payload = {**C1_EXAMPLE, "cvss": cvss, "epss": epss, "kev": kev}
    row = FeedRow.model_validate(payload)
    rt = FeedRow.model_validate_json(row.model_dump_json())
    assert rt == row


@given(score=st.floats(min_value=0.0, max_value=10.0))
def test_priorityrow_round_trips_for_any_score_in_range(score: float):
    payload = {**C2_EXAMPLE, "priority_score": score}
    row = PriorityRow.model_validate(payload)
    rt = PriorityRow.model_validate_json(row.model_dump_json())
    assert rt == row
