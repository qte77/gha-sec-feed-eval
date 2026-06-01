"""Red-phase tests for `gha_sec_feed_eval.loader`.

`parse_feed(text)` consumes a JSONL string, validates each row against
the C1 FeedRow schema, and returns a list of FeedRow. Schema-version
drift is the single hard-fail trigger: any line with
`schema_version != "1.0.0"` raises SchemaVersionError so the producer
can't silently break us. Phase 2b — module 4.
"""

from __future__ import annotations

import json

import pytest
from hypothesis import given
from hypothesis import strategies as st

from gha_sec_feed_eval.loader import LoaderError, SchemaVersionError, parse_feed
from gha_sec_feed_eval.models import FeedRow

# Canonical valid row (from docs/contracts.md).
_VALID_ROW = {
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

_VALID_ROW_2 = {
    **_VALID_ROW,
    "id": "CVE-2026-99999",
    "cvss": None,
    "epss": None,
    "kev": False,
}


def _jsonl(*rows: dict) -> str:
    return "\n".join(json.dumps(row) for row in rows)


# MARK: happy path


def test_parse_feed_single_row():
    text = _jsonl(_VALID_ROW)
    result = parse_feed(text)
    assert len(result) == 1
    assert isinstance(result[0], FeedRow)
    assert result[0].id == "CVE-2026-12345"


def test_parse_feed_multiple_rows_preserves_order():
    text = _jsonl(_VALID_ROW, _VALID_ROW_2)
    result = parse_feed(text)
    assert [row.id for row in result] == ["CVE-2026-12345", "CVE-2026-99999"]


def test_parse_feed_preserves_null_cvss_and_epss():
    """C1 spec: cvss/epss are nullable; loader must pass them through unchanged."""
    text = _jsonl(_VALID_ROW_2)
    [row] = parse_feed(text)
    assert row.cvss is None
    assert row.epss is None


# MARK: whitespace / blank-line resilience


def test_parse_feed_empty_input_returns_empty_list():
    assert parse_feed("") == []


def test_parse_feed_whitespace_only_input_returns_empty_list():
    assert parse_feed("   \n\n\t\n") == []


def test_parse_feed_skips_blank_lines_between_rows():
    """Trailing newline + an empty line between rows must NOT trigger a parse error."""
    text = json.dumps(_VALID_ROW) + "\n\n" + json.dumps(_VALID_ROW_2) + "\n"
    result = parse_feed(text)
    assert len(result) == 2


def test_parse_feed_skips_whitespace_only_lines():
    text = json.dumps(_VALID_ROW) + "\n   \n\t\n" + json.dumps(_VALID_ROW_2)
    assert len(parse_feed(text)) == 2


# MARK: schema-version pin


@pytest.mark.parametrize("drift", ["2.0.0", "0.9.0", "1.0.1", "1.0"])
def test_parse_feed_raises_schema_version_error_on_drift(drift: str):
    """ANY producer schema change is a hard stop-and-ask trigger."""
    bad_row = {**_VALID_ROW, "schema_version": drift}
    text = _jsonl(bad_row)
    with pytest.raises(SchemaVersionError) as excinfo:
        parse_feed(text)
    assert drift in str(excinfo.value)


def test_schema_version_error_includes_line_number():
    """The error must identify WHICH line in the JSONL drifted so an
    operator can grep the source quickly."""
    text = _jsonl(_VALID_ROW, {**_VALID_ROW, "schema_version": "2.0.0"})
    with pytest.raises(SchemaVersionError) as excinfo:
        parse_feed(text)
    # 1-indexed line number, matching grep/sed conventions.
    assert "line 2" in str(excinfo.value)


def test_schema_version_error_is_loader_error_subclass():
    """All loader-emitted errors share a common base so callers can
    `except LoaderError:` for blanket handling."""
    assert issubclass(SchemaVersionError, LoaderError)


# MARK: malformed input


def test_parse_feed_raises_loader_error_on_invalid_json():
    text = _jsonl(_VALID_ROW) + "\nnot-json-{"
    with pytest.raises(LoaderError) as excinfo:
        parse_feed(text)
    assert "line 2" in str(excinfo.value)


def test_parse_feed_raises_loader_error_on_pydantic_validation_failure():
    """A line that's valid JSON but fails FeedRow validation (e.g. wrong
    enum value) raises LoaderError with line-number context."""
    bad_row = {**_VALID_ROW, "source": "kaggle"}  # not in Source enum
    text = _jsonl(_VALID_ROW, bad_row)
    with pytest.raises(LoaderError) as excinfo:
        parse_feed(text)
    assert "line 2" in str(excinfo.value)


def test_parse_feed_does_not_swallow_first_error():
    """When multiple lines are invalid, the FIRST error is raised — not
    the last — so the operator fixes the upstream cause, not a
    downstream symptom."""
    bad1 = {**_VALID_ROW, "schema_version": "2.0.0"}
    bad2 = {**_VALID_ROW, "source": "kaggle"}
    text = _jsonl(_VALID_ROW, bad1, bad2)
    with pytest.raises(LoaderError) as excinfo:
        parse_feed(text)
    assert "line 2" in str(excinfo.value)


# MARK: property tests


@given(n_rows=st.integers(min_value=0, max_value=20))
def test_property_parse_feed_returns_count_equals_input_lines(n_rows: int):
    """For a stream of `n` valid rows, parse_feed returns exactly `n` FeedRow."""
    rows = [{**_VALID_ROW, "id": f"CVE-2026-{1000 + i:05d}"} for i in range(n_rows)]
    text = _jsonl(*rows)
    assert len(parse_feed(text)) == n_rows


@given(
    cvss=st.one_of(st.none(), st.floats(min_value=0.0, max_value=10.0)),
    epss=st.one_of(st.none(), st.floats(min_value=0.0, max_value=1.0)),
)
def test_property_round_trip_through_loader(cvss: float | None, epss: float | None):
    """Any valid C1 row JSON-encoded then loader-parsed yields the same FeedRow."""
    row_dict = {**_VALID_ROW, "cvss": cvss, "epss": epss}
    expected = FeedRow.model_validate(row_dict)
    [actual] = parse_feed(json.dumps(row_dict))
    assert actual == expected
