"""Red-phase tests for `gha_sec_feed_eval.scoring`.

Locked 0-10 priority formula adapted from cve-sentry's Sentry Priority
Score. Phase 2b — module 2. See `docs/scoring.md` for the canonical
spec.

Component sums (each capped at +2.0):

* KEV +2.0
* Active exploit +2.0 (heuristic on source + refs)
* EPSS up to +2.0  (= epss * 2.0)
* Recency up to +2.0  (= max(0, 2 - (days_old / 7) * 2))
* CVSS >= 9.0 +2.0

Final score = min(sum, 10.0), rounded to 2 decimals. Bucketing:
act_now >= 8.0, this_week >= 5.0, monitor below.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from gha_sec_feed_eval.models import FeedRow, PriorityCategory
from gha_sec_feed_eval.scoring import has_active_exploit, priority_category, priority_score


def _row(**overrides) -> FeedRow:
    base = {
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
    base.update(overrides)
    return FeedRow.model_validate(base)


NOW = datetime(2026, 5, 31, 0, 0, tzinfo=UTC)


# MARK: brief-mandated floor


def test_cvss_10_kev_listed_freshly_published_scores_at_least_8():
    """**Brief-mandated floor.** CVSS 10 + KEV + fresh must be Act-Now.

    Stop-and-ask trigger if this ever fails: the formula is broken.
    """
    row = _row(cvss=10.0, kev=True, epss=None, published="2026-05-31T00:00:00Z")
    score = priority_score(row, now=NOW)
    assert score >= 8.0


# MARK: component scoring (KEV / active-exploit / EPSS / recency / CVSS>=9)


def test_kev_true_contributes_2_points():
    row_kev = _row(kev=True, epss=0.0, cvss=0.0, published=NOW.isoformat())
    row_no_kev = _row(kev=False, epss=0.0, cvss=0.0, published=NOW.isoformat())
    delta = priority_score(row_kev, now=NOW) - priority_score(row_no_kev, now=NOW)
    assert delta == pytest.approx(2.0, abs=0.01)


def test_cvss_at_9_contributes_2_points():
    row_critical = _row(cvss=9.0, kev=False, epss=0.0, published=NOW.isoformat())
    row_below = _row(cvss=8.9, kev=False, epss=0.0, published=NOW.isoformat())
    delta = priority_score(row_critical, now=NOW) - priority_score(row_below, now=NOW)
    assert delta == pytest.approx(2.0, abs=0.01)


def test_cvss_at_10_still_contributes_2_points():
    """CVSS 10 should add exactly the critical bump (not double-count)."""
    row_10 = _row(cvss=10.0, kev=False, epss=0.0, published=NOW.isoformat())
    row_9 = _row(cvss=9.0, kev=False, epss=0.0, published=NOW.isoformat())
    assert priority_score(row_10, now=NOW) == priority_score(row_9, now=NOW)


def test_cvss_null_contributes_0():
    """Missing cvss is treated as no contribution to score."""
    row = _row(cvss=None, kev=False, epss=0.0, published=NOW.isoformat())
    assert priority_score(row, now=NOW) == pytest.approx(2.0, abs=0.01)


@pytest.mark.parametrize(
    ("epss", "expected_component"),
    [(0.0, 0.0), (0.25, 0.5), (0.5, 1.0), (0.87, 1.74), (1.0, 2.0)],
)
def test_epss_contributes_epss_times_2(epss: float, expected_component: float):
    row = _row(epss=epss, kev=False, cvss=0.0, published=NOW.isoformat())
    assert priority_score(row, now=NOW) == pytest.approx(expected_component, abs=0.01)


def test_epss_null_contributes_0():
    row = _row(epss=None, kev=False, cvss=0.0, published=NOW.isoformat())
    assert priority_score(row, now=NOW) == 0.0


@pytest.mark.parametrize(
    ("days_old", "expected_recency"),
    [(0, 2.0), (1, 2.0 - 2.0 / 7), (3, 2.0 - 6.0 / 7), (7, 0.0), (14, 0.0)],
)
def test_recency_decays_linearly_over_7_days_then_floors(
    days_old: int, expected_recency: float
):
    published = NOW - timedelta(days=days_old)
    row = _row(
        published=published.isoformat(), kev=False, epss=0.0, cvss=0.0
    )
    assert priority_score(row, now=NOW) == pytest.approx(expected_recency, abs=0.01)


def test_future_published_treated_as_fresh():
    """Negative days_old (published in the future, e.g. clock skew) still
    returns the max recency bump rather than a meaningless negative."""
    future = NOW + timedelta(days=2)
    row = _row(published=future.isoformat(), kev=False, epss=0.0, cvss=0.0)
    # The recency component is `max(0, 2 - (days_old / 7) * 2)`. With a
    # negative days_old, `(days_old / 7) * 2` is negative, so the inner
    # expression > 2 — but the caller must NOT clamp the recency
    # component to a max of 2 (the score itself is clamped to 10).
    # Pinning behaviour here: future timestamps score >= the same row
    # published today, never less.
    today_row = _row(published=NOW.isoformat(), kev=False, epss=0.0, cvss=0.0)
    assert priority_score(row, now=NOW) >= priority_score(today_row, now=NOW)


# MARK: capping + rounding


def test_score_clamps_to_10():
    """Sum of all bumps would be 10 even before any future tweaks; verify cap."""
    row = _row(cvss=10.0, kev=True, epss=1.0, source="cisa-kev",
               published=NOW.isoformat(),
               refs=["https://exploit-db.com/exploits/42"])
    assert priority_score(row, now=NOW) <= 10.0


def test_score_rounded_to_2_decimals():
    """Output is rounded to 2 decimals — formula uses epss=0.876 to force a
    third decimal in the raw value."""
    row = _row(epss=0.876, kev=False, cvss=0.0, published=NOW.isoformat())
    score = priority_score(row, now=NOW)
    assert score == round(score, 2)


def test_score_never_negative():
    """All component contributions are non-negative, so total >= 0."""
    old = NOW - timedelta(days=365)
    row = _row(cvss=None, epss=None, kev=False, published=old.isoformat())
    assert priority_score(row, now=NOW) >= 0.0


# MARK: has_active_exploit heuristic


def test_active_exploit_when_source_is_cisa_kev():
    row = _row(source="cisa-kev", refs=["https://example.com/advisory"])
    assert has_active_exploit(row) is True


@pytest.mark.parametrize(
    "url",
    [
        "https://www.exploit-db.com/exploits/42",
        "https://packetstormsecurity.com/files/12345/foo.html",
        "https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/x.rb",
    ],
)
def test_active_exploit_when_ref_host_matches_known_exploit_repo(url: str):
    row = _row(source="nvd", refs=[url])
    assert has_active_exploit(row) is True


@pytest.mark.parametrize(
    "url",
    [
        "https://example.com/poc/2026-12345",
        "https://example.com/CVE-2026-12345/exploit",
    ],
)
def test_active_exploit_when_ref_path_signals_poc_or_exploit(url: str):
    row = _row(source="nvd", refs=[url])
    assert has_active_exploit(row) is True


def test_no_active_exploit_for_advisory_only_refs():
    row = _row(
        source="nvd",
        refs=[
            "https://nvd.nist.gov/vuln/detail/CVE-2026-12345",
            "https://www.cve.org/CVERecord?id=CVE-2026-12345",
        ],
    )
    assert has_active_exploit(row) is False


def test_no_active_exploit_for_empty_refs():
    row = _row(source="nvd", refs=[])
    assert has_active_exploit(row) is False


def test_active_exploit_contributes_2_points():
    row_exploit = _row(
        source="cisa-kev", kev=False, cvss=0.0, epss=0.0,
        published=NOW.isoformat(), refs=[]
    )
    row_no_exploit = _row(
        source="nvd", kev=False, cvss=0.0, epss=0.0,
        published=NOW.isoformat(), refs=[]
    )
    delta = priority_score(row_exploit, now=NOW) - priority_score(row_no_exploit, now=NOW)
    assert delta == pytest.approx(2.0, abs=0.01)


# MARK: bucketing


@pytest.mark.parametrize(
    ("score", "expected"),
    [
        (10.0, PriorityCategory.act_now),
        (8.0, PriorityCategory.act_now),
        (7.99, PriorityCategory.this_week),
        (5.0, PriorityCategory.this_week),
        (4.99, PriorityCategory.monitor),
        (0.0, PriorityCategory.monitor),
    ],
)
def test_priority_category_thresholds(score: float, expected: PriorityCategory):
    assert priority_category(score) == expected


# MARK: property tests


def _hypothesis_row(
    cvss: float | None, epss: float | None, kev: bool, days_old: int
) -> FeedRow:
    published = NOW - timedelta(days=days_old)
    return _row(
        cvss=cvss, epss=epss, kev=kev, published=published.isoformat(),
        source="nvd", refs=[],
    )


@settings(max_examples=100, deadline=None)
@given(
    cvss=st.one_of(st.none(), st.floats(min_value=0.0, max_value=10.0)),
    epss=st.one_of(st.none(), st.floats(min_value=0.0, max_value=1.0)),
    days_old=st.integers(min_value=0, max_value=365),
)
def test_property_score_always_in_0_to_10(
    cvss: float | None, epss: float | None, days_old: int
):
    """For any valid input combo, the score never exceeds [0, 10]."""
    row_kev = _hypothesis_row(cvss=cvss, epss=epss, kev=True, days_old=days_old)
    row_no_kev = _hypothesis_row(cvss=cvss, epss=epss, kev=False, days_old=days_old)
    for score in (priority_score(row_kev, now=NOW), priority_score(row_no_kev, now=NOW)):
        assert 0.0 <= score <= 10.0


@settings(max_examples=100, deadline=None)
@given(
    cvss=st.one_of(st.none(), st.floats(min_value=0.0, max_value=10.0)),
    epss=st.one_of(st.none(), st.floats(min_value=0.0, max_value=1.0)),
    days_old=st.integers(min_value=0, max_value=365),
)
def test_property_kev_never_decreases_score(
    cvss: float | None, epss: float | None, days_old: int
):
    """Monotonicity: setting kev=True can only raise the score (or equal,
    after the clamp at 10)."""
    row_no_kev = _hypothesis_row(cvss=cvss, epss=epss, kev=False, days_old=days_old)
    row_kev = _hypothesis_row(cvss=cvss, epss=epss, kev=True, days_old=days_old)
    assert priority_score(row_kev, now=NOW) >= priority_score(row_no_kev, now=NOW)
