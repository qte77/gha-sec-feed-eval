"""Locked 0-10 priority score formula. See `docs/scoring.md`.

Adapted from cve-sentry's Sentry Priority Score (formula shape only;
implementation is original). Pinned at v1.0.0 — any change is a
stop-and-ask trigger.
"""

from __future__ import annotations

from datetime import UTC, datetime
from urllib.parse import urlparse

from gha_sec_feed_eval.models import FeedRow, PriorityCategory, Source

# Per docs/scoring.md the heuristic flags refs hosted on these well-known
# exploit/PoC repositories. Substring match against the URL host suffix
# (so `www.exploit-db.com` and `exploit-db.com` both qualify).
_EXPLOIT_HOST_SUBSTRINGS: frozenset[str] = frozenset({
    "exploit-db.com",
    "packetstormsecurity.com",
    "metasploit-framework",
})

# Path-level signals — case-sensitive containment / suffix.
_POC_PATH_SUBSTRING = "/poc/"
_EXPLOIT_PATH_SUFFIX = "/exploit"

_RECENCY_WINDOW_DAYS = 7
_RECENCY_MAX = 2.0
_KEV_BUMP = 2.0
_ACTIVE_EXPLOIT_BUMP = 2.0
_CVSS_CRITICAL_BUMP = 2.0
_CVSS_CRITICAL_THRESHOLD = 9.0
_EPSS_WEIGHT = 2.0
_SCORE_CAP = 10.0

_ACT_NOW_THRESHOLD = 8.0
_THIS_WEEK_THRESHOLD = 5.0


def has_active_exploit(row: FeedRow) -> bool:
    """Heuristic per docs/scoring.md §"Active-exploit heuristic"."""
    if row.source == Source.cisa_kev:
        return True
    for ref in row.refs:
        parsed = urlparse(ref)
        host = parsed.netloc.lower()
        path = parsed.path.lower()
        if any(token in host for token in _EXPLOIT_HOST_SUBSTRINGS):
            return True
        if any(token in path for token in _EXPLOIT_HOST_SUBSTRINGS):
            return True
        if _POC_PATH_SUBSTRING in path or path.endswith(_EXPLOIT_PATH_SUFFIX):
            return True
    return False


def _recency_component(row: FeedRow, now: datetime) -> float:
    days_old = (now - row.published).days
    return _RECENCY_MAX - (days_old / _RECENCY_WINDOW_DAYS) * _RECENCY_MAX


def priority_score(row: FeedRow, now: datetime | None = None) -> float:
    """Compute the 0-10 priority score for a C1 row. Rounded to 2 decimals."""
    when = now if now is not None else datetime.now(UTC)
    score = 0.0
    if row.kev:
        score += _KEV_BUMP
    if has_active_exploit(row):
        score += _ACTIVE_EXPLOIT_BUMP
    if row.epss is not None:
        score += row.epss * _EPSS_WEIGHT
    score += max(0.0, _recency_component(row, when))
    if row.cvss is not None and row.cvss >= _CVSS_CRITICAL_THRESHOLD:
        score += _CVSS_CRITICAL_BUMP
    return round(min(score, _SCORE_CAP), 2)


def priority_category(score: float) -> PriorityCategory:
    """Bucket a 0-10 score into act_now / this_week / monitor."""
    if score >= _ACT_NOW_THRESHOLD:
        return PriorityCategory.act_now
    if score >= _THIS_WEEK_THRESHOLD:
        return PriorityCategory.this_week
    return PriorityCategory.monitor
