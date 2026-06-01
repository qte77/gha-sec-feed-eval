"""EPSS enrichment — return the score to use for a FeedRow.

If the C1 row already carries `epss`, use it (no network call). If
`GSFE_OFFLINE=1` is set, return None. Otherwise fetch from
[api.first.org](https://www.first.org/epss/).

The fetcher is dependency-injected so unit tests stay hermetic; the live
boundary is exercised under `@pytest.mark.network` and uses
`http_client.get` (which enforces the allowlist + offline guard).
"""

from __future__ import annotations

import json
import os
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable

    from gha_sec_feed_eval.models import FeedRow

_EPSS_API_URL = "https://api.first.org/data/v1/epss"
_OFFLINE_ENV_VAR = "GSFE_OFFLINE"
_OFFLINE_TRUTHY = frozenset({"1", "true", "yes"})


class EpssFetchError(Exception):
    """Live EPSS fetch returned an unexpected payload."""


def _offline_mode_enabled() -> bool:
    return os.environ.get(_OFFLINE_ENV_VAR, "").strip().lower() in _OFFLINE_TRUTHY


def _build_url(cve_id: str) -> str:
    return f"{_EPSS_API_URL}?cve={cve_id}"


def _parse_score(body: bytes) -> float | None:
    try:
        envelope = json.loads(body)
    except json.JSONDecodeError as exc:
        msg = f"EPSS API returned non-JSON payload: {exc.msg}"
        raise EpssFetchError(msg) from exc

    if envelope.get("status") != "OK":
        msg = f"EPSS API status not OK: {envelope.get('status')!r}"
        raise EpssFetchError(msg)

    data = envelope.get("data", [])
    if not data:
        return None

    raw = data[0].get("epss")
    try:
        return float(raw)
    except (TypeError, ValueError) as exc:
        msg = f"EPSS payload has non-numeric epss field: {raw!r}"
        raise EpssFetchError(msg) from exc


def resolve_epss(
    row: FeedRow,
    *,
    http_get: Callable[[str], bytes],
) -> float | None:
    """Return the EPSS score to use for `row` (preserves None for missing)."""
    if row.epss is not None:
        return row.epss
    if _offline_mode_enabled():
        return None
    body = http_get(_build_url(row.id))
    return _parse_score(body)
