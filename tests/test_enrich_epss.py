"""Red-phase tests for `gha_sec_feed_eval.enrich.epss`.

`resolve_epss(row, http_get=...)` returns the EPSS score to use for a
FeedRow. Decision order per the Phase 2b decisions memo:

1. If `row.epss` is not None, return it verbatim (no fetch).
2. If `GSFE_OFFLINE=1`, return None (no fetch, no enrichment; scoring
   treats None as 0).
3. Otherwise fetch from [first.org/epss](https://www.first.org/epss/)
   and return the parsed score.

Live-fetch tests are marked `@pytest.mark.network` (excluded from
default `make test`). Hermetic tests inject `http_get` for the I/O.

Phase 2b — module 8.
"""

from __future__ import annotations

import json

import pytest

from gha_sec_feed_eval.enrich.epss import EpssFetchError, resolve_epss
from gha_sec_feed_eval.models import FeedRow


def _row(epss: float | None) -> FeedRow:
    return FeedRow.model_validate({
        "id": "CVE-2026-12345",
        "source": "nvd",
        "published": "2026-05-31T00:00:00Z",
        "severity": "high",
        "cvss": 8.0,
        "epss": epss,
        "kev": False,
        "refs": [],
        "schema_version": "1.0.0",
    })


def _fixture_response(score: float | str, cve: str = "CVE-2026-12345") -> bytes:
    """Mimic the api.first.org/data/v1/epss/?cve=... JSON envelope."""
    return json.dumps({
        "status": "OK",
        "status-code": 200,
        "version": "1.0",
        "access": "public",
        "total": 1,
        "offset": 0,
        "limit": 100,
        "data": [{
            "cve": cve,
            "epss": str(score),
            "percentile": "0.99",
            "date": "2026-05-31",
        }],
    }).encode("utf-8")


# MARK: short-circuit on present epss


def test_resolve_epss_returns_existing_value_without_fetching(monkeypatch):
    monkeypatch.delenv("GSFE_OFFLINE", raising=False)
    fetch_calls: list[str] = []

    def _fail_if_called(url):
        fetch_calls.append(url)
        raise AssertionError("fetch must not be called when row.epss is set")

    row = _row(epss=0.42)
    assert resolve_epss(row, http_get=_fail_if_called) == 0.42
    assert fetch_calls == []


def test_resolve_epss_returns_0_unchanged():
    """EPSS = 0.0 is a valid score, not 'missing' — must NOT trigger fetch."""
    row = _row(epss=0.0)
    assert resolve_epss(row, http_get=lambda _u: b"") == 0.0


# MARK: offline mode short-circuit


def test_resolve_epss_returns_none_in_offline_mode(monkeypatch):
    """GSFE_OFFLINE=1 + missing epss → None (no fetch). scoring.py treats
    None as 0 contribution."""
    monkeypatch.setenv("GSFE_OFFLINE", "1")

    def _fail_if_called(_url):
        raise AssertionError("fetch must not be called in offline mode")

    row = _row(epss=None)
    assert resolve_epss(row, http_get=_fail_if_called) is None


# MARK: fetch path (hermetic via injected http_get)


def test_resolve_epss_fetches_when_missing(monkeypatch):
    monkeypatch.delenv("GSFE_OFFLINE", raising=False)
    captured: list[str] = []

    def _stub_get(url):
        captured.append(url)
        return _fixture_response(score=0.87)

    row = _row(epss=None)
    assert resolve_epss(row, http_get=_stub_get) == 0.87
    assert len(captured) == 1
    assert "api.first.org" in captured[0]
    assert "CVE-2026-12345" in captured[0]


def test_resolve_epss_uses_https(monkeypatch):
    """The constructed fetch URL must use HTTPS — http_client would
    reject http:// downstream but the API contract here is to build the
    correct URL in the first place."""
    monkeypatch.delenv("GSFE_OFFLINE", raising=False)
    captured: list[str] = []

    def _stub_get(url):
        captured.append(url)
        return _fixture_response(score=0.5)

    resolve_epss(_row(epss=None), http_get=_stub_get)
    assert captured[0].startswith("https://")


def test_resolve_epss_handles_empty_data_array(monkeypatch):
    """API returns 200 with empty `data` when the CVE is unknown to EPSS
    (e.g., too recent). Treat as 'no enrichment available' → None."""
    monkeypatch.delenv("GSFE_OFFLINE", raising=False)
    payload = json.dumps({
        "status": "OK", "status-code": 200, "version": "1.0",
        "access": "public", "total": 0, "offset": 0, "limit": 100,
        "data": [],
    }).encode("utf-8")
    row = _row(epss=None)
    assert resolve_epss(row, http_get=lambda _u: payload) is None


# MARK: error paths


def test_resolve_epss_raises_on_malformed_response(monkeypatch):
    monkeypatch.delenv("GSFE_OFFLINE", raising=False)
    row = _row(epss=None)
    with pytest.raises(EpssFetchError):
        resolve_epss(row, http_get=lambda _u: b"not-json")


def test_resolve_epss_raises_on_non_ok_status(monkeypatch):
    monkeypatch.delenv("GSFE_OFFLINE", raising=False)
    payload = json.dumps({
        "status": "ERROR", "status-code": 500, "data": [],
    }).encode("utf-8")
    row = _row(epss=None)
    with pytest.raises(EpssFetchError):
        resolve_epss(row, http_get=lambda _u: payload)


def test_resolve_epss_raises_on_unparseable_score(monkeypatch):
    """A non-numeric epss field in the payload is an upstream bug worth
    surfacing rather than silently coercing to 0."""
    monkeypatch.delenv("GSFE_OFFLINE", raising=False)
    payload = json.dumps({
        "status": "OK", "status-code": 200, "data": [{"cve": "CVE-2026-12345", "epss": "abc"}],
    }).encode("utf-8")
    row = _row(epss=None)
    with pytest.raises(EpssFetchError):
        resolve_epss(row, http_get=lambda _u: payload)


# MARK: live boundary (opt-in via `pytest -m network`)


@pytest.mark.network
def test_live_resolve_epss_fetches_real_score():
    """Integration: hit api.first.org for a real, well-known CVE
    (CVE-2021-44228 Log4Shell — Critical and KEV-listed, so it carries
    an EPSS score). Verify the score is a finite float in [0, 1]."""
    from gha_sec_feed_eval.http_client import get

    row = FeedRow.model_validate({
        "id": "CVE-2021-44228",
        "source": "nvd",
        "published": "2021-12-10T00:00:00Z",
        "severity": "critical",
        "cvss": 10.0,
        "epss": None,
        "kev": True,
        "refs": [],
        "schema_version": "1.0.0",
    })
    score = resolve_epss(row, http_get=get)
    assert score is not None
    assert 0.0 <= score <= 1.0
