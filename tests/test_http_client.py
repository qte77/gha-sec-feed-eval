"""Red-phase tests for `gha_sec_feed_eval.http_client`.

Single egress chokepoint for the entire package. Every outbound HTTP
must:

* go through `http_client.get(url)` — no direct urllib/httpx elsewhere;
* target HTTPS only (no http/ftp/file/javascript schemes);
* target one of the 5 allowlisted hosts (raw.githubusercontent.com,
  api.github.com, attack.mitre.org, d3fend.mitre.org, api.first.org);
* be blocked entirely when `GSFE_OFFLINE=1` is set.

Tests run hermetically — `_ALLOWED_HOSTS` is introspected directly,
and the network sink is dependency-injected via the `opener` kwarg so
no real socket is opened. The live boundary is exercised separately
under `@pytest.mark.network` (out-of-scope here).

Phase 2b — module 5.
"""

from __future__ import annotations

import pytest

from gha_sec_feed_eval.http_client import (
    _ALLOWED_HOSTS,
    HttpClientError,
    OfflineModeError,
    SchemeNotAllowedError,
    HostNotAllowedError,
    get,
)


_EXPECTED_HOSTS = frozenset({
    "raw.githubusercontent.com",
    "api.github.com",
    "attack.mitre.org",
    "d3fend.mitre.org",
    "api.first.org",
})


class _FakeResponse:
    """Stand-in for urllib's response object — `.read()` returns bytes."""

    def __init__(self, body: bytes = b"ok"):
        self._body = body

    def read(self) -> bytes:
        return self._body

    def __enter__(self) -> _FakeResponse:
        return self

    def __exit__(self, *exc_info) -> None:
        pass


def _fake_opener(_request, timeout: float = 30) -> _FakeResponse:  # noqa: ARG001
    return _FakeResponse(b"sample body")


# MARK: allowlist invariants


def test_allowed_hosts_is_exactly_the_documented_five():
    """The 5-host allowlist is brief-mandated and load-bearing — adding a
    sixth host requires a documented brief deviation."""
    assert _ALLOWED_HOSTS == _EXPECTED_HOSTS


def test_allowed_hosts_is_immutable():
    """Tampering with the allowlist at runtime would silently widen
    egress policy — pin to frozenset."""
    assert isinstance(_ALLOWED_HOSTS, frozenset)


# MARK: scheme guard


@pytest.mark.parametrize(
    "url",
    [
        "http://api.github.com/foo",
        "ftp://api.github.com/foo",
        "file:///etc/passwd",
        "javascript:alert(1)",
        "//api.github.com/foo",
        "/relative/path",
    ],
)
def test_get_rejects_non_https_scheme(url: str, monkeypatch):
    monkeypatch.delenv("GSFE_OFFLINE", raising=False)
    with pytest.raises(SchemeNotAllowedError):
        get(url, opener=_fake_opener)


def test_scheme_not_allowed_error_is_http_client_error_subclass():
    assert issubclass(SchemeNotAllowedError, HttpClientError)


# MARK: host allowlist


@pytest.mark.parametrize("host", sorted(_EXPECTED_HOSTS))
def test_get_accepts_each_allowlisted_host(host: str, monkeypatch):
    monkeypatch.delenv("GSFE_OFFLINE", raising=False)
    body = get(f"https://{host}/some/path", opener=_fake_opener)
    assert body == b"sample body"


@pytest.mark.parametrize(
    "url",
    [
        "https://example.com/foo",
        "https://evil.com/data.json",
        "https://attack.mitre.org.evil.com/path",  # suffix-confusion attack
        "https://attack.mitre.com/",  # typo-squat
    ],
)
def test_get_rejects_non_allowlisted_host(url: str, monkeypatch):
    monkeypatch.delenv("GSFE_OFFLINE", raising=False)
    with pytest.raises(HostNotAllowedError):
        get(url, opener=_fake_opener)


def test_host_not_allowed_error_is_http_client_error_subclass():
    assert issubclass(HostNotAllowedError, HttpClientError)


def test_host_check_is_case_insensitive(monkeypatch):
    """RFC 3986: host portion is case-insensitive. URL-Casing must not
    bypass the allowlist."""
    monkeypatch.delenv("GSFE_OFFLINE", raising=False)
    body = get("https://API.GITHUB.COM/foo", opener=_fake_opener)
    assert body == b"sample body"


# MARK: offline mode


def test_get_raises_offline_mode_error_when_env_set(monkeypatch):
    """GSFE_OFFLINE=1 short-circuits any allowlisted URL — pre-network,
    fail-loud."""
    monkeypatch.setenv("GSFE_OFFLINE", "1")
    with pytest.raises(OfflineModeError):
        get("https://api.github.com/foo", opener=_fake_opener)


def test_offline_mode_error_is_http_client_error_subclass():
    assert issubclass(OfflineModeError, HttpClientError)


@pytest.mark.parametrize("truthy", ["1", "true", "TRUE", "yes"])
def test_offline_mode_treats_common_truthy_values_as_enabled(
    truthy: str, monkeypatch
):
    """Tolerant of human-typed truthy values so an operator setting
    `GSFE_OFFLINE=true` for clarity doesn't accidentally hit the
    network."""
    monkeypatch.setenv("GSFE_OFFLINE", truthy)
    with pytest.raises(OfflineModeError):
        get("https://api.github.com/foo", opener=_fake_opener)


@pytest.mark.parametrize("falsy", ["0", "false", "", "no"])
def test_offline_mode_treats_falsy_values_as_disabled(
    falsy: str, monkeypatch
):
    monkeypatch.setenv("GSFE_OFFLINE", falsy)
    body = get("https://api.github.com/foo", opener=_fake_opener)
    assert body == b"sample body"


def test_offline_check_runs_before_scheme_check(monkeypatch):
    """When both an offline flag is set AND the URL is malformed, the
    offline error wins — we never even consider non-https URLs in
    offline mode, so the error message stays accurate."""
    monkeypatch.setenv("GSFE_OFFLINE", "1")
    with pytest.raises(OfflineModeError):
        get("http://example.com", opener=_fake_opener)


# MARK: error propagation


def test_get_wraps_opener_failure_in_http_client_error(monkeypatch):
    """Any opener-side exception (network failure, HTTP error, timeout)
    surfaces as HttpClientError so callers can blanket-except."""
    monkeypatch.delenv("GSFE_OFFLINE", raising=False)

    def _failing_opener(*_args, **_kwargs):
        raise OSError("connection refused")

    with pytest.raises(HttpClientError):
        get("https://api.github.com/foo", opener=_failing_opener)
