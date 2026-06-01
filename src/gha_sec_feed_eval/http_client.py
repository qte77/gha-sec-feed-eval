"""HTTPS-only egress chokepoint with a 5-host allowlist.

Every outbound HTTP in this package goes through `get()`. The function
fails loudly when:

* the URL scheme is not `https`,
* the host is not in the brief-mandated allowlist, or
* `GSFE_OFFLINE=1` is set in the environment.

The opener is dependency-injected so tests can stub the I/O without
opening a socket. The live `@pytest.mark.network` boundary test lives
alongside `enrich/epss.py`.
"""

from __future__ import annotations

import os
from typing import TYPE_CHECKING
from urllib.parse import urlparse
from urllib.request import Request, urlopen

if TYPE_CHECKING:
    from collections.abc import Callable

# Brief-mandated allowlist. Adding a 6th host requires a documented
# brief deviation.
_ALLOWED_HOSTS: frozenset[str] = frozenset(
    {
        "raw.githubusercontent.com",
        "api.github.com",
        "attack.mitre.org",
        "d3fend.mitre.org",
        "api.first.org",
    }
)

_OFFLINE_ENV_VAR = "GSFE_OFFLINE"
_OFFLINE_TRUTHY = frozenset({"1", "true", "yes"})
_HTTPS_SCHEME = "https"
_DEFAULT_TIMEOUT_SECONDS = 30


class HttpClientError(Exception):
    """Base class for http_client errors. Catch this for blanket handling."""


class OfflineModeError(HttpClientError):
    """Raised when GSFE_OFFLINE is enabled and an HTTP call is attempted."""


class SchemeNotAllowedError(HttpClientError):
    """Raised when a non-https URL is requested."""


class HostNotAllowedError(HttpClientError):
    """Raised when the URL's host is not in `_ALLOWED_HOSTS`."""


def _offline_mode_enabled() -> bool:
    return os.environ.get(_OFFLINE_ENV_VAR, "").strip().lower() in _OFFLINE_TRUTHY


def get(
    url: str,
    *,
    timeout: float = _DEFAULT_TIMEOUT_SECONDS,
    opener: Callable | None = None,
) -> bytes:
    """Fetch `url` and return the response body bytes.

    Raises `HttpClientError` (or a subclass) on any policy violation
    or I/O failure.
    """
    if _offline_mode_enabled():
        msg = f"{_OFFLINE_ENV_VAR}=1 set — network calls are disabled"
        raise OfflineModeError(msg)

    parsed = urlparse(url)
    if parsed.scheme != _HTTPS_SCHEME:
        msg = f"non-https scheme not allowed: {parsed.scheme or '(empty)'!r}"
        raise SchemeNotAllowedError(msg)

    host = parsed.hostname or ""
    if host.lower() not in _ALLOWED_HOSTS:
        msg = f"host {host!r} is not in the allowlist"
        raise HostNotAllowedError(msg)

    open_fn = opener if opener is not None else urlopen
    try:
        # Scheme + host are already validated above, so the S310 warning
        # about urlopen accepting file:/// or custom schemes is moot.
        with open_fn(Request(url), timeout=timeout) as response:  # noqa: S310
            return response.read()
    except OSError as exc:
        # urllib's URLError / HTTPError / socket.timeout are all OSError.
        msg = f"fetch failed for {url}: {exc}"
        raise HttpClientError(msg) from exc
