"""Smoke test placeholder.

Pytest exits 5 ("no tests collected") on an empty suite, failing
CI. Real test modules — `test_models.py`, `test_scoring.py`,
`test_loader.py`, `test_filter.py`, `test_http_client.py`,
`test_enrich_*.py`, `test_writer.py`, `test_cli.py` — land per phase 2b
TDD order. Delete this file once the first real test lands.
"""

from gha_sec_feed_eval import __version__


def test_version_is_string():
    assert isinstance(__version__, str)
    assert __version__
