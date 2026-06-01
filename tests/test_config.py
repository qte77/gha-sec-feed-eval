"""Red-phase tests for `gha_sec_feed_eval.config.AppSettings`.

Pydantic-settings model with env prefix `GSFE_`. Phase 2b — module
10 (config half).
"""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from gha_sec_feed_eval.config import AppSettings


def test_default_settings_use_documented_paths(monkeypatch):
    """No env vars set → all the brief-documented defaults apply."""
    for var in (
        "GSFE_FEED_URL",
        "GSFE_DATA_DIR",
        "GSFE_CATEGORIES_FILE",
        "GSFE_ATTACK_DATA_PATH",
        "GSFE_D3FEND_DATA_PATH",
        "GSFE_OFFLINE",
    ):
        monkeypatch.delenv(var, raising=False)
    settings = AppSettings()
    assert settings.feed_url == (
        "https://raw.githubusercontent.com/qte77/gha-sec-feed/main/data/feed.jsonl"
    )
    assert settings.data_dir == Path("./data")
    assert settings.categories_file == Path("categories/default.yaml")
    assert settings.attack_data_path == Path("./vendor/attack-stix.json")
    assert settings.d3fend_data_path == Path("./vendor/d3fend-mappings.json")
    assert settings.offline is False


def test_env_prefix_is_gsfe(monkeypatch):
    """Env var `GSFE_FEED_URL` overrides `feed_url` (case-insensitive)."""
    monkeypatch.setenv("GSFE_FEED_URL", "https://api.github.com/some/feed.jsonl")
    settings = AppSettings()
    assert settings.feed_url == "https://api.github.com/some/feed.jsonl"


def test_env_can_toggle_offline(monkeypatch):
    monkeypatch.setenv("GSFE_OFFLINE", "true")
    settings = AppSettings()
    assert settings.offline is True


def test_unprefixed_env_var_is_ignored(monkeypatch):
    """A plain `FEED_URL` (without the GSFE_ prefix) must NOT silently
    override the default — protects against accidental shell leakage."""
    monkeypatch.setenv("FEED_URL", "https://accidental.example.com/")
    settings = AppSettings()
    assert settings.feed_url != "https://accidental.example.com/"


def test_settings_are_frozen():
    """In-memory immutability — re-binding a field at runtime is a bug."""
    settings = AppSettings()
    with pytest.raises(ValidationError):
        settings.feed_url = "https://hijack.example.com"  # type: ignore[misc]
