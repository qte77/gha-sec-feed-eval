"""Runtime settings — env-prefixed via `GSFE_`.

Defaults match `docs/architecture.md` and the brief. CLI flags in
`cli.py` override these on demand without mutating the frozen model.
"""

from __future__ import annotations

from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class AppSettings(BaseSettings):
    """Single source of truth for runtime knobs. Frozen — copy-on-update."""

    model_config = SettingsConfigDict(
        env_prefix="GSFE_",
        frozen=True,
        extra="ignore",
    )

    feed_url: str = "https://raw.githubusercontent.com/qte77/gha-sec-feed/main/data/feed.jsonl"
    data_dir: Path = Path("./data")
    categories_file: Path = Path("categories/default.yaml")
    attack_data_path: Path = Path("./vendor/attack-stix.json")
    d3fend_data_path: Path = Path("./vendor/d3fend-mappings.json")
    offline: bool = False
