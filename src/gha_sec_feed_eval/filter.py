"""Category filter — load YAML config + match each row's refs.

A row that matches no ecosystem yields an empty `matched_categories` list
and is dropped from the C2 output by the caller. See `docs/categories.md`
for the file shape + override semantics.

Match semantics:

* Case-insensitive substring match against `refs[*]` lowercased.
* Wildcard `*` is supported only at the END of a keyword token; the
  preceding substring must appear in the URL. (Wildcards anywhere else
  would invite regex-style surprise — keep KISS.)
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Annotated, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field

if TYPE_CHECKING:
    from gha_sec_feed_eval.models import FeedRow

_WILDCARD_SUFFIX = "*"


class CategoriesConfig(BaseModel):
    """Loaded `categories.yaml` (default or consumer override)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    stack_keywords: Annotated[dict[str, list[str]], Field(min_length=1)]
    priority_thresholds: dict[str, float]
    match_strategy: Literal["keyword-in-refs-or-affected-products"]


def load_categories(path: str | Path) -> CategoriesConfig:
    """Read a YAML file and parse into `CategoriesConfig`."""
    p = Path(path)
    text = p.read_text(encoding="utf-8")
    data = yaml.safe_load(text)
    return CategoriesConfig.model_validate(data)


def _keyword_matches(keyword: str, haystack: str) -> bool:
    """Case-insensitive substring (with end-wildcard) match."""
    kw = keyword.lower()
    if kw.endswith(_WILDCARD_SUFFIX):
        return kw[:-1] in haystack
    return kw in haystack


def matched_categories(row: FeedRow, config: CategoriesConfig) -> list[str]:
    """Return the ecosystem slugs whose keywords matched any of `row.refs`."""
    haystacks = [ref.lower() for ref in row.refs]
    matches: list[str] = []
    for slug, keywords in config.stack_keywords.items():
        if any(
            _keyword_matches(kw, hay) for kw in keywords for hay in haystacks
        ):
            matches.append(slug)
    return matches
