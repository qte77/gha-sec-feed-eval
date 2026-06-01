"""Red-phase tests for `gha_sec_feed_eval.filter`.

Loads `categories/default.yaml` (or a consumer override), matches each
FeedRow's refs against the ecosystem keyword lists, and returns the
slugs of every ecosystem that matched. Phase 2b — module 3.

Match semantics per docs/categories.md:

* Case-insensitive substring match against `refs[*]`.
* Wildcard `*` is supported only at the END of a keyword token; everything
  preceding the `*` must appear as a substring of the URL.
* A row with no matches yields an empty `matched_categories` list and
  is dropped from the C2 output by downstream code.
"""

from __future__ import annotations

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from pydantic import ValidationError

from gha_sec_feed_eval.filter import CategoriesConfig, load_categories, matched_categories
from gha_sec_feed_eval.models import FeedRow


# -- helpers ----------------------------------------------------------------


def _row(refs: list[str]) -> FeedRow:
    return FeedRow.model_validate({
        "id": "CVE-2026-12345",
        "source": "nvd",
        "published": "2026-05-31T00:00:00Z",
        "severity": "high",
        "cvss": 8.0,
        "epss": 0.1,
        "kev": False,
        "refs": refs,
        "schema_version": "1.0.0",
    })


# Minimal config used by most tests — avoids depending on the shipped
# categories/default.yaml so a default-categories rename doesn't ripple
# into 30 unrelated tests.
_MINIMAL_CONFIG = CategoriesConfig.model_validate({
    "stack_keywords": {
        "python": ["pip", "fastapi", "pydantic"],
        "typescript": ["npm", "react", "@typescript-eslint/*"],
        "github-actions": ["actions/checkout"],
    },
    "priority_thresholds": {"act_now": 8.0, "this_week": 5.0},
    "match_strategy": "keyword-in-refs-or-affected-products",
})


# MARK: config loading


def test_load_categories_returns_pydantic_model(tmp_path):
    yaml_path = tmp_path / "categories.yaml"
    yaml_path.write_text(
        "stack_keywords:\n"
        "  python:\n    - pip\n"
        "priority_thresholds: {act_now: 8.0, this_week: 5.0}\n"
        'match_strategy: "keyword-in-refs-or-affected-products"\n'
    )
    cfg = load_categories(yaml_path)
    assert isinstance(cfg, CategoriesConfig)
    assert cfg.stack_keywords == {"python": ["pip"]}
    assert cfg.priority_thresholds == {"act_now": 8.0, "this_week": 5.0}


def test_load_categories_loads_shipped_defaults():
    """The repo-shipped categories/default.yaml is a valid config."""
    cfg = load_categories("categories/default.yaml")
    assert "python" in cfg.stack_keywords
    assert "github-actions" in cfg.stack_keywords
    assert "actions/checkout" in cfg.stack_keywords["github-actions"]


def test_load_categories_raises_on_missing_file(tmp_path):
    with pytest.raises(FileNotFoundError):
        load_categories(tmp_path / "does-not-exist.yaml")


@pytest.mark.parametrize(
    "bad_strategy",
    ["", "regex", "keyword-only", "KEYWORD-IN-REFS-OR-AFFECTED-PRODUCTS"],
)
def test_categories_config_rejects_unknown_match_strategy(bad_strategy: str):
    with pytest.raises(ValidationError):
        CategoriesConfig.model_validate({
            "stack_keywords": {"python": ["pip"]},
            "priority_thresholds": {"act_now": 8.0, "this_week": 5.0},
            "match_strategy": bad_strategy,
        })


def test_categories_config_rejects_empty_stack_keywords():
    """An empty stack_keywords map matches nothing — likely a config error."""
    with pytest.raises(ValidationError):
        CategoriesConfig.model_validate({
            "stack_keywords": {},
            "priority_thresholds": {"act_now": 8.0, "this_week": 5.0},
            "match_strategy": "keyword-in-refs-or-affected-products",
        })


# MARK: matching — basics


def test_no_refs_matches_nothing():
    row = _row(refs=[])
    assert matched_categories(row, _MINIMAL_CONFIG) == []


def test_single_keyword_match_in_single_ecosystem():
    row = _row(refs=["https://pypi.org/project/pydantic/2.10/"])
    assert matched_categories(row, _MINIMAL_CONFIG) == ["python"]


def test_keyword_match_is_case_insensitive():
    row = _row(refs=["https://github.com/pydata/PYDANTIC/issues/1"])
    assert "python" in matched_categories(row, _MINIMAL_CONFIG)


def test_multiple_ecosystems_match_in_same_ref():
    """A single ref URL can hit keywords from different ecosystems —
    each matched ecosystem appears once, regardless of how many keywords
    inside it matched."""
    row = _row(refs=["https://github.com/actions/checkout/issues/pip-cache"])
    matches = set(matched_categories(row, _MINIMAL_CONFIG))
    assert matches == {"python", "github-actions"}


def test_advisory_with_no_keywords_matches_nothing():
    row = _row(refs=[
        "https://nvd.nist.gov/vuln/detail/CVE-2026-12345",
        "https://www.cve.org/CVERecord?id=CVE-2026-12345",
    ])
    assert matched_categories(row, _MINIMAL_CONFIG) == []


def test_each_ecosystem_appears_at_most_once_per_row():
    """Multiple keywords from the same ecosystem inside one URL must
    NOT double-count the ecosystem slug."""
    row = _row(refs=["https://pypi.org/pip-fastapi-pydantic-combo"])
    matches = matched_categories(row, _MINIMAL_CONFIG)
    assert matches.count("python") == 1


# MARK: wildcard


def test_wildcard_keyword_matches_prefix():
    """`@typescript-eslint/*` matches `@typescript-eslint/parser`."""
    row = _row(refs=["https://github.com/typescript-eslint/typescript-eslint/blob/main/packages/@typescript-eslint/parser/README.md"])
    assert "typescript" in matched_categories(row, _MINIMAL_CONFIG)


def test_wildcard_keyword_does_not_match_without_prefix():
    """A URL without the wildcard's prefix substring does NOT match."""
    row = _row(refs=["https://example.com/unrelated/path"])
    assert matched_categories(row, _MINIMAL_CONFIG) == []


# MARK: stability / property tests


def test_matched_categories_is_idempotent():
    """Calling matched_categories twice on the same row yields the same
    set of slugs (no hidden state, no list-order drift)."""
    row = _row(refs=[
        "https://pypi.org/pydantic",
        "https://github.com/actions/checkout",
    ])
    first = matched_categories(row, _MINIMAL_CONFIG)
    second = matched_categories(row, _MINIMAL_CONFIG)
    assert sorted(first) == sorted(second)


@settings(max_examples=50, deadline=None)
@given(refs=st.lists(st.text(min_size=0, max_size=200), max_size=10))
def test_property_match_count_never_exceeds_ecosystem_count(refs: list[str]):
    row = _row(refs=refs)
    matches = matched_categories(row, _MINIMAL_CONFIG)
    assert len(matches) <= len(_MINIMAL_CONFIG.stack_keywords)
    # No duplicates.
    assert len(matches) == len(set(matches))


@settings(max_examples=50, deadline=None)
@given(extra=st.text(min_size=0, max_size=50))
def test_property_appending_non_matching_text_does_not_remove_matches(extra: str):
    """Adding more text to a ref can only add matches, never remove them."""
    base_refs = ["https://pypi.org/pydantic"]
    row_base = _row(refs=base_refs)
    row_extended = _row(refs=[base_refs[0] + extra])
    base_matches = set(matched_categories(row_base, _MINIMAL_CONFIG))
    extended_matches = set(matched_categories(row_extended, _MINIMAL_CONFIG))
    assert base_matches.issubset(extended_matches)
