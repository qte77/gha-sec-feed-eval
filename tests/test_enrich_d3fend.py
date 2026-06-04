"""Red-phase tests for `gha_sec_feed_eval.enrich.d3fend`.

Loads the vendored MITRE D3FEND subset (ATT&CK technique-ID →
D3FEND countermeasure-ID list) from `vendor/d3fend-mappings.json`.
Mirrors the shape used by `enrich/attack.py` — see Phase 2b decisions.

Phase 2b — module 7.
"""

from __future__ import annotations

import json

import pytest

from gha_sec_feed_eval.enrich.attack import VendoredDataError
from gha_sec_feed_eval.enrich.d3fend import D3fendMapping, load_d3fend_mapping

_VALID_MAPPING = {
    "version": "D3FEND v0.18 (subset)",
    "generated_at": "2026-06-01T00:00:00Z",
    "mappings": {
        "T1190": ["D3-NTA", "D3-WAFC"],
        "T1078.004": ["D3-MFA"],
        "T1611": ["D3-CHN"],
    },
}


def _write(tmp_path, payload) -> str:
    path = tmp_path / "d3fend.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return str(path)


# MARK: load


def test_load_returns_d3fend_mapping(tmp_path):
    mapping = load_d3fend_mapping(_write(tmp_path, _VALID_MAPPING))
    assert isinstance(mapping, D3fendMapping)
    assert mapping.version == "D3FEND v0.18 (subset)"


def test_load_missing_file_raises_vendored_data_error(tmp_path):
    with pytest.raises(VendoredDataError) as excinfo:
        load_d3fend_mapping(tmp_path / "nope.json")
    assert "refresh-vendored-data.md" in str(excinfo.value)


def test_load_invalid_json_raises_vendored_data_error(tmp_path):
    path = tmp_path / "broken.json"
    path.write_text("{not valid json", encoding="utf-8")
    with pytest.raises(VendoredDataError):
        load_d3fend_mapping(str(path))


def test_load_extra_top_level_field_rejected(tmp_path):
    path = _write(tmp_path, {**_VALID_MAPPING, "rogue": "field"})
    with pytest.raises(VendoredDataError):
        load_d3fend_mapping(path)


# MARK: lookup


def test_lookup_returns_countermeasures_for_known_technique(tmp_path):
    mapping = load_d3fend_mapping(_write(tmp_path, _VALID_MAPPING))
    assert mapping.lookup("T1190") == ["D3-NTA", "D3-WAFC"]


def test_lookup_returns_empty_list_for_unknown_technique(tmp_path):
    mapping = load_d3fend_mapping(_write(tmp_path, _VALID_MAPPING))
    result = mapping.lookup("T9999")
    assert result == []
    assert isinstance(result, list)


def test_lookup_returns_independent_lists(tmp_path):
    """Mutating the returned list must not corrupt the stored mapping."""
    mapping = load_d3fend_mapping(_write(tmp_path, _VALID_MAPPING))
    first = mapping.lookup("T1190")
    first.append("D3-XXX")
    second = mapping.lookup("T1190")
    assert second == ["D3-NTA", "D3-WAFC"]


def test_lookup_is_case_sensitive_on_technique_id(tmp_path):
    """ATT&CK technique IDs are canonically uppercase. Mixed-case lookup
    misses (callers should normalise upstream)."""
    mapping = load_d3fend_mapping(_write(tmp_path, _VALID_MAPPING))
    assert mapping.lookup("t1190") == []


# MARK: shipped vendored data + alignment with attack mapping


def test_shipped_vendored_file_loads_cleanly():
    """The repo-shipped vendor/d3fend-mappings.json must parse against the
    schema. Drift here = refresh bug; fail CI."""
    mapping = load_d3fend_mapping("vendor/d3fend-mappings.json")
    assert len(mapping.mappings) > 0


def test_shipped_d3fend_covers_techniques_referenced_by_shipped_attack():
    """Every ATT&CK technique we ship in vendor/attack-stix.json should
    have at least one D3FEND countermeasure mapping. Otherwise CVE→
    technique enrichment runs but the technique→countermeasure step
    silently returns []."""
    from gha_sec_feed_eval.enrich.attack import load_attack_mapping

    attack = load_attack_mapping("vendor/attack-stix.json")
    d3fend = load_d3fend_mapping("vendor/d3fend-mappings.json")
    referenced_techniques = {
        tid for technique_list in attack.mappings.values() for tid in technique_list
    }
    missing = sorted(t for t in referenced_techniques if not d3fend.lookup(t))
    assert not missing, f"techniques without D3FEND coverage: {missing}"
