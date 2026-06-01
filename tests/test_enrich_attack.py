"""Red-phase tests for `gha_sec_feed_eval.enrich.attack`.

Loads the vendored MITRE ATT&CK subset (CVE → technique-ID list) from
`vendor/attack-stix.json` and exposes a `.lookup(cve_id)` method.
Subset format (not full STIX) per the Phase 2b decisions memo.

Phase 2b — module 6.
"""

from __future__ import annotations

import json

import pytest

from gha_sec_feed_eval.enrich.attack import AttackMapping, VendoredDataError, load_attack_mapping

_VALID_MAPPING = {
    "version": "ATT&CK v17.1",
    "generated_at": "2026-06-01T00:00:00Z",
    "mappings": {
        "CVE-2026-12345": ["T1190", "T1078.004"],
        "CVE-2026-99999": ["T1190"],
    },
}


def _write(tmp_path, payload) -> str:
    path = tmp_path / "attack.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return str(path)


# MARK: load


def test_load_returns_attack_mapping(tmp_path):
    mapping = load_attack_mapping(_write(tmp_path, _VALID_MAPPING))
    assert isinstance(mapping, AttackMapping)
    assert mapping.version == "ATT&CK v17.1"


def test_load_missing_file_raises_vendored_data_error(tmp_path):
    with pytest.raises(VendoredDataError) as excinfo:
        load_attack_mapping(tmp_path / "nope.json")
    assert "refresh-vendored-data.md" in str(excinfo.value)


def test_load_invalid_json_raises_vendored_data_error(tmp_path):
    path = tmp_path / "broken.json"
    path.write_text("{not valid json", encoding="utf-8")
    with pytest.raises(VendoredDataError):
        load_attack_mapping(str(path))


def test_load_missing_mappings_key_raises_vendored_data_error(tmp_path):
    path = _write(tmp_path, {"version": "v17.1", "generated_at": "2026-06-01T00:00:00Z"})
    with pytest.raises(VendoredDataError):
        load_attack_mapping(path)


def test_load_extra_top_level_field_rejected(tmp_path):
    """Unknown fields signal vendor-data drift; fail loud."""
    path = _write(tmp_path, {**_VALID_MAPPING, "rogue_field": "anything"})
    with pytest.raises(VendoredDataError):
        load_attack_mapping(path)


# MARK: lookup


def test_lookup_returns_techniques_for_known_cve(tmp_path):
    mapping = load_attack_mapping(_write(tmp_path, _VALID_MAPPING))
    assert mapping.lookup("CVE-2026-12345") == ["T1190", "T1078.004"]


def test_lookup_returns_empty_list_for_unknown_cve(tmp_path):
    """Unknown CVE returns an empty list (NOT None) so downstream code
    can iterate without type guards."""
    mapping = load_attack_mapping(_write(tmp_path, _VALID_MAPPING))
    result = mapping.lookup("CVE-2026-00000")
    assert result == []
    assert isinstance(result, list)


def test_lookup_is_case_sensitive_on_cve_id(tmp_path):
    """CVE IDs are conventionally uppercase. Mixed-case lookup misses
    (callers should normalise upstream)."""
    mapping = load_attack_mapping(_write(tmp_path, _VALID_MAPPING))
    assert mapping.lookup("cve-2026-12345") == []


def test_lookup_returns_independent_lists(tmp_path):
    """Mutating the returned list must not corrupt the stored mapping."""
    mapping = load_attack_mapping(_write(tmp_path, _VALID_MAPPING))
    first = mapping.lookup("CVE-2026-12345")
    first.append("T9999")
    second = mapping.lookup("CVE-2026-12345")
    assert second == ["T1190", "T1078.004"]


# MARK: shipped vendored data


def test_shipped_vendored_file_loads_cleanly():
    """The repo-shipped vendor/attack-stix.json must parse against the
    AttackMapping schema. Drift here = vendor-refresh bug; fail CI."""
    mapping = load_attack_mapping("vendor/attack-stix.json")
    # Sanity: at least one CVE→technique entry. A zero-mapping vendored
    # file is a refresh failure mode worth catching.
    assert len(mapping.mappings) > 0
