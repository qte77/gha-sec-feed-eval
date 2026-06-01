"""Red-phase tests for `gha_sec_feed_eval.cli`.

`run(settings, *, http_get)` orchestrates the pipeline:
loader.parse_feed → filter.matched_categories → scoring →
enrich/{attack,d3fend,epss} → writer.write_outputs.

`main(argv)` is the argparse entry point that builds an AppSettings,
calls `run`, and returns an exit code.

Phase 2b — module 10 (cli half).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from gha_sec_feed_eval.cli import main, run
from gha_sec_feed_eval.config import AppSettings

_FIXTURE_PATH = Path("tests/fixtures/feed-min.jsonl")
_FIXTURE_BYTES = _FIXTURE_PATH.read_bytes()


def _stub_get_returning_fixture(_url: str) -> bytes:
    return _FIXTURE_BYTES


def _settings(tmp_path: Path) -> AppSettings:
    """AppSettings pointing at tmp output_dir + real vendored data."""
    return AppSettings(
        feed_url="https://raw.githubusercontent.com/qte77/gha-sec-feed/main/data/feed.jsonl",
        data_dir=tmp_path,
        categories_file=Path("categories/default.yaml"),
        attack_data_path=Path("vendor/attack-stix.json"),
        d3fend_data_path=Path("vendor/d3fend-mappings.json"),
        offline=True,  # default tests skip the EPSS fetch path
    )


# MARK: run() — orchestration end-to-end


def test_run_produces_priority_jsonl_with_realistic_filter_results(tmp_path):
    """The 5-row fixture is intentionally realistic — only the rows with
    refs hitting categories/default.yaml keywords pass:

    * CVE-2021-44228 (Log4Shell) — `pydantic` ref → python ecosystem
    * CVE-2024-21626 (runc) — `alpine` ref → docker ecosystem

    The other 3 (CVE-2024-3094, CVE-2022-22965, CVE-2026-00001) have
    no keyword hits and are dropped. Pinning the realistic count
    catches both filter regressions (count drops) and accidental
    keyword-broadening regressions (count grows).
    """
    settings = _settings(tmp_path)
    run(settings, http_get=_stub_get_returning_fixture)
    text = (tmp_path / "priority.jsonl").read_text(encoding="utf-8")
    lines = [line for line in text.splitlines() if line.strip()]
    assert len(lines) == 2
    parsed_ids = {json.loads(line)["id"] for line in lines}
    assert parsed_ids == {"CVE-2021-44228", "CVE-2024-21626"}


def test_run_outputs_round_trip_through_priorityrow(tmp_path):
    """Every C2 line written must validate against the PriorityRow schema."""
    from gha_sec_feed_eval.models import PriorityRow

    settings = _settings(tmp_path)
    run(settings, http_get=_stub_get_returning_fixture)
    text = (tmp_path / "priority.jsonl").read_text(encoding="utf-8")
    for raw_line in text.splitlines():
        if not raw_line.strip():
            continue
        PriorityRow.model_validate_json(raw_line)


def test_run_drops_rows_with_no_matched_categories(tmp_path):
    """A row whose refs match no ecosystem must not appear in C2 output."""
    settings = _settings(tmp_path).model_copy(update={
        "categories_file": Path("categories/default.yaml"),
    })
    # Feed contains ONE row whose only ref is example.com (no category match).
    no_match_payload = json.dumps({
        "id": "CVE-9999-99999",
        "source": "nvd",
        "published": "2026-05-31T00:00:00Z",
        "severity": "low",
        "cvss": 2.0,
        "epss": 0.001,
        "kev": False,
        "refs": ["https://example.com/unrelated"],
        "schema_version": "1.0.0",
    }).encode("utf-8")
    run(settings, http_get=lambda _u: no_match_payload)
    text = (tmp_path / "priority.jsonl").read_text(encoding="utf-8")
    assert text == ""


def test_run_attaches_attack_techniques_when_vendor_has_mapping(tmp_path):
    """CVE-2021-44228 is in vendor/attack-stix.json — its C2 row must
    carry the corresponding attack_techniques list."""
    from gha_sec_feed_eval.models import PriorityRow

    settings = _settings(tmp_path)
    run(settings, http_get=_stub_get_returning_fixture)
    text = (tmp_path / "priority.jsonl").read_text(encoding="utf-8")
    rows = [PriorityRow.model_validate_json(ln) for ln in text.splitlines() if ln.strip()]
    by_id = {row.id: row for row in rows}
    assert by_id["CVE-2021-44228"].attack_techniques == ["T1190", "T1059", "T1203"]


def test_run_attaches_d3fend_countermeasures(tmp_path):
    """CVE-2021-44228 → ATT&CK T1190 → D3-NTA, D3-WAFC, D3-IRA per the
    vendored D3FEND subset."""
    from gha_sec_feed_eval.models import PriorityRow

    settings = _settings(tmp_path)
    run(settings, http_get=_stub_get_returning_fixture)
    text = (tmp_path / "priority.jsonl").read_text(encoding="utf-8")
    rows = [PriorityRow.model_validate_json(ln) for ln in text.splitlines() if ln.strip()]
    by_id = {row.id: row for row in rows}
    d3fends = by_id["CVE-2021-44228"].d3fend_countermeasures
    assert "D3-NTA" in d3fends
    assert "D3-WAFC" in d3fends


def test_run_writes_priority_meta_and_report(tmp_path):
    settings = _settings(tmp_path)
    run(settings, http_get=_stub_get_returning_fixture)
    assert (tmp_path / "priority.jsonl").exists()
    assert (tmp_path / "priority-meta.json").exists()
    assert (tmp_path / "REPORT.md").exists()


def test_run_uses_meta_input_source_from_settings(tmp_path):
    settings = _settings(tmp_path)
    run(settings, http_get=_stub_get_returning_fixture)
    meta = json.loads((tmp_path / "priority-meta.json").read_text(encoding="utf-8"))
    assert meta["input_source"] == settings.feed_url


def test_run_meta_total_matches_c2_line_count(tmp_path):
    settings = _settings(tmp_path)
    run(settings, http_get=_stub_get_returning_fixture)
    meta = json.loads((tmp_path / "priority-meta.json").read_text(encoding="utf-8"))
    lines = [
        ln for ln in (tmp_path / "priority.jsonl").read_text("utf-8").splitlines()
        if ln.strip()
    ]
    assert meta["total"] == len(lines)


# MARK: scoring assertions on the fixture


def test_log4shell_falls_into_this_week_after_recency_decay(tmp_path):
    """CVE-2021-44228 (CVSS 10 + KEV + cisa-kev source for active-exploit
    bump + EPSS 0.97) scores 2 + 2 + 1.94 + 0 (no recency, 4+ years
    old) + 2 = 7.94 → this_week. The recency decay is load-bearing
    behaviour the formula deliberately encodes; pin it so a future
    re-tune doesn't silently collapse recency-distinguishability."""
    from gha_sec_feed_eval.models import PriorityRow

    settings = _settings(tmp_path)
    run(settings, http_get=_stub_get_returning_fixture)
    text = (tmp_path / "priority.jsonl").read_text(encoding="utf-8")
    rows = [PriorityRow.model_validate_json(ln) for ln in text.splitlines() if ln.strip()]
    by_id = {row.id: row for row in rows}
    log4shell = by_id["CVE-2021-44228"]
    assert log4shell.priority_category.value == "this_week"
    assert 7.0 < log4shell.priority_score < 8.0


# MARK: argparse CLI


def test_main_returns_0_on_success(monkeypatch, tmp_path):
    """Smoke: `main(argv)` returns 0 when the pipeline runs cleanly."""
    monkeypatch.setattr(
        "gha_sec_feed_eval.cli.http_get",
        _stub_get_returning_fixture,
    )
    monkeypatch.setenv("GSFE_OFFLINE", "1")
    rc = main([
        "--feed-url", "https://raw.githubusercontent.com/qte77/gha-sec-feed/main/data/feed.jsonl",
        "--output-dir", str(tmp_path),
        "--categories-file", "categories/default.yaml",
    ])
    assert rc == 0
    assert (tmp_path / "priority.jsonl").exists()


def test_main_overrides_feed_url_via_flag(monkeypatch, tmp_path):
    captured: list[str] = []

    def _capturing_get(url: str) -> bytes:
        captured.append(url)
        return _FIXTURE_BYTES

    monkeypatch.setattr("gha_sec_feed_eval.cli.http_get", _capturing_get)
    monkeypatch.setenv("GSFE_OFFLINE", "1")
    main([
        "--feed-url", "https://api.github.com/feed.jsonl",
        "--output-dir", str(tmp_path),
    ])
    assert captured[0] == "https://api.github.com/feed.jsonl"


def test_main_returns_nonzero_on_schema_drift(monkeypatch, tmp_path):
    """A schema_version drift in the fetched feed must surface as a
    non-zero exit code rather than a silent empty output."""
    bad_feed = json.dumps({
        **json.loads(_FIXTURE_BYTES.splitlines()[0]),
        "schema_version": "2.0.0",
    }).encode("utf-8")
    monkeypatch.setattr("gha_sec_feed_eval.cli.http_get", lambda _u: bad_feed)
    monkeypatch.setenv("GSFE_OFFLINE", "1")
    rc = main([
        "--feed-url", "https://raw.githubusercontent.com/qte77/gha-sec-feed/main/data/feed.jsonl",
        "--output-dir", str(tmp_path),
    ])
    assert rc != 0


def test_main_help_does_not_crash(capsys):
    """`--help` exits with SystemExit(0) and prints usage to stdout."""
    with pytest.raises(SystemExit) as excinfo:
        main(["--help"])
    assert excinfo.value.code == 0
    captured = capsys.readouterr()
    assert "feed-url" in captured.out


# MARK: --input-file (local-fixture path bypassing http_client)


def test_main_input_file_bypasses_http_client(monkeypatch, tmp_path):
    """`--input-file PATH` reads a local fixture instead of calling
    http_client. Required for `make smoke` to work without the producer
    ship (#6) and without a separate fixture-server harness."""

    def _fail_if_called(_url):
        raise AssertionError("http_get must not be called when --input-file is set")

    monkeypatch.setattr("gha_sec_feed_eval.cli.http_get", _fail_if_called)
    monkeypatch.setenv("GSFE_OFFLINE", "1")
    rc = main([
        "--input-file", str(_FIXTURE_PATH),
        "--output-dir", str(tmp_path),
    ])
    assert rc == 0
    assert (tmp_path / "priority.jsonl").exists()


def test_main_input_file_records_path_as_input_source(monkeypatch, tmp_path):
    """priority-meta.json's input_source field must reflect the actual
    input — the local file path, not the default feed URL — so audit
    trails are accurate."""
    monkeypatch.setattr(
        "gha_sec_feed_eval.cli.http_get",
        lambda _u: (_ for _ in ()).throw(AssertionError("not used")),
    )
    monkeypatch.setenv("GSFE_OFFLINE", "1")
    main([
        "--input-file", str(_FIXTURE_PATH),
        "--output-dir", str(tmp_path),
    ])
    meta = json.loads((tmp_path / "priority-meta.json").read_text(encoding="utf-8"))
    assert meta["input_source"] == str(_FIXTURE_PATH)


def test_main_input_file_missing_returns_nonzero(monkeypatch, tmp_path):
    monkeypatch.setenv("GSFE_OFFLINE", "1")
    rc = main([
        "--input-file", str(tmp_path / "does-not-exist.jsonl"),
        "--output-dir", str(tmp_path / "out"),
    ])
    assert rc != 0


def test_main_rejects_both_feed_url_and_input_file(monkeypatch, tmp_path):
    """--feed-url and --input-file are mutually exclusive — silently
    preferring one would mask operator confusion."""
    monkeypatch.setenv("GSFE_OFFLINE", "1")
    with pytest.raises(SystemExit):
        main([
            "--feed-url", "https://example.com/feed.jsonl",
            "--input-file", str(_FIXTURE_PATH),
            "--output-dir", str(tmp_path),
        ])
