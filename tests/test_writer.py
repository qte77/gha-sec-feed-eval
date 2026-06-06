"""Red-phase tests for `gha_sec_feed_eval.writer`.

`write_outputs(rows, output_dir, *, input_source, categories_used,
last_run=None)` emits the three deliverables expected downstream:

* `priority.jsonl` — one C2 row per line, in input order
* `priority-meta.json` — `Meta` envelope with counts / sources / timestamp
* `REPORT.md` — basic Markdown report; polish lands in Phase 2c (#4)

Phase 2b — module 9.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime

from gha_sec_feed_eval.models import PriorityRow
from gha_sec_feed_eval.writer import build_meta, write_outputs

_NOW = datetime(2026, 5, 31, 12, 0, tzinfo=UTC)


def _priority(
    cve_id: str,
    *,
    score: float = 9.0,
    category: str = "act_now",
    source: str = "nvd",
) -> PriorityRow:
    return PriorityRow.model_validate(
        {
            "id": cve_id,
            "source": source,
            "published": "2026-05-31T00:00:00Z",
            "severity": "critical",
            "cvss": 9.8,
            "epss": 0.87,
            "kev": True,
            "refs": [f"https://nvd.nist.gov/vuln/detail/{cve_id}"],
            "priority_score": score,
            "priority_category": category,
            "attack_techniques": ["T1190"],
            "d3fend_countermeasures": ["D3-NTA"],
            "matched_categories": ["python"],
            "schema_version": "1.0.0",
        }
    )


def _sample_rows() -> list[PriorityRow]:
    return [
        _priority("CVE-2026-00001", score=9.5, category="act_now"),
        _priority("CVE-2026-00002", score=6.0, category="this_week", source="ghsa"),
        _priority("CVE-2026-00003", score=3.0, category="monitor", source="osv"),
        _priority("CVE-2026-00004", score=8.2, category="act_now"),
        _priority("CVE-2026-00005", score=2.0, category="monitor", source="ghsa"),
    ]


# MARK: build_meta


def test_build_meta_counts_categories_correctly():
    rows = _sample_rows()
    meta = build_meta(
        rows,
        input_source="https://example.com/feed.jsonl",
        categories_used="categories/default.yaml",
        last_run=_NOW,
    )
    assert meta.total == 5
    assert meta.by_category == {"act_now": 2, "this_week": 1, "monitor": 2}
    assert meta.by_source == {"nvd": 2, "ghsa": 2, "osv": 1}
    assert meta.input_source == "https://example.com/feed.jsonl"
    assert meta.last_run == _NOW


def test_build_meta_empty_rows_returns_zero_counts():
    meta = build_meta(
        [],
        input_source="https://example.com/feed.jsonl",
        categories_used="categories/default.yaml",
        last_run=_NOW,
    )
    assert meta.total == 0
    assert meta.by_category == {}
    assert meta.by_source == {}


# MARK: priority.jsonl


def test_priority_jsonl_one_line_per_row_in_input_order(tmp_path):
    rows = _sample_rows()
    write_outputs(
        rows,
        output_dir=tmp_path,
        input_source="https://example.com/feed.jsonl",
        categories_used="categories/default.yaml",
        last_run=_NOW,
    )
    text = (tmp_path / "priority.jsonl").read_text(encoding="utf-8")
    lines = [line for line in text.splitlines() if line.strip()]
    assert len(lines) == 5
    parsed_ids = [json.loads(line)["id"] for line in lines]
    assert parsed_ids == [row.id for row in rows]


def test_priority_jsonl_lines_round_trip_to_priorityrow(tmp_path):
    rows = _sample_rows()
    write_outputs(
        rows,
        output_dir=tmp_path,
        input_source="https://example.com/feed.jsonl",
        categories_used="categories/default.yaml",
        last_run=_NOW,
    )
    text = (tmp_path / "priority.jsonl").read_text(encoding="utf-8")
    for raw_line in text.splitlines():
        if not raw_line.strip():
            continue
        PriorityRow.model_validate_json(raw_line)


def test_priority_jsonl_empty_when_no_rows(tmp_path):
    write_outputs(
        [],
        output_dir=tmp_path,
        input_source="https://example.com/feed.jsonl",
        categories_used="categories/default.yaml",
        last_run=_NOW,
    )
    text = (tmp_path / "priority.jsonl").read_text(encoding="utf-8")
    assert text == ""


# MARK: priority-meta.json


def test_priority_meta_is_valid_json_and_loads_as_meta(tmp_path):
    """Round-trip: write_outputs emits priority-meta.json that loads
    back through the Meta pydantic schema. Also pins the consumer-facing
    C1 compat range — removing this field silently breaks downstream
    integrations that read priority-meta.json to learn what feeds are
    accepted."""
    from gha_sec_feed_eval.models import Meta

    write_outputs(
        _sample_rows(),
        output_dir=tmp_path,
        input_source="https://example.com/feed.jsonl",
        categories_used="categories/default.yaml",
        last_run=_NOW,
    )
    text = (tmp_path / "priority-meta.json").read_text(encoding="utf-8")
    meta = Meta.model_validate_json(text)
    assert meta.total == 5
    assert meta.accepted_c1_schema_versions == ["1.0.0", "1.1.0"]


# MARK: REPORT.md


def test_report_md_contains_three_bucket_sections(tmp_path):
    write_outputs(
        _sample_rows(),
        output_dir=tmp_path,
        input_source="https://example.com/feed.jsonl",
        categories_used="categories/default.yaml",
        last_run=_NOW,
    )
    report = (tmp_path / "REPORT.md").read_text(encoding="utf-8")
    for heading in ("## Act-Now", "## This-Week", "## Monitor"):
        assert heading in report


def test_report_md_shows_per_bucket_counts_in_headings(tmp_path):
    """Each bucket section heading carries the row count: with the 5-row
    sample the splits are act_now=2, this_week=1, monitor=2. The heading
    format itself is firmed up in Phase 2c (#4); this test fails if the
    count is missing OR a future regression mis-buckets a row."""
    write_outputs(
        _sample_rows(),
        output_dir=tmp_path,
        input_source="https://example.com/feed.jsonl",
        categories_used="categories/default.yaml",
        last_run=_NOW,
    )
    report = (tmp_path / "REPORT.md").read_text(encoding="utf-8")
    assert "## Act-Now (2)" in report
    assert "## This-Week (1)" in report
    assert "## Monitor (2)" in report


def test_report_md_contains_every_cve_id(tmp_path):
    rows = _sample_rows()
    write_outputs(
        rows,
        output_dir=tmp_path,
        input_source="https://example.com/feed.jsonl",
        categories_used="categories/default.yaml",
        last_run=_NOW,
    )
    report = (tmp_path / "REPORT.md").read_text(encoding="utf-8")
    for row in rows:
        assert row.id in report


def test_report_md_frontmatter_satisfies_md041(tmp_path):
    """Markdownlint MD041 requires a title — frontmatter `title:` field
    satisfies the rule per .markdownlint.json."""
    write_outputs(
        _sample_rows(),
        output_dir=tmp_path,
        input_source="https://example.com/feed.jsonl",
        categories_used="categories/default.yaml",
        last_run=_NOW,
    )
    report = (tmp_path / "REPORT.md").read_text(encoding="utf-8")
    assert report.startswith("---\n")
    assert "title:" in report.split("---", 2)[1]


# MARK: output dir handling


def test_output_dir_created_when_missing(tmp_path):
    target = tmp_path / "nested" / "deep" / "output"
    write_outputs(
        _sample_rows(),
        output_dir=target,
        input_source="https://example.com/feed.jsonl",
        categories_used="categories/default.yaml",
        last_run=_NOW,
    )
    assert (target / "priority.jsonl").exists()
    assert (target / "priority-meta.json").exists()
    assert (target / "REPORT.md").exists()


# MARK: defaults


def test_last_run_defaults_to_utc_now_when_omitted(monkeypatch, tmp_path):
    """Omitting last_run uses datetime.now(UTC) — verify the written
    timestamp is within a tight window around 'now'."""
    write_outputs(
        _sample_rows(),
        output_dir=tmp_path,
        input_source="https://example.com/feed.jsonl",
        categories_used="categories/default.yaml",
    )
    text = (tmp_path / "priority-meta.json").read_text(encoding="utf-8")
    last_run_str = json.loads(text)["last_run"]
    last_run = datetime.fromisoformat(last_run_str.replace("Z", "+00:00"))
    delta = (datetime.now(UTC) - last_run).total_seconds()
    assert 0 <= delta < 10
