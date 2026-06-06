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
    attack_techniques: list[str] | None = None,
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
            "attack_techniques": attack_techniques if attack_techniques is not None else ["T1190"],
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


def test_report_md_methodology_section_links_scoring_md_and_cites_cve_sentry(tmp_path):
    """Methodology section is the consumer-facing pointer to the locked
    formula spec + its citation. Both anchors must be present so neither
    can silently drift loose."""
    write_outputs(
        _sample_rows(),
        output_dir=tmp_path,
        input_source="https://example.com/feed.jsonl",
        categories_used="categories/default.yaml",
        last_run=_NOW,
    )
    report = (tmp_path / "REPORT.md").read_text(encoding="utf-8")
    assert "## Methodology" in report
    section = report.split("## Methodology")[1]
    # Markdown link target must point at docs/scoring.md (the formula spec).
    assert "docs/scoring.md" in section or "(scoring.md)" in section
    # cve-sentry citation must travel with the report verbatim.
    assert "cve-sentry" in section


def test_report_md_by_source_section_lists_each_source_with_counts_desc(tmp_path):
    """The By source section reports per-Source counts, ordered by count
    descending. Pins both the per-row aggregation and the sort direction."""
    rows = [
        _priority("CVE-2026-S1", source="nvd"),
        _priority("CVE-2026-S2", source="nvd"),
        _priority("CVE-2026-S3", source="nvd"),
        _priority("CVE-2026-S4", source="ghsa"),
        _priority("CVE-2026-S5", source="ghsa"),
        _priority("CVE-2026-S6", source="osv"),
    ]
    write_outputs(
        rows,
        output_dir=tmp_path,
        input_source="https://example.com/feed.jsonl",
        categories_used="categories/default.yaml",
        last_run=_NOW,
    )
    report = (tmp_path / "REPORT.md").read_text(encoding="utf-8")
    assert "## By source" in report
    section = report.split("## By source")[1].split("\n## ")[0]
    # Ordering by count desc: nvd (3) before ghsa (2) before osv (1).
    pos_nvd = section.find("nvd")
    pos_ghsa = section.find("ghsa")
    pos_osv = section.find("osv")
    assert 0 < pos_nvd < pos_ghsa < pos_osv
    # Each source appears with its exact count in the same line.
    for source_slug, count in [("nvd", 3), ("ghsa", 2), ("osv", 1)]:
        matching = [
            line
            for line in section.splitlines()
            if source_slug in line and f"| {count} |" in line
        ]
        assert matching, f"no row for source={source_slug!r} count={count}"


def test_report_md_top_attack_techniques_orders_by_count_desc_with_names(tmp_path):
    """Top ATT&CK section ranks techniques by occurrence count and resolves
    each ID to its canonical human name. Pins ordering + name lookup in one
    assertion path."""
    rows = [
        _priority("CVE-2026-A1", attack_techniques=["T1190"]),
        _priority("CVE-2026-A2", attack_techniques=["T1190"]),
        _priority("CVE-2026-A3", attack_techniques=["T1190", "T1078.004"]),
        _priority("CVE-2026-A4", attack_techniques=["T1078.004"]),
        _priority("CVE-2026-A5", attack_techniques=["T1059"]),
    ]
    # Expected occurrences: T1190 x 3, T1078.004 x 2, T1059 x 1.
    write_outputs(
        rows,
        output_dir=tmp_path,
        input_source="https://example.com/feed.jsonl",
        categories_used="categories/default.yaml",
        last_run=_NOW,
    )
    report = (tmp_path / "REPORT.md").read_text(encoding="utf-8")
    assert "## Top ATT&CK techniques" in report
    section = report.split("## Top ATT&CK techniques")[1].split("\n## ")[0]
    # Ordering by count descending: T1190 must appear before T1078.004 before T1059.
    pos_1190 = section.find("T1190")
    pos_1078 = section.find("T1078.004")
    pos_1059 = section.find("T1059")
    assert 0 < pos_1190 < pos_1078 < pos_1059
    # Name resolution: each row carries the canonical ATT&CK technique name.
    assert "Exploit Public-Facing Application" in section
    assert "Cloud Accounts" in section  # T1078.004
    assert "Command and Scripting Interpreter" in section  # T1059


def test_report_md_caps_bucket_rows_at_50_with_overflow_footer(tmp_path):
    """A bucket with > 50 rows is truncated to 50 in the rendered table and
    a footer line links the full data and states the total. Footer wording
    is the consumer-facing breadcrumb to data/priority.jsonl when the table
    visibly hides rows."""
    rows = [_priority(f"CVE-2026-{i:05d}", score=9.5, category="act_now") for i in range(60)]
    write_outputs(
        rows,
        output_dir=tmp_path,
        input_source="https://example.com/feed.jsonl",
        categories_used="categories/default.yaml",
        last_run=_NOW,
    )
    report = (tmp_path / "REPORT.md").read_text(encoding="utf-8")
    # Heading still reports the total bucket size (truth, not the visible cap).
    assert "## Act-Now (60)" in report
    # Exactly 50 visible CVE rows in the Act-Now section (one per markdown table row).
    act_now_section = report.split("## Act-Now")[1].split("## This-Week")[0]
    visible_ids = [f"CVE-2026-{i:05d}" for i in range(60) if f"CVE-2026-{i:05d}" in act_now_section]
    assert len(visible_ids) == 50
    # Footer links the raw JSONL and states the total so consumers know to scroll.
    assert "priority.jsonl" in act_now_section
    assert "60" in act_now_section


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
