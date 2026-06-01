"""C2 output writer — priority.jsonl + priority-meta.json + REPORT.md.

`write_outputs(rows, output_dir, *, input_source, categories_used,
last_run=None)` is the single orchestrator. Phase 2c (#4) polishes
the REPORT.md sections; this module ships the basic structure so
downstream CI + consumer wiring lands in 2b.
"""

from __future__ import annotations

from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING

from gha_sec_feed_eval.models import Meta

if TYPE_CHECKING:
    from collections.abc import Iterable

    from gha_sec_feed_eval.models import PriorityRow

_PRIORITY_JSONL = "priority.jsonl"
_PRIORITY_META = "priority-meta.json"
_REPORT_MD = "REPORT.md"


def build_meta(
    rows: Iterable[PriorityRow],
    *,
    input_source: str,
    categories_used: str,
    last_run: datetime,
) -> Meta:
    """Aggregate per-row PriorityCategory + Source counts into a Meta envelope."""
    materialised = list(rows)
    by_category = Counter(row.priority_category.value for row in materialised)
    by_source = Counter(row.source.value for row in materialised)
    return Meta(
        schema_version="1.0.0",
        input_schema_version="1.0.0",
        input_source=input_source,
        last_run=last_run,
        total=len(materialised),
        by_category=dict(by_category),
        by_source=dict(by_source),
        categories_used=categories_used,
    )


def _write_jsonl(rows: list[PriorityRow], path: Path) -> None:
    lines = [row.model_dump_json() for row in rows]
    payload = "\n".join(lines)
    if lines:
        payload += "\n"
    path.write_text(payload, encoding="utf-8")


def _write_meta_json(meta: Meta, path: Path) -> None:
    path.write_text(meta.model_dump_json(indent=2), encoding="utf-8")


def _bucket_rows(rows: list[PriorityRow]) -> dict[str, list[PriorityRow]]:
    buckets: dict[str, list[PriorityRow]] = {
        "act_now": [],
        "this_week": [],
        "monitor": [],
    }
    for row in rows:
        buckets[row.priority_category.value].append(row)
    return buckets


def _render_bucket_section(title: str, rows: list[PriorityRow]) -> str:
    body = [f"## {title} ({len(rows)})", ""]
    if not rows:
        body.append("_No CVEs in this bucket._")
        body.append("")
        return "\n".join(body)
    body.append("| Score | CVE | CVSS | Source | ATT&CK |")
    body.append("|---|---|---|---|---|")
    for row in rows:
        techniques = ", ".join(row.attack_techniques) or "—"
        cvss = "—" if row.cvss is None else f"{row.cvss:.1f}"
        body.append(
            f"| {row.priority_score} | {row.id} | {cvss} | {row.source.value} | {techniques} |"
        )
    body.append("")
    return "\n".join(body)


def _render_report(rows: list[PriorityRow], meta: Meta) -> str:
    buckets = _bucket_rows(rows)
    frontmatter = (
        "---\n"
        "title: Priority Report\n"
        f"updated: {meta.last_run.isoformat()}\n"
        "---\n\n"
    )
    sections = [
        f"# Priority Report ({meta.total} total)\n",
        f"Input: `{meta.input_source}` · "
        f"Categories: `{meta.categories_used}`\n",
        _render_bucket_section("Act-Now", buckets["act_now"]),
        _render_bucket_section("This-Week", buckets["this_week"]),
        _render_bucket_section("Monitor", buckets["monitor"]),
    ]
    return frontmatter + "\n".join(sections)


def _write_report(rows: list[PriorityRow], meta: Meta, path: Path) -> None:
    path.write_text(_render_report(rows, meta), encoding="utf-8")


def write_outputs(
    rows: Iterable[PriorityRow],
    output_dir: str | Path,
    *,
    input_source: str,
    categories_used: str,
    last_run: datetime | None = None,
) -> Meta:
    """Write priority.jsonl + priority-meta.json + REPORT.md into `output_dir`.

    Returns the Meta envelope written (so callers don't recompute counts).
    """
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    materialised = list(rows)
    when = last_run if last_run is not None else datetime.now(UTC)
    meta = build_meta(
        materialised,
        input_source=input_source,
        categories_used=categories_used,
        last_run=when,
    )

    _write_jsonl(materialised, out / _PRIORITY_JSONL)
    _write_meta_json(meta, out / _PRIORITY_META)
    _write_report(materialised, meta, out / _REPORT_MD)
    return meta
