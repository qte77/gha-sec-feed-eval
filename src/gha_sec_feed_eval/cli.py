"""End-to-end orchestrator + argparse entry point.

`run(settings, *, http_get)` is the dependency-injectable pipeline.
`main(argv)` is the argparse adapter — keeps the orchestration testable
in isolation while the argparse pathway has its own coverage.
"""

from __future__ import annotations

import argparse
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING

from gha_sec_feed_eval.config import AppSettings
from gha_sec_feed_eval.enrich.attack import AttackMapping, load_attack_mapping
from gha_sec_feed_eval.enrich.d3fend import D3fendMapping, load_d3fend_mapping
from gha_sec_feed_eval.enrich.epss import resolve_epss
from gha_sec_feed_eval.filter import load_categories, matched_categories
from gha_sec_feed_eval.http_client import get as http_get
from gha_sec_feed_eval.loader import LoaderError, parse_feed
from gha_sec_feed_eval.models import FeedRow, PriorityRow
from gha_sec_feed_eval.scoring import priority_category, priority_score
from gha_sec_feed_eval.writer import write_outputs

if TYPE_CHECKING:
    from collections.abc import Callable


def _enrich_row(
    row: FeedRow,
    *,
    matches: list[str],
    attack: AttackMapping,
    d3fend: D3fendMapping,
    epss: float | None,
    now: datetime,
) -> PriorityRow:
    techniques = attack.lookup(row.id)
    countermeasures: list[str] = []
    for tid in techniques:
        for cm in d3fend.lookup(tid):
            if cm not in countermeasures:
                countermeasures.append(cm)
    score_row = row.model_copy(update={"epss": epss})
    score = priority_score(score_row, now=now)
    return PriorityRow.model_validate({
        **row.model_dump(mode="json"),
        "epss": epss,
        "priority_score": score,
        "priority_category": priority_category(score).value,
        "attack_techniques": techniques,
        "d3fend_countermeasures": countermeasures,
        "matched_categories": matches,
    })


def run(
    settings: AppSettings,
    *,
    http_get: Callable[[str], bytes],
    input_file: Path | None = None,
) -> None:
    """Execute the C1 → C2 pipeline using `settings` + injected fetcher.

    When `input_file` is provided, the C1 feed is read from disk instead
    of fetched via `http_get`. The local-fixture path is used by
    `make smoke` so the dev loop doesn't require a live producer (see #6).
    """
    if input_file is not None:
        feed_bytes = input_file.read_bytes()
        input_source = str(input_file)
    else:
        feed_bytes = http_get(settings.feed_url)
        input_source = settings.feed_url
    rows = parse_feed(feed_bytes.decode("utf-8"))

    categories = load_categories(settings.categories_file)
    attack = load_attack_mapping(settings.attack_data_path)
    d3fend = load_d3fend_mapping(settings.d3fend_data_path)

    now = datetime.now(UTC)
    output: list[PriorityRow] = []
    for row in rows:
        matches = matched_categories(row, categories)
        if not matches:
            continue
        epss = resolve_epss(row, http_get=http_get)
        output.append(
            _enrich_row(
                row, matches=matches, attack=attack, d3fend=d3fend,
                epss=epss, now=now,
            )
        )

    write_outputs(
        output,
        output_dir=settings.data_dir,
        input_source=input_source,
        categories_used=str(settings.categories_file),
        last_run=now,
    )


def _build_argparser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="gha_sec_feed_eval",
        description="Evaluate a gha-sec-feed C1 JSONL feed.",
    )
    # `--feed-url` (HTTP-fetched) vs `--input-file` (read locally) are
    # mutually exclusive — silently preferring one would hide operator
    # confusion.
    source = p.add_mutually_exclusive_group()
    source.add_argument("--feed-url", help="C1 source URL (overrides GSFE_FEED_URL)")
    source.add_argument(
        "--input-file",
        type=Path,
        help="Read C1 JSONL from a local file instead of fetching (local dev / `make smoke`)",
    )
    p.add_argument(
        "--output-dir",
        type=Path,
        help="Where to write priority.jsonl / -meta / REPORT.md (overrides GSFE_DATA_DIR)",
    )
    p.add_argument(
        "--categories-file",
        type=Path,
        help="Categories override YAML (overrides GSFE_CATEGORIES_FILE)",
    )
    return p


def _settings_from_args(args: argparse.Namespace) -> AppSettings:
    overrides: dict = {}
    if args.feed_url is not None:
        overrides["feed_url"] = args.feed_url
    if args.output_dir is not None:
        overrides["data_dir"] = args.output_dir
    if args.categories_file is not None:
        overrides["categories_file"] = args.categories_file
    return AppSettings(**overrides)


def main(argv: list[str] | None = None) -> int:
    """Entry point for argparse — returns a Unix exit code."""
    args = _build_argparser().parse_args(argv)
    settings = _settings_from_args(args)
    try:
        run(settings, http_get=http_get, input_file=args.input_file)
    except LoaderError as exc:
        print(f"error: feed loader failed: {exc}", file=sys.stderr)
        return 2
    except FileNotFoundError as exc:
        print(f"error: input file not found: {exc}", file=sys.stderr)
        return 2
    return 0
