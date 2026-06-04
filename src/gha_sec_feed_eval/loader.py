"""C1 JSONL loader — parse + validate already-fetched feed text.

HTTP fetching is the responsibility of `http_client.py`; this module
operates on a JSONL string. The pinned C1 schema version is enforced
here: any drift in `schema_version` raises SchemaVersionError so the
caller stops loudly rather than silently shipping garbage downstream.
"""

from __future__ import annotations

import json

from pydantic import ValidationError

from gha_sec_feed_eval.models import FeedRow

_PINNED_SCHEMA_VERSION = "1.0.0"


class LoaderError(Exception):
    """Base class for loader-emitted errors. Catch this for blanket handling."""


class SchemaVersionError(LoaderError):
    """C1 row drifted from the pinned schema version — stop and reconcile."""


def _is_blank(line: str) -> bool:
    return not line.strip()


def _parse_line(line: str, line_no: int) -> FeedRow:
    try:
        payload = json.loads(line)
    except json.JSONDecodeError as exc:
        msg = f"line {line_no}: invalid JSON ({exc.msg})"
        raise LoaderError(msg) from exc

    observed_version = payload.get("schema_version")
    if observed_version != _PINNED_SCHEMA_VERSION:
        msg = (
            f"line {line_no}: schema_version {observed_version!r} drifted from"
            f" pinned {_PINNED_SCHEMA_VERSION!r}"
        )
        raise SchemaVersionError(msg)

    try:
        return FeedRow.model_validate(payload)
    except ValidationError as exc:
        msg = f"line {line_no}: FeedRow validation failed ({exc.error_count()} errors)"
        raise LoaderError(msg) from exc


def parse_feed(text: str) -> list[FeedRow]:
    """Parse a JSONL feed text into a list of FeedRow.

    Blank or whitespace-only lines are skipped. The first invalid line
    raises; subsequent lines are not parsed.
    """
    rows: list[FeedRow] = []
    for line_no, raw_line in enumerate(text.splitlines(), start=1):
        if _is_blank(raw_line):
            continue
        rows.append(_parse_line(raw_line, line_no))
    return rows
