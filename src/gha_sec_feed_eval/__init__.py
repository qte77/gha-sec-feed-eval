"""gha-sec-feed-eval: evaluator for the gha-sec-feed C1 JSONL feed.

Reads C1 rows, applies category filters, scores each row 0-10 on the
locked priority formula, enriches with MITRE ATT&CK + D3FEND, and emits
the C2 JSONL output plus a Markdown report.
"""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("gha-sec-feed-eval")
except PackageNotFoundError:  # pragma: no cover
    __version__ = "0.0.0"

__all__ = ["__version__"]
