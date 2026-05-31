"""Module entry point — `python -m gha_sec_feed_eval`.

Delegates to :func:`gha_sec_feed_eval.cli.main`. The cli module lands
in phase 2b; until then this raises a clear error rather than failing
silently.
"""

from __future__ import annotations

import sys


def main() -> int:
    """Entry point. Implemented in phase 2b."""
    raise NotImplementedError(
        "gha_sec_feed_eval.cli.main lands in phase 2b. "
        "See docs/architecture.md for the planned CLI shape."
    )


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
