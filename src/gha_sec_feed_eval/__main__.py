"""Module entry point: `python -m gha_sec_feed_eval`.

Delegates to :func:`gha_sec_feed_eval.cli.main`.
"""

from __future__ import annotations

import sys

from gha_sec_feed_eval.cli import main

if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
