from __future__ import annotations

from typing import Optional

from .runner import main as _main


def main(_argv: Optional[list[str]] = None) -> None:
    """Entry point used by console scripts."""
    _main()


if __name__ == "__main__":  # pragma: no cover
    main()
