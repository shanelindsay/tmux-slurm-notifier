"""Legacy entrypoint preserved for backward compatibility."""
from __future__ import annotations

import sys
from pathlib import Path

_pkg_root = Path(__file__).resolve().parents[3] / "codex_tooling" / "src"
if str(_pkg_root) not in sys.path:
    sys.path.insert(0, str(_pkg_root))

from codex_watcher.watch_multi import *  # noqa: F401,F403,E402
