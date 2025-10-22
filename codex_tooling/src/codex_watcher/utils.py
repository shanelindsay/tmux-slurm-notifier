from __future__ import annotations

import datetime as _dt
import os
import re
from pathlib import Path
from typing import Dict, Iterable

ISO8601 = "%Y-%m-%dT%H:%M:%SZ"
_ANSI_RE = re.compile(r"\x1B\[[0-?]*[ -/]*[@-~]")
_WATERMARK_BACKOFF = _dt.timedelta(seconds=30)
_ENV_ALLOWLIST = {
    "PATH",
    "HOME",
    "SHELL",
    "LANG",
    "LC_ALL",
    "TERM",
    "TMPDIR",
    "PYTHONPATH",
}


def _now_utc() -> str:
    return _dt.datetime.utcnow().strftime(ISO8601)


def _iso(dt: _dt.datetime) -> str:
    return dt.strftime(ISO8601)


def _parse_iso(s: str) -> _dt.datetime:
    return _dt.datetime.strptime(s, ISO8601)


def _strip_ansi(text: str) -> str:
    if not text:
        return text
    return _ANSI_RE.sub("", text)


def _compute_new_since(previous: str, batches: Iterable[Iterable[dict]]) -> str:
    """Return the latest timestamp seen across batches, falling back to *previous*."""
    candidates = [previous]
    for batch in batches:
        for item in batch:
            for key in ("updated_at", "created_at"):
                ts = item.get(key)
                if ts:
                    candidates.append(ts)
    try:
        return max(candidates)
    except ValueError:
        return previous


def _build_subprocess_env(cwd: Path) -> Dict[str, str]:
    env: Dict[str, str] = {}
    for key in _ENV_ALLOWLIST:
        value = os.environ.get(key)
        if value is not None:
            env[key] = value

    for key, value in os.environ.items():
        if key.startswith("POSIS_"):
            env[key] = value

    if os.environ.get("POSIS_FORWARD_GITHUB_TOKEN") == "1":
        token = os.environ.get("GITHUB_TOKEN")
        if token:
            env["GITHUB_TOKEN"] = token

    env.setdefault("PWD", str(cwd))
    return env

__all__ = [
    "ISO8601",
    "_now_utc",
    "_iso",
    "_parse_iso",
    "_strip_ansi",
    "_compute_new_since",
    "_build_subprocess_env",
    "_WATERMARK_BACKOFF",
]
