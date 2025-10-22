from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Dict

from .utils import _iso


class State:
    """JSON-backed persistence for per-repository watcher state."""

    def __init__(self, path: Path):
        self.path = str(path)
        self.data: Dict[str, Dict] = {"repos": {}}
        self._load()

    def _load(self) -> None:
        try:
            with open(self.path, "r", encoding="utf-8") as fh:
                loaded = json.load(fh)
            if isinstance(loaded, dict):
                self.data.update(loaded)
        except FileNotFoundError:
            pass

    def ensure_repo(self, repo: str, path: Path) -> None:
        repos = self.data.setdefault("repos", {})
        if repo not in repos:
            repos[repo] = {
                "path": str(path),
                "last_since": _iso(_now_utc_dt_offset(days=7)),
                "processed_comment_ids": [],
                "runs": {},
                "issue_runs": {},
            }
        else:
            entry = repos[repo]
            entry["path"] = str(path)
            entry.setdefault("processed_comment_ids", [])
            entry.setdefault("runs", {})
            entry.setdefault("issue_runs", {})

    def save(self) -> None:
        tmp = f"{self.path}.tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(self.data, fh, indent=2)
        os.replace(tmp, self.path)


def _now_utc_dt_offset(**delta_kwargs):
    import datetime as _dt

    return _dt.datetime.utcnow() - _dt.timedelta(**delta_kwargs)


class SingleInstanceLock:
    """Advisory lock that prevents multiple watcher instances from running."""

    def __init__(self, path: Path):
        self.path = str(path)
        self._fd = None

    def acquire(self) -> None:
        import fcntl

        self._fd = open(self.path, "w")
        try:
            fcntl.flock(self._fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self._fd.write(str(os.getpid()))
            self._fd.flush()
        except BlockingIOError:
            sys.exit(f"Another codex watcher instance is running (lock: {self.path}).")

    def release(self) -> None:
        if not self._fd:
            return
        import fcntl

        try:
            fcntl.flock(self._fd, fcntl.LOCK_UN)
        finally:
            self._fd.close()
