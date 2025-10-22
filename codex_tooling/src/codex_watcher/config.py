from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import List


@dataclass
class Config:
    """Runtime configuration loaded from environment variables."""

    token: str
    root: Path
    recursive: bool = field(default_factory=lambda: os.getenv("POSIS_RECURSIVE", "0") == "1")
    regex: str = field(default_factory=lambda: os.getenv("POSIS_REGEX", r"codexe"))
    match_target: str = field(default_factory=lambda: os.getenv("POSIS_MATCH_TARGET", "comments"))
    poll_seconds: int = field(default_factory=lambda: int(os.getenv("POSIS_POLL_SECONDS", "20")))
    per_repo_pause: float = field(default_factory=lambda: float(os.getenv("POSIS_PER_REPO_PAUSE", "0.3")))
    state_path: Path = field(default=None)  # type: ignore[assignment]
    codex_cmd: str = field(default_factory=lambda: os.getenv("CODEX_CMD", "codex"))
    codex_args: List[str] = field(default_factory=lambda: os.getenv("CODEX_ARGS", "exec -").split())
    codex_resume_args: List[str] = field(default_factory=lambda: os.getenv("CODEX_RESUME_ARGS", "resume").split())
    codex_timeout: int = field(default_factory=lambda: int(os.getenv("CODEX_TIMEOUT", "3600")))
    lockfile: Path = field(default=None)  # type: ignore[assignment]
    require_marker: bool = field(default_factory=lambda: os.getenv("POSIS_REQUIRE_MARKER", "0") == "1")
    exclude_dirs: List[str] = field(
        default_factory=lambda: [s for s in os.getenv("POSIS_EXCLUDE_DIRS", "").split(",") if s]
    )
    ignore_self: bool = field(default_factory=lambda: os.getenv("POSIS_IGNORE_SELF", "1") == "1")
    default_resume: bool = field(default_factory=lambda: os.getenv("POSIS_DEFAULT_RESUME", "1") == "1")
    resume_send_context: bool = field(default_factory=lambda: os.getenv("POSIS_RESUME_SEND_CONTEXT", "0") == "1")

    def __post_init__(self) -> None:
        if self.state_path is None:
            self.state_path = self.root / ".posis_state_multi.json"
        if self.lockfile is None:
            self.lockfile = self.root / ".posis_multi.lock"
        self.match_target = self.match_target.lower()
        if self.match_target not in {"comments", "issue_or_comments"}:
            sys.exit("POSIS_MATCH_TARGET must be 'comments' or 'issue_or_comments'.")
        if self.per_repo_pause < 0:
            self.per_repo_pause = 0.0

    @staticmethod
    def from_env() -> "Config":
        token = os.getenv("GITHUB_TOKEN", "").strip()
        if not token:
            sys.exit("GITHUB_TOKEN is required in environment.")
        root = Path(os.getenv("POSIS_ROOT", os.getcwd())).resolve()
        return Config(token=token, root=root)
