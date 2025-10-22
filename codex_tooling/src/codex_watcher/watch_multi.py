"""Backward compatible surface for the multi-repo watcher.

Historically the code lived in ``dev/s/posis/posis_watch_multi.py``.  This module
collects and re-exports the same symbols so existing imports continue to work
while the implementation lives in a structured package.
"""
import subprocess as _subprocess

from .codex import (
    decide_codex_invocation,
    extract_codex_run_id,
    extract_intent,
    extract_resume_flag,
    run_external,
)
from .config import Config
from .discovery import discover_git_remote, discover_local_repos, parse_github_owner_repo
from .payload import build_job_input, find_parent_issue_number, format_result_comment, postprocess_stdout
from .github import GitHub
from .runner import main, run_loop
from .state import SingleInstanceLock, State
from .utils import _build_subprocess_env, _compute_new_since

subprocess = _subprocess

__all__ = [
    "Config",
    "GitHub",
    "State",
    "SingleInstanceLock",
    "discover_git_remote",
    "parse_github_owner_repo",
    "discover_local_repos",
    "find_parent_issue_number",
    "build_job_input",
    "run_external",
    "postprocess_stdout",
    "extract_codex_run_id",
    "extract_intent",
    "decide_codex_invocation",
    "format_result_comment",
    "extract_resume_flag",
    "main",
    "run_loop",
    "_compute_new_since",
    "_build_subprocess_env",
    "subprocess",
]
