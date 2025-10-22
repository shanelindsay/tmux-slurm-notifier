"""Codex watcher package.

This package exposes the multi-repository POSIS watcher that previously lived
under ``dev/s/posis``. Public names mirror the legacy module so that existing
code can import from ``codex_watcher`` without behavioural changes.
"""
from .config import Config
from .discovery import discover_git_remote, discover_local_repos, parse_github_owner_repo
from .github import GitHub
from .state import SingleInstanceLock, State
from .codex import (
    decide_codex_invocation,
    extract_codex_run_id,
    extract_intent,
    extract_resume_flag,
    run_external,
)
from .payload import (
    build_job_input,
    find_parent_issue_number,
    format_result_comment,
    postprocess_stdout,
)
from .runner import main, run_loop
from .utils import _build_subprocess_env, _compute_new_since

__all__ = [
    "Config",
    "GitHub",
    "State",
    "SingleInstanceLock",
    "discover_git_remote",
    "discover_local_repos",
    "parse_github_owner_repo",
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
]
