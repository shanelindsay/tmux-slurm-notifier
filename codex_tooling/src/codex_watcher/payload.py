from __future__ import annotations

from pathlib import Path
from typing import List, Optional

import re


def find_parent_issue_number(issue_body: str) -> Optional[int]:
    if not issue_body:
        return None
    match = re.search(r"(?im)^\s*parent\s*[:\-]?\s*#(\d+)\s*$", issue_body)
    if match:
        return int(match.group(1))
    for line in issue_body.splitlines():
        if re.search(r"(?i)\bparent\b", line):
            match_line = re.search(r"#(\d+)", line)
            if match_line:
                return int(match_line.group(1))
    return None


def build_job_input(
    repo: str,
    issue: dict,
    comments: List[dict],
    parent: Optional[dict],
    trigger_comment: dict,
    resume: bool,
) -> str:
    header = [
        f"REPO: {repo}",
        f"ISSUE: #{issue['number']} - {issue.get('title', '').strip()}",
        f"TRIGGERED_BY: comment_id={trigger_comment.get('id')} by @{trigger_comment.get('user', {}).get('login', '')} at {trigger_comment.get('created_at')}",
        f"MODE: {'RESUME' if resume else 'NEW'}",
        "",
        "=== INITIAL INSTRUCTIONS (SYSTEM) ===",
        "1) Read the 'ISSUE BODY', 'PARENT ISSUE BODY' (if present), and 'ISSUE COMMENTS'.",
        "2) Follow the instructions contained in the issue (and parent if relevant).",
        "3) Perform the requested work, and provide your output.",
        "",
        "=== ISSUE BODY ===",
        issue.get("body") or "(no body)",
        "",
    ]

    if parent is not None:
        header.extend(
            [
                "=== PARENT ISSUE BODY ===",
                f"(Parent issue #{parent.get('number')}: {parent.get('title', '').strip()})",
                parent.get("body") or "(no body)",
                "",
            ]
        )

    header.append("=== ISSUE COMMENTS (chronological) ===")
    for comment in sorted(comments, key=lambda x: x.get("created_at", "")):
        who = comment.get("user", {}).get("login", "unknown")
        when = comment.get("created_at", "?")
        body = comment.get("body", "").rstrip()
        header.append(f"[{when}] @{who}:")
        header.append(body)
        header.append("")

    return "\n".join(header)


def postprocess_stdout(out: str, codex_cmd: str) -> str:
    if not out:
        return out
    try:
        cmd_name = Path(codex_cmd).name.lower()
    except Exception:
        cmd_name = codex_cmd.lower()

    if cmd_name != "codex":
        return out

    lower = out.lower()
    tokens_idx = lower.rfind("tokens used")
    if tokens_idx == -1:
        return out.strip()

    prefix = out[:tokens_idx].rstrip()
    marker_idx = prefix.lower().rfind("\ncodex\n")
    if marker_idx == -1:
        marker_idx = prefix.lower().rfind("\nthinking\n")
    if marker_idx == -1:
        marker_idx = 0
    else:
        marker_idx = marker_idx + prefix[marker_idx:].find("\n") + 1

    trimmed = prefix[marker_idx:].strip()
    lines = trimmed.splitlines()
    if lines and lines[0].strip().lower() == "codex":
        lines = lines[1:]

    return "\n".join(lines).strip() or out.strip()


def format_result_comment(ok: bool, run_id: str, returncode: int, out: str, err: str) -> str:
    out = (out or "").strip()
    err = (err or "").strip()

    if ok and out:
        return out

    if not ok:
        body = err or out or "(no output)"
        return f"```\n{body}\n```\n\n_exit code: {returncode}_"

    if out:
        return out
    if err:
        return f"```\n{err}\n```"
    return f"(run {run_id} exited with code {returncode} without producing output)"
