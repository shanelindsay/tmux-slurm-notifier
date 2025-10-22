from __future__ import annotations

import re
import subprocess
from pathlib import Path
from typing import List, Optional, Tuple

from .config import Config
from .utils import _build_subprocess_env, _strip_ansi


def run_external(
    codex_cmd: str,
    codex_args: List[str],
    payload: Optional[str],
    timeout: int,
    cwd: Path,
) -> Tuple[int, str, str]:
    try:
        proc = subprocess.run(
            [codex_cmd] + codex_args,
            input=(payload.encode("utf-8") if payload is not None else None),
            capture_output=True,
            timeout=timeout,
            cwd=str(cwd),
            env=_build_subprocess_env(cwd),
        )
        out = _strip_ansi(proc.stdout.decode("utf-8", errors="replace"))
        err = _strip_ansi(proc.stderr.decode("utf-8", errors="replace"))
        max_chars = 60000
        if len(out) > max_chars:
            out = out[:max_chars] + "\n\n[output truncated]"
        if len(err) > max_chars:
            err = err[:max_chars] + "\n\n[stderr truncated]"
        return proc.returncode, out, err
    except subprocess.TimeoutExpired:
        return 124, "", f"Process timed out after {timeout}s."
    except FileNotFoundError:
        return 127, "", f"Command not found or not executable: {codex_cmd}"
    except Exception as exc:  # pragma: no cover - defensive
        return 125, "", f"Unexpected error: {exc!r}"


_RUN_ID_PATTERNS = [
    re.compile(r"(?im)\b(?:run[ _-]?id|session)\s*[:=]\s*([A-Za-z0-9._-]{6,})"),
    re.compile(r"(?im)\bresume\s+with:?\s*codex\s+resume\s+([A-Za-z0-9._-]{6,})"),
    re.compile(r"(?im)\"id\"\s*:\s*\"([A-Za-z0-9._-]{6,})\""),
]


def extract_codex_run_id(text: str) -> Optional[str]:
    blob = text or ""
    for pattern in _RUN_ID_PATTERNS:
        match = pattern.search(blob)
        if match:
            return match.group(1)
    return None


def extract_intent(text: str) -> Tuple[str, Optional[str]]:
    snippet = text or ""
    if re.search(r"(?i)\bcodexe\b.*\bnew\b", snippet):
        return "new", None
    resume_match = re.search(
        r"(?i)\bcodexe\b.*\bresume\b(?:\s+([A-Za-z0-9._-]{6,}))?",
        snippet,
    )
    if resume_match:
        return "resume", resume_match.group(1)
    return "default", None


def decide_codex_invocation(
    cfg: Config,
    intent: str,
    requested_id: Optional[str],
    stored_id: Optional[str],
) -> Tuple[List[str], bool, bool, Optional[str]]:
    intent = intent or "default"

    if intent == "new":
        return cfg.codex_args, True, False, None

    if intent == "resume":
        target_id = requested_id or stored_id
        if target_id:
            return cfg.codex_resume_args + [target_id], cfg.resume_send_context, True, target_id
        return cfg.codex_args, True, False, None

    if stored_id and cfg.default_resume:
        return cfg.codex_resume_args + [stored_id], cfg.resume_send_context, True, stored_id

    return cfg.codex_args, True, False, None



def extract_resume_flag(text: str) -> bool:
    return bool(re.search(r"(?i)\bresume\b", text or ""))
