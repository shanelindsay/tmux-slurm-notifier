#!/usr/bin/env python3
"""
POSIS GitHub Issue Watcher (Multi-Repo)
---------------------------------------
Watches *multiple* GitHub repositories found under a local root folder.
For each repo, it polls issue comments since the last watermark and looks
for a regex trigger in the comment text. When matched, it collects the full
issue context, optionally includes a "parent issue", runs an external command
(e.g., "codecs exec --stdin") with the context as stdin **in that repo's
working directory**, and posts the result back to the issue as a comment.

Key differences vs the single-repo watcher:
- Discovers repos by scanning a root folder for git repositories.
- Maintains per-repo state (watermarks, processed comment IDs).
- Runs the external command with cwd set to the repo's local path.
- Regex-based trigger (POSIS_REGEX), case-insensitive by default.

Environment variables
---------------------
GITHUB_TOKEN         : Personal access token with repo scope (classic) or fine-grained with issues:read/write.
POSIS_ROOT           : Local root directory that contains subfolders with git repos. Default: current working dir.
POSIS_RECURSIVE      : "1" to discover repos recursively, else only immediate children. Default: "0".
POSIS_REGEX          : Regex to match in issue comments (case-insensitive). Default: r"##codecs".
POSIS_POLL_SECONDS   : Poll interval in seconds. Default: 20.
POSIS_STATE          : Path to state file (json). Default: '<POSIS_ROOT>/.posis_state_multi.json'.
CODECS_CMD           : Path to external command to run. Default: 'codecs'.
CODECS_ARGS          : Args for the external command. Default: 'exec --stdin'.
CODECS_TIMEOUT       : Seconds before the external command is killed. Default: 3600.
POSIS_LOCKFILE       : Path to a lock file to prevent multiple concurrent watchers. Default: '<POSIS_ROOT>/.posis_multi.lock'.

Optional quality-of-life toggles
--------------------------------
POSIS_REQUIRE_MARKER : If set to "1", only watch repos that contain a file named '.posis-enabled'. Default: "0".
POSIS_EXCLUDE_DIRS   : Comma-separated directory names to skip during discovery (e.g., 'venv,node_modules'). Default: "".

Usage
-----
$ export GITHUB_TOKEN=ghp_xxx
$ export POSIS_ROOT=/path/to/upper-level
$ ./posis_watch_multi.py

Or run via tmux:
$ chmod +x tmux-start-multi.sh posis_watch_multi.py
$ ./tmux-start-multi.sh
$ tmux attach -t posis

Notes
-----
- This script polls rather than using webhooks, by design (tmux-friendly).
- Stores per-repo state to survive restarts.
- Ignores its own comments (i.e., comments authored by the authenticated account).
"""

import datetime as _dt
import json
import logging
import os
import re
import signal
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import requests

ISO8601 = "%Y-%m-%dT%H:%M:%SZ"

def _now_utc() -> str:
    return _dt.datetime.utcnow().strftime(ISO8601)

def _iso(dt: _dt.datetime) -> str:
    return dt.strftime(ISO8601)

def _parse_iso(s: str) -> _dt.datetime:
    return _dt.datetime.strptime(s, ISO8601)

def discover_git_remote(path: Path) -> Optional[str]:
    """Return the remote.origin.url for a git repo at 'path', else None."""
    try:
        url = subprocess.check_output(
            ["git", "-C", str(path), "config", "--get", "remote.origin.url"],
            text=True,
        ).strip()
        return url or None
    except Exception:
        return None

def parse_github_owner_repo(remote_url: str) -> Optional[str]:
    """
    Accept 'git@github.com:owner/repo.git' or 'https://github.com/owner/repo.git'
    and return 'owner/repo' or None.
    """
    m = re.search(r"github\.com[:/](?P<owner>[^/]+)/(?P<repo>[^/.]+)(?:\.git)?$", remote_url or "", re.I)
    if not m:
        return None
    return f"{m.group('owner')}/{m.group('repo')}"

def discover_local_repos(root: Path, recursive: bool, require_marker: bool, exclude_dirs: List[str]) -> Dict[str, Path]:
    """
    Scan 'root' for git repositories and return { 'owner/repo': local_path }.
    If recursive is False, only direct subdirectories are considered.
    If require_marker is True, only repos containing '.posis-enabled' are included.
    """
    repos: Dict[str, Path] = {}

    def consider_dir(d: Path):
        if not (d / ".git").exists():
            return
        # optional marker gate
        if require_marker and not (d / ".posis-enabled").exists():
            return
        remote = discover_git_remote(d)
        if not remote:
            return
        or_name = parse_github_owner_repo(remote)
        if not or_name:
            return
        if or_name not in repos:
            repos[or_name] = d

    if not recursive:
        for child in root.iterdir():
            if not child.is_dir():
                continue
            if child.name in exclude_dirs:
                continue
            consider_dir(child)
    else:
        for dirpath, dirnames, filenames in os.walk(root):
            # prune excluded directory names in-place
            dirnames[:] = [n for n in dirnames if n not in exclude_dirs]
            d = Path(dirpath)
            if (d / ".git").exists():
                consider_dir(d)
                # do not descend into subdirectories of a found repo
                dirnames[:] = []
                continue

    return repos

@dataclass
class Config:
    token: str
    root: Path
    recursive: bool = field(default_factory=lambda: os.getenv("POSIS_RECURSIVE", "0") == "1")
    regex: str = field(default_factory=lambda: os.getenv("POSIS_REGEX", r"##codecs"))
    poll_seconds: int = field(default_factory=lambda: int(os.getenv("POSIS_POLL_SECONDS", "20")))
    state_path: Path = field(default=None)
    codecs_cmd: str = field(default_factory=lambda: os.getenv("CODECS_CMD", "codecs"))
    codecs_args: List[str] = field(default_factory=lambda: os.getenv("CODECS_ARGS", "exec --stdin").split())
    codecs_timeout: int = field(default_factory=lambda: int(os.getenv("CODECS_TIMEOUT", "3600")))
    lockfile: Path = field(default=None)
    require_marker: bool = field(default_factory=lambda: os.getenv("POSIS_REQUIRE_MARKER", "0") == "1")
    exclude_dirs: List[str] = field(default_factory=lambda: [s for s in os.getenv("POSIS_EXCLUDE_DIRS", "").split(",") if s])

    def __post_init__(self):
        if self.state_path is None:
            self.state_path = self.root / ".posis_state_multi.json"
        if self.lockfile is None:
            self.lockfile = self.root / ".posis_multi.lock"

    @staticmethod
    def from_env() -> "Config":
        token = os.getenv("GITHUB_TOKEN", "").strip()
        if not token:
            sys.exit("GITHUB_TOKEN is required in environment.")
        root = Path(os.getenv("POSIS_ROOT", os.getcwd())).resolve()
        return Config(token=token, root=root)

class GitHub:
    def __init__(self, token: str):
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"token {token}",
            "Accept": "application/vnd.github+json",
            "User-Agent": "posis-watcher-multi/1.0",
        })
        self.api = "https://api.github.com"
        self._me = None

    def me_login(self) -> str:
        if self._me is None:
            r = self.session.get(f"{self.api}/user", timeout=30)
            r.raise_for_status()
            self._me = r.json()["login"]
        return self._me

    def list_issue_comments_since(self, repo: str, since_iso: str, per_page: int = 100) -> List[dict]:
        """List comments across all issues for a single repo since ISO time."""
        comments: List[dict] = []
        url = f"{self.api}/repos/{repo}/issues/comments"
        params = {"since": since_iso, "per_page": per_page, "page": 1}
        while True:
            r = self.session.get(url, params=params, timeout=60)
            if r.status_code == 304:
                break
            r.raise_for_status()
            batch = r.json()
            if not isinstance(batch, list):
                break
            comments.extend(batch)
            link = r.headers.get("Link", "")
            if 'rel="next"' not in link:
                break
            m = re.search(r'<([^>]+)>;\s*rel="next"', link)
            if not m:
                break
            next_url = m.group(1)
            url, params = next_url, {}
        return comments

    def get_issue(self, repo: str, number: int) -> dict:
        r = self.session.get(f"{self.api}/repos/{repo}/issues/{number}", timeout=30)
        r.raise_for_status()
        return r.json()

    def list_issue_comments(self, repo: str, number: int) -> List[dict]:
        url = f"{self.api}/repos/{repo}/issues/{number}/comments"
        out: List[dict] = []
        params = {"per_page": 100, "page": 1}
        while True:
            r = self.session.get(url, params=params, timeout=60)
            r.raise_for_status()
            batch = r.json()
            out.extend(batch)
            link = r.headers.get("Link", "")
            if 'rel="next"' not in link:
                break
            m = re.search(r'<([^>]+)>;\s*rel="next"', link)
            if not m:
                break
            next_url = m.group(1)
            url, params = next_url, {}
        return out

    def post_issue_comment(self, repo: str, number: int, body: str) -> dict:
        r = self.session.post(
            f"{self.api}/repos/{repo}/issues/{number}/comments",
            json={"body": body},
            timeout=60,
        )
        r.raise_for_status()
        return r.json()

class State:
    def __init__(self, path: Path):
        self.path = str(path)
        self.data = {
            "repos": {
                # "owner/repo": {
                #     "path": "/abs/local/path",
                #     "last_since": ISO8601,
                #     "processed_comment_ids": [],
                #     "runs": {}  # issue_number -> dict(...)
                # }
            }
        }
        self._load()

    def _load(self):
        try:
            with open(self.path, "r") as f:
                loaded = json.load(f)
            if isinstance(loaded, dict):
                self.data.update(loaded)
        except FileNotFoundError:
            pass

    def ensure_repo(self, repo: str, path: Path):
        if repo not in self.data["repos"]:
            self.data["repos"][repo] = {
                "path": str(path),
                "last_since": _iso(_dt.datetime.utcnow() - _dt.timedelta(days=7)),
                "processed_comment_ids": [],
                "runs": {},
            }
        else:
            # keep path up to date if it changed
            self.data["repos"][repo]["path"] = str(path)

    def save(self):
        tmp = self.path + ".tmp"
        with open(tmp, "w") as f:
            json.dump(self.data, f, indent=2)
        os.replace(tmp, self.path)

class SingleInstanceLock:
    def __init__(self, path: Path):
        self.path = str(path)
        self.fd = None

    def acquire(self):
        import fcntl
        self.fd = open(self.path, "w")
        try:
            fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.fd.write(str(os.getpid()))
            self.fd.flush()
        except BlockingIOError:
            sys.exit(f"Another posis_watch_multi.py instance is running (lock: {self.path}).")

    def release(self):
        if not self.fd:
            return
        import fcntl
        try:
            fcntl.flock(self.fd, fcntl.LOCK_UN)
        finally:
            self.fd.close()

def find_parent_issue_number(issue_body: str) -> Optional[int]:
    if not issue_body:
        return None
    m = re.search(r"(?im)^\s*parent\s*[:\-]?\s*#(\d+)\s*$", issue_body)
    if m:
        return int(m.group(1))
    for line in issue_body.splitlines():
        if re.search(r"(?i)\bparent\b", line):
            m2 = re.search(r"#(\d+)", line)
            if m2:
                return int(m2.group(1))
    return None

def build_job_input(repo: str, issue: dict, comments: List[dict], parent: Optional[dict], trigger_comment: dict, resume: bool) -> str:
    header = [
        f"REPO: {repo}",
        f"ISSUE: #{issue['number']} - {issue.get('title','').strip()}",
        f"TRIGGERED_BY: comment_id={trigger_comment.get('id')} by @{trigger_comment.get('user',{}).get('login','')} at {trigger_comment.get('created_at')}",
        f"MODE: {'RESUME' if resume else 'NEW'}",
        "",
        "=== INITIAL INSTRUCTIONS (SYSTEM) ===",
        "1) Read the 'ISSUE BODY', 'PARENT ISSUE BODY' (if present), and 'ISSUE COMMENTS'.",
        "2) Follow the instructions contained in the issue (and parent if relevant).",
        "3) Perform the requested work. Keep a short log of decisions made.",
        "4) On completion, produce a clear summary of what you did and any artefacts produced.",
        "5) Output a concise markdown report in under ~500 lines, starting with '## Result'.",
        "6) If you could not complete the task, state blockers and next steps succinctly.",
        "",
        "=== ISSUE BODY ===",
        issue.get("body") or "(no body)",
        "",
    ]

    if parent is not None:
        header.extend([
            "=== PARENT ISSUE BODY ===",
            f"(Parent issue #{parent.get('number')}: {parent.get('title','').strip()})",
            parent.get("body") or "(no body)",
            "",
        ])

    header.append("=== ISSUE COMMENTS (chronological) ===")
    for c in sorted(comments, key=lambda x: x.get("created_at","")):
        who = c.get("user", {}).get("login", "unknown")
        when = c.get("created_at", "?")
        body = c.get("body","").rstrip()
        header.append(f"[{when}] @{who}:")
        header.append(body)
        header.append("")

    return "\n".join(header)

def run_external(codecs_cmd: str, codecs_args: List[str], payload: str, timeout: int, cwd: Path) -> Tuple[int, str, str]:
    try:
        proc = subprocess.run(
            [codecs_cmd] + codecs_args,
            input=payload.encode("utf-8"),
            capture_output=True,
            timeout=timeout,
            cwd=str(cwd),
        )
        out = proc.stdout.decode("utf-8", errors="replace")
        err = proc.stderr.decode("utf-8", errors="replace")
        max_chars = 60000
        if len(out) > max_chars:
            out = out[:max_chars] + "\n\n[output truncated]"
        if len(err) > max_chars:
            err = err[:max_chars] + "\n\n[stderr truncated]"
        return proc.returncode, out, err
    except subprocess.TimeoutExpired:
        return 124, "", f"Process timed out after {timeout}s."
    except FileNotFoundError:
        return 127, "", f"Command not found or not executable: {codecs_cmd}"
    except Exception as e:
        return 125, "", f"Unexpected error: {e!r}"

def format_result_comment(ok: bool, run_id: str, returncode: int, out: str, err: str) -> str:
    status = "✅ Completed" if ok else "⚠️ Completed with issues" if returncode == 0 else "❌ Failed"
    header = f"POSIS run `{run_id}` status: {status}\n\n"
    body = "### Output\n```\n" + (out or "(no stdout)") + "\n```\n"
    if err.strip():
        body += "\n<details>\n<summary>stderr</summary>\n\n```\n" + err + "\n```\n</details>\n"
    footer = "\n_This comment was posted automatically by POSIS multi-repo watcher._"
    return header + body + footer

def extract_resume_flag(text: str) -> bool:
    return bool(re.search(r"(?i)\bresume\b", text or ""))

def main():
    cfg = Config.from_env()

    # Logging
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )
    log = logging.getLogger("posis-multi")

    # Single-instance lock
    lock = SingleInstanceLock(cfg.lockfile)
    lock.acquire()

    # Graceful shutdown
    stop = {"flag": False}
    def _sig(*_a):
        log.info("Signal received, shutting down...")
        stop["flag"] = True
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, _sig)

    # Discover repos from local filesystem
    log.info("Scanning for git repos under %s (recursive=%s)", cfg.root, cfg.recursive)
    repos = discover_local_repos(cfg.root, cfg.recursive, cfg.require_marker, cfg.exclude_dirs)
    if not repos:
        log.warning("No repos found. Create a git repo under %s or adjust POSIS_ROOT.", cfg.root)

    # Compile regex trigger (case-insensitive)
    try:
        trigger_re = re.compile(cfg.regex, re.I)
    except re.error as e:
        lock.release()
        sys.exit(f"Invalid POSIS_REGEX '{cfg.regex}': {e}")

    gh = GitHub(cfg.token)
    me = gh.me_login()
    log.info("Authenticated as @%s, watching %d repos, regex='%s', poll=%ss", me, len(repos), cfg.regex, cfg.poll_seconds)

    # Load (and create) per-repo state
    st = State(cfg.state_path)
    for repo, path in repos.items():
        st.ensure_repo(repo, path)
    st.save()

    # Poll loop
    while not stop["flag"]:
        try:
            # Re-discover repos periodically in case new ones are added
            # (cheap: re-scan every loop; cost is small compared to API calls)
            repos = discover_local_repos(cfg.root, cfg.recursive, cfg.require_marker, cfg.exclude_dirs)
            for repo, path in repos.items():
                st.ensure_repo(repo, path)

            for repo, meta in list(st.data["repos"].items()):
                local_path = Path(meta["path"])
                if repo not in repos:
                    # Repo disappeared locally: skip but keep state
                    continue

                since = meta.get("last_since") or _iso(_dt.datetime.utcnow() - _dt.timedelta(days=7))
                processed = set(meta.get("processed_comment_ids", []))

                comments = gh.list_issue_comments_since(repo, since)
                # Update watermark to now (double-guarded by processed_comment_ids)
                meta["last_since"] = _now_utc()

                for c in sorted(comments, key=lambda x: x.get("created_at","")):
                    cid = c.get("id")
                    if cid in processed:
                        continue
                    body = (c.get("body") or "")

                    # Ignore our own comments to prevent loops
                    author = c.get("user", {}).get("login", "")
                    if author == me:
                        meta.setdefault("processed_comment_ids", []).append(cid)
                        processed.add(cid)
                        continue

                    # Regex match
                    if not trigger_re.search(body):
                        meta.setdefault("processed_comment_ids", []).append(cid)
                        processed.add(cid)
                        continue

                    # Determine issue number
                    issue_url = c.get("issue_url","")
                    m = re.search(r"/issues/(\d+)$", issue_url)
                    if not m:
                        meta.setdefault("processed_comment_ids", []).append(cid)
                        processed.add(cid)
                        continue
                    number = int(m.group(1))

                    issue = gh.get_issue(repo, number)
                    if "pull_request" in issue:
                        # Skip PRs; watcher is for issues
                        meta.setdefault("processed_comment_ids", []).append(cid)
                        processed.add(cid)
                        continue

                    # Gather context for the issue
                    issue_comments = gh.list_issue_comments(repo, number)
                    parent_issue = None
                    pnum = find_parent_issue_number(issue.get("body","") or "")
                    if pnum:
                        try:
                            parent_issue = gh.get_issue(repo, pnum)
                        except Exception as e:
                            logging.warning("Could not fetch parent issue #%s in %s: %r", pnum, repo, e)

                    resume = extract_resume_flag(body)
                    payload = build_job_input(repo, issue, issue_comments, parent_issue, c, resume=resume)

                    run_id = f"{repo.replace('/','_')}-{number}-{cid}-{int(time.time())}"
                    log.info("Trigger from @%s on %s#%d (comment %s); resume=%s; run_id=%s; cwd=%s",
                             author, repo, number, cid, resume, run_id, local_path)

                    rc, out, err = run_external(cfg.codecs_cmd, cfg.codecs_args, payload, cfg.codecs_timeout, cwd=local_path)

                    ok = (rc == 0) and ("## Result" in out)
                    comment_body = format_result_comment(ok, run_id, rc, out, err)

                    try:
                        gh.post_issue_comment(repo, number, comment_body)
                    except requests.HTTPError as e:
                        log.error("Failed to post comment to %s#%d: %s", repo, number, e)
                    except Exception as e:
                        log.error("Unexpected error posting comment to %s#%d: %r", repo, number, e)

                    meta.setdefault("runs", {})[str(number)] = {
                        "status": "ok" if ok else "error",
                        "last_run_at": _now_utc(),
                        "last_comment_id": cid,
                        "run_id": run_id,
                        "resume": resume,
                        "returncode": rc,
                    }

                    meta.setdefault("processed_comment_ids", []).append(cid)
                    processed.add(cid)

                    # Persist after each execution
                    st.save()

                # Trim processed list per repo
                if len(meta.get("processed_comment_ids", [])) > 5000:
                    meta["processed_comment_ids"] = meta["processed_comment_ids"][-2000:]
                    st.save()

            # End per-loop save
            st.save()

        except requests.HTTPError as e:
            resp = getattr(e, "response", None)
            retry_after = None
            if resp is not None:
                retry_after = resp.headers.get("Retry-After")
                remaining = resp.headers.get("X-RateLimit-Remaining")
                reset = resp.headers.get("X-RateLimit-Reset")
                logging.warning("HTTPError %s; remaining=%s; reset=%s; retry_after=%s",
                                e, remaining, reset, retry_after)
            sleep_s = int(retry_after) if (retry_after and retry_after.isdigit()) else cfg.poll_seconds * 3
            time.sleep(sleep_s)
        except Exception as e:
            logging.exception("Unexpected error in poll loop: %r", e)
            time.sleep(cfg.poll_seconds)
        finally:
            if stop["flag"]:
                break
            time.sleep(cfg.poll_seconds)

    lock.release()
    log.info("Stopped.")

if __name__ == "__main__":
    main()
