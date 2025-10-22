from __future__ import annotations

import logging
import re
import signal
import sys
import time
from pathlib import Path
from typing import Dict, Iterable

import requests

from .codex import (
    decide_codex_invocation,
    extract_codex_run_id,
    extract_intent,
    run_external,
)
from .config import Config
from .discovery import discover_local_repos
from .github import GitHub
from .payload import (
    build_job_input,
    find_parent_issue_number,
    format_result_comment,
    postprocess_stdout,
)
from .state import SingleInstanceLock, State
from .utils import _WATERMARK_BACKOFF, _compute_new_since, _iso, _now_utc, _parse_iso


def _sorted_by_created(data: Iterable[dict]) -> list[dict]:
    return sorted(data, key=lambda item: item.get("created_at", ""))


def run_loop(cfg: Config, stop: Dict[str, bool]) -> None:
    log = logging.getLogger("codex-watcher")

    repos = discover_local_repos(cfg.root, cfg.recursive, cfg.require_marker, cfg.exclude_dirs)
    if not repos:
        log.warning("No repos found. Create a git repo under %s or adjust POSIS_ROOT.", cfg.root)

    try:
        trigger_re = re.compile(cfg.regex, re.I)
    except re.error as exc:
        raise SystemExit(f"Invalid POSIS_REGEX '{cfg.regex}': {exc}") from exc

    gh = GitHub(cfg.token)
    me = gh.me_login()
    log.info(
        "Authenticated as @%s, watching %d repos, regex='%s', poll=%ss, match_target=%s, per_repo_pause=%.2fs",
        me,
        len(repos),
        cfg.regex,
        cfg.poll_seconds,
        cfg.match_target,
        cfg.per_repo_pause,
    )

    st = State(cfg.state_path)
    for repo, path in repos.items():
        st.ensure_repo(repo, path)
    st.save()

    while not stop["flag"]:
        try:
            repos = discover_local_repos(cfg.root, cfg.recursive, cfg.require_marker, cfg.exclude_dirs)
            for repo, path in repos.items():
                st.ensure_repo(repo, path)

            for repo, meta in list(st.data.get("repos", {}).items()):
                local_path = Path(meta.get("path", cfg.root))
                if repo not in repos:
                    continue

                since = meta.get("last_since") or _now_utc()
                try:
                    since_dt = _parse_iso(since)
                except ValueError:
                    since_dt = _parse_iso(_now_utc())
                    since = _now_utc()

                fetch_since = _iso(since_dt - _WATERMARK_BACKOFF)
                processed_ids = set(meta.get("processed_comment_ids", []))

                comments = gh.list_issue_comments_since(repo, fetch_since)
                issues: list[dict] = []

                for comment in _sorted_by_created(comments):
                    cid = comment.get("id")
                    if cid in processed_ids:
                        continue

                    body = comment.get("body") or ""
                    author = comment.get("user", {}).get("login", "")
                    if cfg.ignore_self and author == me:
                        meta.setdefault("processed_comment_ids", []).append(cid)
                        processed_ids.add(cid)
                        continue

                    if not trigger_re.search(body):
                        meta.setdefault("processed_comment_ids", []).append(cid)
                        processed_ids.add(cid)
                        continue

                    issue_url = comment.get("issue_url", "")
                    match = re.search(r"/issues/(\d+)$", issue_url)
                    if not match:
                        meta.setdefault("processed_comment_ids", []).append(cid)
                        processed_ids.add(cid)
                        continue

                    number = int(match.group(1))
                    issue = gh.get_issue(repo, number)
                    if "pull_request" in issue:
                        meta.setdefault("processed_comment_ids", []).append(cid)
                        processed_ids.add(cid)
                        continue

                    issue_runs = meta.setdefault("issue_runs", {})
                    issue_comments = gh.list_issue_comments(repo, number)
                    parent_issue = None
                    parent_number = find_parent_issue_number(issue.get("body", "") or "")
                    if parent_number:
                        try:
                            parent_issue = gh.get_issue(repo, parent_number)
                        except Exception as exc:
                            logging.warning("Could not fetch parent issue #%s in %s: %r", parent_number, repo, exc)

                    intent, requested_id = extract_intent(body)
                    issue_state = issue_runs.get(str(number), {})
                    stored_id = issue_state.get("codex_run_id")
                    args, send_payload, resume_flag, resume_target = decide_codex_invocation(
                        cfg, intent, requested_id, stored_id
                    )

                    payload = build_job_input(
                        repo,
                        issue,
                        issue_comments,
                        parent_issue,
                        comment,
                        resume=resume_flag,
                    )
                    payload_to_send = payload if send_payload else None

                    run_id = f"{repo.replace('/', '_')}-{number}-{cid}-{int(time.time())}"
                    log.info(
                        "Trigger from @%s on %s#%d (comment %s); intent=%s; resume=%s; run_id=%s; cwd=%s",
                        author,
                        repo,
                        number,
                        cid,
                        intent,
                        resume_flag,
                        run_id,
                        local_path,
                    )

                    rc, out, err = run_external(
                        cfg.codex_cmd,
                        args,
                        payload_to_send,
                        cfg.codex_timeout,
                        cwd=local_path,
                    )
                    processed_out = postprocess_stdout(out, cfg.codex_cmd)

                    ok = (rc == 0) and bool(processed_out.strip())
                    comment_body = format_result_comment(ok, run_id, rc, processed_out, err)
                    combined = "\n".join(part for part in (out, err) if part)
                    codex_id = extract_codex_run_id(combined) or (resume_target if resume_flag else None)
                    issue_updated_at = issue.get("updated_at") or issue.get("created_at") or _now_utc()

                    if ok and cid is not None:
                        try:
                            reacted = gh.add_reaction_to_comment(repo, cid, "eyes")
                            if reacted:
                                log.info("Added 👀 reaction to %s comment %s", repo, cid)
                        except Exception as exc:
                            log.warning("Failed to add reaction to %s comment %s: %r", repo, cid, exc)

                    try:
                        gh.post_issue_comment(repo, number, comment_body)
                    except requests.HTTPError as exc:
                        log.error("Failed to post comment to %s#%d: %s", repo, number, exc)
                    except Exception as exc:
                        log.error("Unexpected error posting comment to %s#%d: %r", repo, number, exc)

                    meta.setdefault("runs", {})[str(number)] = {
                        "status": "ok" if ok else "error",
                        "last_run_at": _now_utc(),
                        "last_comment_id": cid,
                        "run_id": run_id,
                        "resume": resume_flag,
                        "returncode": rc,
                        "source": "comment",
                        "codex_run_id": codex_id,
                    }

                    new_issue_run = dict(issue_state)
                    new_issue_run.update(
                        {
                            "last_issue_updated": issue_updated_at,
                            "run_id": run_id,
                            "returncode": rc,
                            "status": "ok" if ok else "error",
                        }
                    )
                    if codex_id:
                        new_issue_run["codex_run_id"] = codex_id
                    issue_runs[str(number)] = new_issue_run

                    meta.setdefault("processed_comment_ids", []).append(cid)
                    processed_ids.add(cid)

                    st.save()

                if cfg.match_target == "issue_or_comments":
                    issue_runs = meta.setdefault("issue_runs", {})
                    issues = gh.list_issues_since(repo, fetch_since)
                    for issue in issues:
                        if "pull_request" in issue:
                            continue
                        title_text = issue.get("title", "") or ""
                        body_text = issue.get("body", "") or ""
                        if not (trigger_re.search(title_text) or trigger_re.search(body_text)):
                            continue

                        number = issue.get("number")
                        if number is None:
                            continue

                        issue_updated_at = issue.get("updated_at") or issue.get("created_at") or _now_utc()
                        last_processed_at = issue_runs.get(str(number), {}).get("last_issue_updated")
                        if last_processed_at == issue_updated_at:
                            continue

                        issue_comments = gh.list_issue_comments(repo, number)
                        parent_issue = None
                        parent_number = find_parent_issue_number(body_text)
                        if parent_number:
                            try:
                                parent_issue = gh.get_issue(repo, parent_number)
                            except Exception as exc:
                                logging.warning(
                                    "Could not fetch parent issue #%s in %s (issue trigger): %r",
                                    parent_number,
                                    repo,
                                    exc,
                                )

                        trigger_id = issue.get("id") or f"issue-{number}"
                        trigger_comment = {
                            "id": trigger_id,
                            "user": issue.get("user") or {},
                            "created_at": issue.get("created_at") or issue_updated_at,
                            "body": body_text or title_text,
                        }

                        intent, requested_id = extract_intent(trigger_comment["body"])
                        issue_state = issue_runs.get(str(number), {})
                        stored_id = issue_state.get("codex_run_id")
                        args, send_payload, resume_flag, resume_target = decide_codex_invocation(
                            cfg, intent, requested_id, stored_id
                        )

                        payload = build_job_input(
                            repo,
                            issue,
                            issue_comments,
                            parent_issue,
                            trigger_comment,
                            resume=resume_flag,
                        )
                        payload_to_send = payload if send_payload else None

                        run_id = f"{repo.replace('/', '_')}-{number}-{trigger_id}-{int(time.time())}"
                        log.info(
                            "Trigger from issue body/title on %s#%d; intent=%s; resume=%s; run_id=%s; cwd=%s",
                            repo,
                            number,
                            intent,
                            resume_flag,
                            run_id,
                            local_path,
                        )

                        rc, out, err = run_external(
                            cfg.codex_cmd,
                            args,
                            payload_to_send,
                            cfg.codex_timeout,
                            cwd=local_path,
                        )
                        processed_out = postprocess_stdout(out, cfg.codex_cmd)

                        ok = (rc == 0) and bool(processed_out.strip())
                        comment_body = format_result_comment(ok, run_id, rc, processed_out, err)
                        combined = "\n".join(part for part in (out, err) if part)
                        codex_id = extract_codex_run_id(combined) or (resume_target if resume_flag else None)

                        try:
                            gh.post_issue_comment(repo, number, comment_body)
                        except requests.HTTPError as exc:
                            log.error("Failed to post comment to %s#%d (issue trigger): %s", repo, number, exc)
                        except Exception as exc:
                            log.error(
                                "Unexpected error posting comment to %s#%d (issue trigger): %r",
                                repo,
                                number,
                                exc,
                            )

                        meta.setdefault("runs", {})[str(number)] = {
                            "status": "ok" if ok else "error",
                            "last_run_at": _now_utc(),
                            "last_comment_id": trigger_id,
                            "run_id": run_id,
                            "resume": resume_flag,
                            "returncode": rc,
                            "source": "issue",
                            "codex_run_id": codex_id,
                        }

                        issue_run_record = dict(issue_state)
                        issue_run_record.update(
                            {
                                "last_issue_updated": issue_updated_at,
                                "run_id": run_id,
                                "returncode": rc,
                                "status": "ok" if ok else "error",
                            }
                        )
                        if codex_id:
                            issue_run_record["codex_run_id"] = codex_id

                        issue_runs[str(number)] = issue_run_record

                        st.save()

                if len(meta.get("processed_comment_ids", [])) > 5000:
                    meta["processed_comment_ids"] = meta["processed_comment_ids"][-2000:]
                    st.save()

                meta["last_since"] = _compute_new_since(since, (comments, issues))

                if cfg.per_repo_pause > 0:
                    time.sleep(cfg.per_repo_pause)

            st.save()

        except requests.HTTPError as exc:
            resp = getattr(exc, "response", None)
            retry_after = None
            remaining = None
            reset = None
            if resp is not None:
                retry_after = resp.headers.get("Retry-After")
                remaining = resp.headers.get("X-RateLimit-Remaining")
                reset = resp.headers.get("X-RateLimit-Reset")
                logging.warning(
                    "HTTPError %s; remaining=%s; reset=%s; retry_after=%s",
                    exc,
                    remaining,
                    reset,
                    retry_after,
                )

            sleep_s = cfg.poll_seconds * 3
            if retry_after and retry_after.isdigit():
                sleep_s = max(int(retry_after), 1)
            elif reset is not None:
                try:
                    reset_ts = int(float(reset))
                except (TypeError, ValueError):
                    reset_ts = None
                if reset_ts is not None:
                    now = int(time.time())
                    sleep_s = max(reset_ts - now, 0) + 1

            time.sleep(sleep_s)
        except Exception as exc:
            logging.exception("Unexpected error in poll loop: %r", exc)
            time.sleep(cfg.poll_seconds)
        finally:
            if stop["flag"]:
                break
            time.sleep(cfg.poll_seconds)


def main() -> None:
    cfg = Config.from_env()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    log = logging.getLogger("codex-watcher")

    lock = SingleInstanceLock(cfg.lockfile)
    lock.acquire()

    stop = {"flag": False}

    def _signal_handler(*_args) -> None:
        log.info("Signal received, shutting down...")
        stop["flag"] = True

    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, _signal_handler)

    try:
        run_loop(cfg, stop)
    finally:
        lock.release()
        log.info("Stopped.")
