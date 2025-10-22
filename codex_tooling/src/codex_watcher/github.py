from __future__ import annotations

import logging
import re
from typing import List

import requests


class GitHub:
    """Thin wrapper around the GitHub REST API used by the watcher."""

    def __init__(self, token: str):
        self.session = requests.Session()
        self.session.headers.update(
            {
                "Authorization": f"token {token}",
                "Accept": "application/vnd.github+json",
                "User-Agent": "codex-watcher/1.0",
            }
        )
        self.api = "https://api.github.com"
        self._me = None

    def me_login(self) -> str:
        if self._me is None:
            response = self.session.get(f"{self.api}/user", timeout=30)
            response.raise_for_status()
            self._me = response.json()["login"]
        return self._me

    def list_issue_comments_since(self, repo: str, since_iso: str, per_page: int = 100) -> List[dict]:
        comments: List[dict] = []
        url = f"{self.api}/repos/{repo}/issues/comments"
        params = {"since": since_iso, "per_page": per_page, "page": 1}
        while True:
            response = self.session.get(url, params=params, timeout=60)
            if response.status_code == 304:
                break
            response.raise_for_status()
            batch = response.json()
            if not isinstance(batch, list):
                break
            comments.extend(batch)
            link = response.headers.get("Link", "")
            if 'rel="next"' not in link:
                break
            match = re.search(r'<([^>]+)>;\s*rel="next"', link)
            if not match:
                break
            url, params = match.group(1), {}
        return comments

    def get_issue(self, repo: str, number: int) -> dict:
        response = self.session.get(f"{self.api}/repos/{repo}/issues/{number}", timeout=30)
        response.raise_for_status()
        return response.json()

    def list_issue_comments(self, repo: str, number: int) -> List[dict]:
        url = f"{self.api}/repos/{repo}/issues/{number}/comments"
        out: List[dict] = []
        params = {"per_page": 100, "page": 1}
        while True:
            response = self.session.get(url, params=params, timeout=60)
            response.raise_for_status()
            batch = response.json()
            out.extend(batch)
            link = response.headers.get("Link", "")
            if 'rel="next"' not in link:
                break
            match = re.search(r'<([^>]+)>;\s*rel="next"', link)
            if not match:
                break
            url, params = match.group(1), {}
        return out

    def list_issues_since(self, repo: str, since_iso: str, per_page: int = 100) -> List[dict]:
        issues: List[dict] = []
        url = f"{self.api}/repos/{repo}/issues"
        params = {"since": since_iso, "per_page": per_page, "page": 1, "state": "all"}
        while True:
            response = self.session.get(url, params=params, timeout=60)
            if response.status_code == 304:
                break
            response.raise_for_status()
            batch = response.json()
            if not isinstance(batch, list):
                break
            for item in batch:
                if "pull_request" in item:
                    continue
                issues.append(item)
            link = response.headers.get("Link", "")
            if 'rel="next"' not in link:
                break
            match = re.search(r'<([^>]+)>;\s*rel="next"', link)
            if not match:
                break
            url, params = match.group(1), {}
        return issues

    def post_issue_comment(self, repo: str, number: int, body: str) -> dict:
        response = self.session.post(
            f"{self.api}/repos/{repo}/issues/{number}/comments",
            json={"body": body},
            timeout=60,
        )
        response.raise_for_status()
        return response.json()

    def add_reaction_to_comment(self, repo: str, comment_id: int, content: str) -> bool:
        url = f"{self.api}/repos/{repo}/issues/comments/{comment_id}/reactions"
        headers = {
            "Accept": "application/vnd.github+json, application/vnd.github.squirrel-girl-preview+json",
            "Content-Type": "application/json",
        }
        response = self.session.post(url, json={"content": content}, headers=headers, timeout=30)
        logging.getLogger("codex-watcher").info(
            "Reaction response for %s comment %s: %s", repo, comment_id, response.status_code
        )
        if response.status_code in (200, 201):
            return True
        if response.status_code in (204, 409):
            return False
        response.raise_for_status()
        return True
