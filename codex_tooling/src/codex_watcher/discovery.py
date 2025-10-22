from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path
from typing import Dict, List, Optional


def discover_git_remote(path: Path) -> Optional[str]:
    """Return the remote.origin.url for a git repo at *path*, else ``None``."""
    try:
        url = subprocess.check_output(
            ["git", "-C", str(path), "config", "--get", "remote.origin.url"],
            text=True,
        ).strip()
        return url or None
    except Exception:
        return None


def parse_github_owner_repo(remote_url: str) -> Optional[str]:
    """Extract ``owner/repo`` from HTTPS or SSH GitHub remotes."""
    match = re.search(r"github\.com[:/](?P<owner>[^/]+)/(?P<repo>[^/.]+)(?:\.git)?$", remote_url or "", re.I)
    if not match:
        return None
    return f"{match.group('owner')}/{match.group('repo')}"


def discover_local_repos(
    root: Path,
    recursive: bool,
    require_marker: bool,
    exclude_dirs: List[str],
) -> Dict[str, Path]:
    """Scan *root* for git repositories keyed by ``owner/repo``."""
    repos: Dict[str, Path] = {}

    def consider_dir(candidate: Path) -> None:
        if not (candidate / ".git").exists():
            return
        if require_marker and not (candidate / ".posis-enabled").exists():
            return
        remote = discover_git_remote(candidate)
        if not remote:
            return
        owner_repo = parse_github_owner_repo(remote)
        if not owner_repo:
            return
        repos.setdefault(owner_repo, candidate)

    if not recursive:
        for child in root.iterdir():
            if not child.is_dir():
                continue
            if child.name in exclude_dirs:
                continue
            consider_dir(child)
    else:
        for dirpath, dirnames, _filenames in os.walk(root):
            dirnames[:] = [name for name in dirnames if name not in exclude_dirs]
            folder = Path(dirpath)
            if (folder / ".git").exists():
                consider_dir(folder)
                dirnames[:] = []  # do not descend further once repo discovered

    return repos
