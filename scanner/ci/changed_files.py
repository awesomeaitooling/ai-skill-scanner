"""
Changed file detection for CI/PR scanning.

Primary method: GitHub REST API (GET /repos/{owner}/{repo}/pulls/{pr}/files).
Fallback: git diff --name-status for local testing or non-GitHub CI.
"""

import json
import os
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


@dataclass
class ChangedFile:
    """A file changed in a pull request."""

    path: str
    status: str  # "added", "modified", "deleted", "renamed"
    previous_path: Optional[str] = None
    patch: Optional[str] = None


# ── GitHub REST API ──────────────────────────────────────────────────


_STATUS_MAP = {
    "added": "added",
    "modified": "modified",
    "removed": "deleted",
    "renamed": "renamed",
    "copied": "added",
    "changed": "modified",
}


def get_changed_files_from_github(
    owner: str,
    repo: str,
    pr_number: int,
    github_token: str,
) -> list[ChangedFile]:
    """Fetch changed files for a PR using the GitHub REST API.

    Handles pagination (up to 3000 files per PR, 100 per page).

    Raises ``RuntimeError`` on API errors.
    """
    files: list[ChangedFile] = []
    page = 1

    while True:
        url = (
            f"https://api.github.com/repos/{owner}/{repo}"
            f"/pulls/{pr_number}/files?per_page=100&page={page}"
        )
        req = Request(url)
        req.add_header("Accept", "application/vnd.github+json")
        req.add_header("Authorization", f"Bearer {github_token}")
        req.add_header("X-GitHub-Api-Version", "2022-11-28")

        try:
            with urlopen(req, timeout=30) as resp:
                data = json.loads(resp.read().decode())
        except HTTPError as exc:
            body = exc.read().decode() if exc.fp else ""
            raise RuntimeError(
                f"GitHub API error {exc.code} fetching PR files: {body[:500]}"
            ) from exc
        except URLError as exc:
            raise RuntimeError(
                f"Network error fetching PR files: {exc.reason}"
            ) from exc

        if not data:
            break

        for entry in data:
            status_raw = entry.get("status", "modified")
            files.append(
                ChangedFile(
                    path=entry["filename"],
                    status=_STATUS_MAP.get(status_raw, "modified"),
                    previous_path=entry.get("previous_filename"),
                    patch=entry.get("patch"),
                )
            )

        if len(data) < 100:
            break
        page += 1

    return files


# ── Git diff fallback ────────────────────────────────────────────────

_GIT_STATUS_MAP = {
    "A": "added",
    "M": "modified",
    "D": "deleted",
    "R": "renamed",
    "C": "added",
    "T": "modified",
}


def get_changed_files_from_git(
    base_ref: str,
    head_ref: str,
    repo_root: str,
) -> list[ChangedFile]:
    """Detect changed files via ``git diff --name-status``.

    Works without GitHub API access — suitable for local testing.
    """
    cmd = [
        "git", "diff", "--name-status", "--no-renames",
        f"{base_ref}...{head_ref}",
    ]

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        cwd=repo_root,
        timeout=60,
    )

    if result.returncode != 0:
        # Retry with two-dot diff (in case three-dot is unsupported)
        cmd_fallback = [
            "git", "diff", "--name-status",
            base_ref, head_ref,
        ]
        result = subprocess.run(
            cmd_fallback,
            capture_output=True,
            text=True,
            cwd=repo_root,
            timeout=60,
        )
        if result.returncode != 0:
            raise RuntimeError(
                f"git diff failed: {result.stderr[:500]}"
            )

    files: list[ChangedFile] = []
    for line in result.stdout.strip().splitlines():
        if not line.strip():
            continue
        parts = line.split("\t")
        if len(parts) < 2:
            continue

        status_code = parts[0][0]  # first char (R100 -> R)
        status = _GIT_STATUS_MAP.get(status_code, "modified")
        file_path = parts[-1]
        prev_path = parts[1] if len(parts) > 2 else None

        files.append(
            ChangedFile(
                path=file_path,
                status=status,
                previous_path=prev_path,
            )
        )

    return files


# ── Patch retrieval helper ───────────────────────────────────────────


def get_file_patch(
    base_ref: str,
    head_ref: str,
    file_path: str,
    repo_root: str,
) -> Optional[str]:
    """Get the unified diff patch for a single file between two refs."""
    cmd = ["git", "diff", base_ref, head_ref, "--", file_path]
    result = subprocess.run(
        cmd, capture_output=True, text=True, cwd=repo_root, timeout=30,
    )
    if result.returncode == 0 and result.stdout.strip():
        return result.stdout
    return None


# ── Auto-detection helper ────────────────────────────────────────────


def get_changed_files(
    repo_root: str,
    *,
    github_token: Optional[str] = None,
    pr_number: Optional[int] = None,
    base_ref: Optional[str] = None,
    head_ref: Optional[str] = None,
) -> list[ChangedFile]:
    """Get changed files using the best available method.

    Tries GitHub API first (if token + PR number available), then
    falls back to git diff.
    """
    token = github_token or os.environ.get("GITHUB_TOKEN")
    gh_repo = os.environ.get("GITHUB_REPOSITORY", "")

    if token and pr_number and gh_repo:
        parts = gh_repo.split("/", 1)
        if len(parts) == 2:
            owner, repo = parts
            return get_changed_files_from_github(owner, repo, pr_number, token)

    # Fallback to git diff
    base = base_ref or os.environ.get("GITHUB_BASE_REF")
    head = head_ref or os.environ.get("GITHUB_SHA", "HEAD")

    if not base:
        raise RuntimeError(
            "Cannot determine changed files: provide --pr-number + GitHub token, "
            "or --base-ref + --head-ref for git diff"
        )

    return get_changed_files_from_git(base, head, repo_root)
