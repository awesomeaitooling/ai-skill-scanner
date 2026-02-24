"""
Git Utilities - Functions for cloning and managing git-based plugins.
"""

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse


def _sanitize_git_url(url: str) -> str:
    """
    Sanitize and validate a git URL to prevent command injection.
    
    Args:
        url: Git URL to sanitize
        
    Returns:
        Sanitized URL
        
    Raises:
        ValueError: If URL is invalid or potentially malicious
    """
    if not url:
        raise ValueError("Empty URL provided")
    
    # Block dangerous git protocol handlers
    dangerous_prefixes = [
        "ext::",      # External command execution
        "--",         # Git option injection
        "-",          # Flag injection
    ]
    
    url_lower = url.lower().strip()
    for prefix in dangerous_prefixes:
        if url_lower.startswith(prefix):
            raise ValueError(f"Potentially malicious URL pattern detected: {prefix}")
    
    # Only allow safe protocols
    allowed_protocols = ["https://", "http://", "git@", "ssh://", "git://"]
    
    # Check if it's a GitHub shorthand (owner/repo)
    if "/" in url and not any(url_lower.startswith(p) for p in allowed_protocols):
        parts = url.split("/")
        if len(parts) == 2:
            # Validate owner/repo format - alphanumeric, hyphens, underscores only
            import re
            if all(re.match(r'^[\w\-\.]+$', p) for p in parts):
                return url  # Valid shorthand
        raise ValueError("Invalid repository shorthand format")
    
    # Validate URL has allowed protocol
    if not any(url_lower.startswith(p) for p in allowed_protocols):
        raise ValueError(f"URL must use one of: {', '.join(allowed_protocols)}")
    
    # Check for null bytes and other injection characters
    if '\x00' in url or '\n' in url or '\r' in url:
        raise ValueError("URL contains invalid characters")
    
    return url


def _sanitize_branch_name(branch: str) -> str:
    """
    Sanitize branch name to prevent injection.
    
    Args:
        branch: Branch name to sanitize
        
    Returns:
        Sanitized branch name
        
    Raises:
        ValueError: If branch name is invalid
    """
    import re
    
    if not branch:
        raise ValueError("Empty branch name")
    
    # Branch names cannot start with - (prevents flag injection)
    if branch.startswith("-"):
        raise ValueError("Branch name cannot start with '-'")
    
    # Allow only safe characters in branch names
    # Git branch names: alphanumeric, /, -, _, .
    if not re.match(r'^[\w\-\./]+$', branch):
        raise ValueError("Branch name contains invalid characters")
    
    # Prevent path traversal in branch names
    if ".." in branch:
        raise ValueError("Branch name cannot contain '..'")
    
    return branch


def clone_marketplace(
    url: str,
    target_dir: Optional[str] = None,
    branch: Optional[str] = None
) -> str:
    """
    Clone a marketplace repository.
    
    Args:
        url: Git repository URL
        target_dir: Target directory (uses temp dir if not specified)
        branch: Specific branch to clone
    
    Returns:
        Path to cloned repository
        
    Raises:
        ValueError: If URL or branch is invalid
        RuntimeError: If git clone fails
    """
    # Sanitize inputs to prevent command injection
    sanitized_url = _sanitize_git_url(url)
    
    if target_dir is None:
        target_dir = tempfile.mkdtemp(prefix="plugin-scanner-")
    
    target_path = Path(target_dir)
    
    # Build clone command with sanitized inputs
    cmd = ["git", "clone", "--depth", "1"]
    
    if branch:
        sanitized_branch = _sanitize_branch_name(branch)
        cmd.extend(["--branch", sanitized_branch])
    
    cmd.extend(["--", sanitized_url, str(target_path)])  # "--" prevents option injection
    
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=120,
            env={**os.environ, "GIT_TERMINAL_PROMPT": "0"}  # Disable interactive prompts
        )
        
        if result.returncode != 0:
            # Sanitize error message to prevent information leakage
            error_msg = result.stderr[:500] if result.stderr else "Unknown error"
            raise RuntimeError(f"Git clone failed: {error_msg}")
        
        return str(target_path)
    
    except subprocess.TimeoutExpired:
        # Clean up partial clone on timeout
        if target_path.exists():
            shutil.rmtree(target_path, ignore_errors=True)
        raise RuntimeError("Git clone timed out")


def fetch_plugin_from_git(
    url: str,
    target_dir: Optional[str] = None,
    ref: Optional[str] = None
) -> str:
    """
    Fetch a plugin from a git URL.
    
    Supports:
    - Full repository URLs
    - GitHub shorthand (owner/repo)
    - Specific refs (branches, tags, commits)
    
    Args:
        url: Git URL or GitHub shorthand
        target_dir: Target directory
        ref: Git ref (branch, tag, or commit)
    
    Returns:
        Path to fetched plugin
    """
    # Expand GitHub shorthand
    if "/" in url and not url.startswith(("http://", "https://", "git@")):
        url = f"https://github.com/{url}.git"
    
    return clone_marketplace(url, target_dir, ref)


def discover_plugins_in_marketplace(marketplace_path: str) -> list[dict]:
    """
    Discover plugins defined in a marketplace.
    
    Args:
        marketplace_path: Path to marketplace directory
    
    Returns:
        List of plugin definitions
    """
    marketplace_json = Path(marketplace_path) / "marketplace.json"
    
    if not marketplace_json.exists():
        # Try to find plugins by directory structure
        return _discover_plugins_by_structure(marketplace_path)
    
    try:
        with open(marketplace_json, "r", encoding="utf-8") as f:
            data = json.load(f)
        
        plugins = []
        
        for plugin in data.get("plugins", []):
            plugin_info = {
                "name": plugin.get("name", ""),
                "description": plugin.get("description", ""),
                "source": plugin.get("source", ""),
                "version": plugin.get("version", ""),
            }
            
            # Resolve source path
            source = plugin.get("source", "")
            if source.startswith("./"):
                plugin_info["path"] = str(Path(marketplace_path) / source)
            elif source.startswith("http"):
                plugin_info["git_url"] = source
            else:
                plugin_info["path"] = str(Path(marketplace_path) / source)
            
            plugins.append(plugin_info)
        
        return plugins
    
    except Exception as e:
        raise RuntimeError(f"Failed to parse marketplace.json: {e}")


def _discover_plugins_by_structure(marketplace_path: str) -> list[dict]:
    """
    Discover plugins by examining directory structure.
    
    Looks for directories containing plugin.json or .claude-plugin/plugin.json.
    """
    plugins = []
    root = Path(marketplace_path)
    
    for item in root.iterdir():
        if not item.is_dir():
            continue
        
        # Check for plugin manifest
        manifest_paths = [
            item / "plugin.json",
            item / ".claude-plugin" / "plugin.json",
        ]
        
        for manifest_path in manifest_paths:
            if manifest_path.exists():
                try:
                    with open(manifest_path, "r", encoding="utf-8") as f:
                        manifest = json.load(f)
                    
                    plugins.append({
                        "name": manifest.get("name", item.name),
                        "description": manifest.get("description", ""),
                        "version": manifest.get("version", ""),
                        "path": str(item),
                    })
                    break
                except Exception:
                    plugins.append({
                        "name": item.name,
                        "path": str(item),
                    })
                    break
    
    return plugins


def cleanup_temp_dir(path: str) -> None:
    """
    Clean up a temporary directory.
    
    Args:
        path: Path to directory to remove
    """
    if path and Path(path).exists():
        shutil.rmtree(path, ignore_errors=True)


def create_worktree(ref: str, repo_root: str) -> str:
    """
    Create a temporary git worktree checked out at a specific ref.
    
    Args:
        ref: Git ref to checkout (branch, tag, or commit SHA)
        repo_root: Path to the git repository root
    
    Returns:
        Path to the worktree directory
    
    Raises:
        RuntimeError: If worktree creation fails
    """
    import tempfile

    tmp_dir = tempfile.mkdtemp(prefix="scanner-worktree-")
    cmd = ["git", "worktree", "add", "--detach", tmp_dir, ref]

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        cwd=repo_root,
        timeout=60,
        env={**os.environ, "GIT_TERMINAL_PROMPT": "0"},
    )

    if result.returncode != 0:
        shutil.rmtree(tmp_dir, ignore_errors=True)
        raise RuntimeError(
            f"Failed to create worktree at {ref}: {result.stderr[:300]}"
        )

    return tmp_dir


def cleanup_worktree(worktree_path: str, repo_root: str) -> None:
    """
    Remove a git worktree and clean up its directory.
    
    Args:
        worktree_path: Path to the worktree to remove
        repo_root: Path to the git repository root
    """
    try:
        subprocess.run(
            ["git", "worktree", "remove", "--force", worktree_path],
            capture_output=True,
            text=True,
            cwd=repo_root,
            timeout=30,
        )
    except Exception:
        pass
    shutil.rmtree(worktree_path, ignore_errors=True)


def get_changed_files_from_diff(
    base_ref: str,
    head_ref: str,
    repo_root: str,
) -> list[dict]:
    """
    Get changed files between two git refs using git diff.
    
    Args:
        base_ref: Base git ref
        head_ref: Head git ref
        repo_root: Path to the git repository root
    
    Returns:
        List of dicts with 'path', 'status' keys
    """
    cmd = [
        "git", "diff", "--name-status",
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
        # Fall back to two-dot diff
        cmd = ["git", "diff", "--name-status", base_ref, head_ref]
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            cwd=repo_root,
            timeout=60,
        )
        if result.returncode != 0:
            raise RuntimeError(f"git diff failed: {result.stderr[:300]}")

    status_map = {
        "A": "added", "M": "modified", "D": "deleted",
        "R": "renamed", "C": "added", "T": "modified",
    }

    files = []
    for line in result.stdout.strip().splitlines():
        if not line.strip():
            continue
        parts = line.split("\t")
        if len(parts) < 2:
            continue
        status_code = parts[0][0]
        files.append({
            "path": parts[-1],
            "status": status_map.get(status_code, "modified"),
        })

    return files


def validate_git_url(url: str) -> bool:
    """
    Validate a git URL.
    
    Args:
        url: URL to validate
    
    Returns:
        True if URL appears valid
    """
    if not url:
        return False
    
    # GitHub shorthand
    if "/" in url and not url.startswith(("http://", "https://", "git@")):
        parts = url.split("/")
        return len(parts) == 2 and all(p for p in parts)
    
    # Full URL
    try:
        parsed = urlparse(url)
        return parsed.scheme in ("http", "https", "git", "ssh") and bool(parsed.netloc)
    except Exception:
        return False

