"""
Discovery module — recursively find plugins and standalone skills in a directory.

Supports the following layouts:

Skills:
  repo/SKILL.md
  repo/skills/<name>/SKILL.md
  repo/a/b/skills/<name>/SKILL.md

Plugins:
  repo/<plugin>/.claude-plugin/plugin.json
  repo/plugins/<plugin-1>/.claude-plugin/plugin.json
  repo/plugins/<plugin-2>/.claude-plugin/plugin.json
"""

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


SKIP_DIRS = {
    ".git", ".svn", ".hg", "node_modules", "__pycache__",
    ".tox", ".venv", "venv", ".env", "env", ".mypy_cache",
    ".pytest_cache", ".ruff_cache", "dist", "build",
}

MAX_WALK_DEPTH = 20

MANIFEST_NAMES = {"plugin.json"}
MANIFEST_DIRS = {".claude-plugin"}
SKILL_FILENAME = "skill.md"


@dataclass
class DiscoveredTarget:
    """A plugin or standalone skill discovered in a directory tree."""

    path: str
    target_type: str  # "plugin" or "skill"
    name: str

    def __repr__(self) -> str:
        return f"DiscoveredTarget({self.target_type}: {self.name} @ {self.path})"


def discover_targets(root_path: str) -> list[DiscoveredTarget]:
    """
    Recursively discover all plugins and standalone skills under *root_path*.

    1. Walk the tree and collect every directory that contains a plugin
       manifest (`.claude-plugin/plugin.json` or bare `plugin.json`).
    2. Walk again for `SKILL.md` files; keep only those whose parent
       directory is **not** inside any discovered plugin.
    3. Deduplicate by resolved path and return sorted by name.
    """
    root = Path(root_path).resolve()
    if not root.is_dir():
        return []

    plugin_targets = _discover_plugins(root)
    plugin_paths = {Path(t.path).resolve() for t in plugin_targets}

    skill_targets = _discover_standalone_skills(root, plugin_paths)

    seen: set[str] = set()
    merged: list[DiscoveredTarget] = []
    for target in plugin_targets + skill_targets:
        resolved = str(Path(target.path).resolve())
        if resolved not in seen:
            seen.add(resolved)
            merged.append(target)

    merged.sort(key=lambda t: t.name.lower())
    return merged


def _discover_plugins(root: Path) -> list[DiscoveredTarget]:
    """Find all directories that contain a plugin manifest."""
    targets: list[DiscoveredTarget] = []
    found_paths: set[Path] = set()

    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        current = Path(dirpath)

        depth = len(current.resolve().relative_to(root.resolve()).parts)
        if depth > MAX_WALK_DEPTH:
            dirnames.clear()
            continue

        manifest_path: Optional[Path] = None

        claude_plugin_dir = current / ".claude-plugin"
        if claude_plugin_dir.is_dir():
            candidate = claude_plugin_dir / "plugin.json"
            if candidate.is_file():
                manifest_path = candidate

        if manifest_path is None and "plugin.json" in filenames:
            candidate = current / "plugin.json"
            if candidate.is_file():
                manifest_path = candidate

        if manifest_path is not None:
            resolved = current.resolve()
            if resolved not in found_paths:
                found_paths.add(resolved)
                name = _read_plugin_name(manifest_path, fallback=current.name)
                targets.append(DiscoveredTarget(
                    path=str(current),
                    target_type="plugin",
                    name=name,
                ))
                dirnames.clear()

    return targets


def _discover_standalone_skills(
    root: Path,
    plugin_paths: set[Path],
) -> list[DiscoveredTarget]:
    """Find SKILL.md files that are NOT inside a discovered plugin directory."""
    targets: list[DiscoveredTarget] = []
    found_paths: set[Path] = set()

    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        current = Path(dirpath)

        depth = len(current.resolve().relative_to(root.resolve()).parts)
        if depth > MAX_WALK_DEPTH:
            dirnames.clear()
            continue

        for fname in filenames:
            if fname.lower() == SKILL_FILENAME:
                skill_dir = current.resolve()
                if _is_inside_plugin(skill_dir, plugin_paths):
                    continue
                if skill_dir not in found_paths:
                    found_paths.add(skill_dir)
                    targets.append(DiscoveredTarget(
                        path=str(current),
                        target_type="skill",
                        name=current.name,
                    ))

    return targets


def _is_inside_plugin(path: Path, plugin_paths: set[Path]) -> bool:
    """Return True if *path* is equal to or a descendant of any plugin root."""
    for pp in plugin_paths:
        try:
            path.relative_to(pp)
            return True
        except ValueError:
            continue
    return False


def _read_plugin_name(manifest_path: Path, fallback: str) -> str:
    """Best-effort read of the plugin name from its manifest JSON."""
    try:
        with open(manifest_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data.get("name") or fallback
    except Exception:
        return fallback
