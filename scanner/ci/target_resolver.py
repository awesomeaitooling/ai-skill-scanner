"""
LLM-powered target resolution for CI/PR scanning.

Given a list of changed files, uses the LLM to determine which files belong
to which AI agent skills/plugins, what the change scenario is (new, modified,
deleted), and filters out unrelated files.

Falls back to a heuristic directory-walk when the LLM is unavailable.
"""

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from scanner.ci.changed_files import ChangedFile
from scanner.ai.providers import invoke_with_retry, extract_text_content, RateLimiter


# ── Data classes ─────────────────────────────────────────────────────


@dataclass
class AffectedTarget:
    """A skill or plugin affected by changes in the PR."""

    path: str
    target_type: str  # "plugin" or "skill"
    name: str
    change_scenario: str  # "new_target", "modified", "file_added", "file_removed", "deleted_target"
    changed_files: list[ChangedFile] = field(default_factory=list)
    reasoning: str = ""


# ── Prompt templates ─────────────────────────────────────────────────

_SYSTEM_PROMPT = """\
You are an expert at analyzing AI agent plugin and skill directory structures.
You understand the standard layouts for Claude Code plugins, Cursor skills,
MCP servers, and similar AI agent extension ecosystems.

Standard plugin structure:
- .claude-plugin/plugin.json (or top-level plugin.json) marks a plugin root
- skills/<name>/SKILL.md marks a skill within a plugin
- commands/<name>/COMMAND.md, agents/<name>/AGENT.md define commands/agents
- hooks/hooks.json configures event hooks
- .mcp.json configures MCP servers, .lsp.json configures LSP servers
- scripts/ contains executable scripts, resources/ contains data files

Standalone skills:
- A SKILL.md file NOT inside a plugin directory marks a standalone skill
- The skill root is the directory containing the SKILL.md

Skills can also live at:
- .cursor/skills/<name>/SKILL.md
- .claude/skills/<name>/SKILL.md

Change scenarios:
- "new_target": The entire skill/plugin is new (all files are added)
- "modified": Existing files within the skill/plugin were changed
- "file_added": New files were added to an existing skill/plugin
- "file_removed": Files were removed from an existing skill/plugin
- "deleted_target": The entire skill/plugin is being deleted (all files removed)

If a target has a mix of added, modified, and deleted files, pick the most
accurate scenario. Use "modified" as the default for mixed changes.

CRITICAL: Respond ONLY with valid JSON. No markdown fences, no commentary.\
"""

_USER_PROMPT_TEMPLATE = """\
Analyze these changed files from a pull request and determine which ones
belong to AI agent skills or plugins.

**Changed files:**
{changed_files_list}

**Directory tree context (relevant subtrees):**
{directory_tree}

For each skill or plugin affected, identify:
1. The root path of the skill/plugin
2. Whether it's a "plugin" or standalone "skill"
3. Its name
4. The change scenario
5. Which changed files belong to it

Return JSON with this exact schema:
{{
  "affected_targets": [
    {{
      "root_path": "path/to/plugin-or-skill",
      "target_type": "plugin|skill",
      "name": "target-name",
      "change_scenario": "new_target|modified|file_added|file_removed|deleted_target",
      "reasoning": "Brief explanation of why this is a skill/plugin and the scenario",
      "changed_files": ["path/to/file1", "path/to/file2"]
    }}
  ],
  "unrelated_files": ["path/to/unrelated1"]
}}\
"""


# ── Directory tree builder ───────────────────────────────────────────

_SKIP_DIRS = {
    ".git", "node_modules", "__pycache__", ".venv", "venv",
    ".env", "dist", "build", ".tox", ".mypy_cache", ".ruff_cache",
}

_MAX_TREE_DEPTH = 4
_MAX_ENTRIES = 300


def _build_directory_tree(repo_root: str, changed_files: list[ChangedFile]) -> str:
    """Build a directory tree covering the subtrees relevant to changed files.

    Limits depth and entry count to keep the LLM context reasonable.
    """
    root = Path(repo_root).resolve()

    # Collect unique parent directories of changed files (up to 3 levels up)
    interesting_dirs: set[Path] = set()
    for cf in changed_files:
        p = (root / cf.path).resolve()
        for ancestor in [p.parent, p.parent.parent, p.parent.parent.parent]:
            try:
                ancestor.relative_to(root)
                interesting_dirs.add(ancestor)
            except ValueError:
                break

    lines: list[str] = []
    entry_count = 0

    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        current = Path(dirpath)

        # Prune skip dirs
        dirnames[:] = [d for d in sorted(dirnames) if d not in _SKIP_DIRS]

        try:
            rel = current.relative_to(root)
        except ValueError:
            continue

        depth = len(rel.parts)
        if depth > _MAX_TREE_DEPTH:
            dirnames.clear()
            continue

        # Only include subtrees near changed files (or the top 2 levels always)
        if depth > 1 and current not in interesting_dirs:
            is_ancestor_of_interesting = any(
                d == current or str(d).startswith(str(current) + os.sep)
                for d in interesting_dirs
            )
            if not is_ancestor_of_interesting:
                dirnames.clear()
                continue

        indent = "  " * depth
        dir_name = rel.name or "."
        lines.append(f"{indent}{dir_name}/")
        entry_count += 1

        for fname in sorted(filenames):
            lines.append(f"{indent}  {fname}")
            entry_count += 1
            if entry_count >= _MAX_ENTRIES:
                lines.append(f"{indent}  ... (truncated)")
                return "\n".join(lines)

    return "\n".join(lines) if lines else "(empty)"


# ── LLM-powered resolution ──────────────────────────────────────────


def _format_changed_files(changed_files: list[ChangedFile]) -> str:
    lines = []
    for cf in changed_files:
        rename_info = f" (was: {cf.previous_path})" if cf.previous_path else ""
        lines.append(f"- [{cf.status.upper()}] {cf.path}{rename_info}")
    return "\n".join(lines)


def resolve_targets_with_llm(
    changed_files: list[ChangedFile],
    repo_root: str,
    llm,
    *,
    verbose: bool = False,
    rate_limiter: Optional[RateLimiter] = None,
) -> list[AffectedTarget]:
    """Use the LLM to resolve changed files to skill/plugin targets.

    Falls back to heuristic resolution on failure.
    """
    if not changed_files:
        return []

    tree = _build_directory_tree(repo_root, changed_files)
    files_list = _format_changed_files(changed_files)

    user_prompt = _USER_PROMPT_TEMPLATE.format(
        changed_files_list=files_list,
        directory_tree=tree,
    )

    messages = [
        {"role": "system", "content": _SYSTEM_PROMPT},
        {"role": "user", "content": user_prompt},
    ]

    try:
        response = invoke_with_retry(
            llm, messages,
            max_retries=2,
            rate_limiter=rate_limiter,
            verbose=verbose,
        )
        raw = extract_text_content(response.content)

        # Strip markdown fences if present
        text = raw.strip()
        if text.startswith("```"):
            first_nl = text.index("\n")
            last_fence = text.rfind("```")
            text = text[first_nl + 1:last_fence].strip()

        data = json.loads(text)
        return _parse_llm_response(data, changed_files, repo_root)

    except Exception as exc:
        if verbose:
            print(f"  [WARNING] LLM target resolution failed: {exc}")
            print("  Falling back to heuristic resolution...")
        return resolve_targets_heuristic(changed_files, repo_root)


def _parse_llm_response(
    data: dict,
    changed_files: list[ChangedFile],
    repo_root: str,
) -> list[AffectedTarget]:
    """Parse and validate the LLM JSON response into AffectedTarget objects."""
    targets: list[AffectedTarget] = []
    cf_by_path = {cf.path: cf for cf in changed_files}

    for entry in data.get("affected_targets", []):
        root_path = entry.get("root_path", "").strip().rstrip("/")
        if not root_path:
            continue

        matched_files = []
        for fp in entry.get("changed_files", []):
            cf = cf_by_path.get(fp)
            if cf:
                matched_files.append(cf)

        if not matched_files:
            continue

        target_type = entry.get("target_type", "plugin")
        if target_type not in ("plugin", "skill"):
            target_type = "plugin"

        scenario = entry.get("change_scenario", "modified")
        valid_scenarios = {
            "new_target", "modified", "file_added", "file_removed", "deleted_target",
        }
        if scenario not in valid_scenarios:
            scenario = "modified"

        targets.append(AffectedTarget(
            path=root_path,
            target_type=target_type,
            name=entry.get("name", Path(root_path).name),
            change_scenario=scenario,
            changed_files=matched_files,
            reasoning=entry.get("reasoning", ""),
        ))

    return _deduplicate_targets(targets)


# ── Heuristic fallback ───────────────────────────────────────────────

_PLUGIN_MARKERS = {"plugin.json"}
_PLUGIN_DIRS = {".claude-plugin"}
_SKILL_MARKER = "skill.md"
_COMPONENT_MARKERS = {
    "skill.md", "agent.md", "command.md",
    "hooks.json", ".mcp.json", ".lsp.json",
}


def resolve_targets_heuristic(
    changed_files: list[ChangedFile],
    repo_root: str,
) -> list[AffectedTarget]:
    """Heuristic fallback: walk up directories looking for plugin/skill markers."""
    root = Path(repo_root).resolve()
    target_map: dict[str, AffectedTarget] = {}

    for cf in changed_files:
        file_path = (root / cf.path).resolve()
        target_info = _find_parent_target(file_path, root)

        if target_info is None:
            continue

        t_path, t_type = target_info
        rel_path = str(t_path.relative_to(root))

        if rel_path in target_map:
            target_map[rel_path].changed_files.append(cf)
        else:
            target_map[rel_path] = AffectedTarget(
                path=rel_path,
                target_type=t_type,
                name=t_path.name,
                change_scenario="modified",
                changed_files=[cf],
                reasoning="Heuristic: found plugin/skill marker in parent directory",
            )

    # Refine change scenarios
    for target in target_map.values():
        statuses = {cf.status for cf in target.changed_files}
        if statuses == {"added"}:
            target.change_scenario = "new_target"
        elif statuses == {"deleted"}:
            target.change_scenario = "deleted_target"
        elif "added" in statuses and "deleted" not in statuses:
            target.change_scenario = "file_added"
        elif "deleted" in statuses and "added" not in statuses:
            target.change_scenario = "file_removed"

    return list(target_map.values())


def _find_parent_target(
    file_path: Path,
    repo_root: Path,
) -> Optional[tuple[Path, str]]:
    """Walk up from *file_path* looking for the nearest plugin or skill root."""
    current = file_path.parent

    while True:
        try:
            current.relative_to(repo_root)
        except ValueError:
            break

        # Check for plugin markers
        if (current / ".claude-plugin" / "plugin.json").exists():
            return current, "plugin"
        if (current / "plugin.json").exists():
            return current, "plugin"

        # Check for standalone SKILL.md
        skill_md = current / "SKILL.md"
        if skill_md.exists():
            # Make sure it's not inside a plugin
            parent_is_plugin = False
            check = current.parent
            while True:
                try:
                    check.relative_to(repo_root)
                except ValueError:
                    break
                if (check / ".claude-plugin" / "plugin.json").exists():
                    parent_is_plugin = True
                    break
                if (check / "plugin.json").exists():
                    parent_is_plugin = True
                    break
                check = check.parent

            if not parent_is_plugin:
                return current, "skill"

        if current == repo_root:
            break
        current = current.parent

    # Check if the file itself is a component marker
    name_lower = file_path.name.lower()
    if name_lower in _COMPONENT_MARKERS:
        return file_path.parent, "skill"

    return None


def _deduplicate_targets(targets: list[AffectedTarget]) -> list[AffectedTarget]:
    """Merge targets that point to the same root path."""
    merged: dict[str, AffectedTarget] = {}
    for t in targets:
        key = t.path.rstrip("/")
        if key in merged:
            existing = merged[key]
            seen_paths = {cf.path for cf in existing.changed_files}
            for cf in t.changed_files:
                if cf.path not in seen_paths:
                    existing.changed_files.append(cf)
                    seen_paths.add(cf.path)
        else:
            merged[key] = t
    return list(merged.values())
