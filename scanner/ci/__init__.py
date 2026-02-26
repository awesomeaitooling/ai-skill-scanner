"""
CI/PR scanning module for AI Skill Security Scanner.

Provides GitHub Actions integration for scanning skills and plugins
affected by pull request changes, with LLM-powered target resolution
and impact analysis.
"""

from scanner.ci.changed_files import (
    ChangedFile,
    get_changed_files,
    get_changed_files_from_github,
    get_changed_files_from_git,
)
from scanner.ci.target_resolver import (
    AffectedTarget,
    resolve_targets_with_llm,
    resolve_targets_heuristic,
)
from scanner.ci.diff_scanner import (
    DiffScanner,
    ImpactFinding,
    TargetImpactResult,
    PRScanResult,
    PRScanSummary,
)
from scanner.ci.pr_reporter import (
    generate_pr_comment,
    generate_pr_sarif,
    generate_pr_json,
    write_pr_comment,
    write_pr_sarif,
    write_pr_json,
)

__all__ = [
    "ChangedFile",
    "get_changed_files",
    "get_changed_files_from_github",
    "get_changed_files_from_git",
    "AffectedTarget",
    "resolve_targets_with_llm",
    "resolve_targets_heuristic",
    "DiffScanner",
    "ImpactFinding",
    "TargetImpactResult",
    "PRScanResult",
    "PRScanSummary",
    "generate_pr_comment",
    "generate_pr_sarif",
    "generate_pr_json",
    "write_pr_comment",
    "write_pr_sarif",
    "write_pr_json",
]
