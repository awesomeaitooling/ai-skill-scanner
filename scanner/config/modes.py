"""
Scan Mode Profiles — Predefined configuration profiles for different scan use cases.

Modes:
- strict:     All analyzers enabled, aggressive rules, low FP tolerance. Good for
              security audits and marketplace approval.
- balanced:   Default. All analyzers enabled, moderate rules. Good for development.
- permissive: Reduced analyzers, only high/critical rules. Good for quick checks
              or noisy/legacy plugins.
"""

from typing import Any, Dict


# ── Strict Mode ────────────────────────────────────────────────────
STRICT_OVERRIDES: Dict[str, Any] = {
    "analyzers": {
        "skill_analyzer": True,
        "script_analyzer": True,
        "hook_analyzer": True,
        "mcp_analyzer": True,
        "lsp_analyzer": True,
        "agent_command_analyzer": True,
        "ast_analyzer": True,
        "dataflow_analyzer": True,
        "alignment_analyzer": True,
        "cross_skill_analyzer": True,
        "meta_analyzer": True,
    },
    "components": {
        "skills": True,
        "commands": True,
        "agents": True,
        "hooks": True,
        "mcp_servers": True,
        "lsp_servers": True,
        "scripts": True,
        "resources": True,
    },
    "rules": {
        "disabled_rules": [],
        "disabled_categories": [],
    },
    "thresholds": {
        "fail_on_critical": True,
        "fail_on_high": True,
        "max_critical": 0,
        "max_high": 0,
        "max_medium": -1,
        "max_low": -1,
    },
    "output": {
        "show_snippets": True,
        "max_findings_display": 500,
    },
}


# ── Balanced Mode (default) ───────────────────────────────────────
BALANCED_OVERRIDES: Dict[str, Any] = {
    "analyzers": {
        "skill_analyzer": True,
        "script_analyzer": True,
        "hook_analyzer": True,
        "mcp_analyzer": True,
        "lsp_analyzer": True,
        "agent_command_analyzer": True,
        "ast_analyzer": True,
        "dataflow_analyzer": True,
        "alignment_analyzer": True,
        "cross_skill_analyzer": True,
        "meta_analyzer": True,
    },
    "components": {
        "skills": True,
        "commands": True,
        "agents": True,
        "hooks": True,
        "mcp_servers": True,
        "lsp_servers": True,
        "scripts": True,
        "resources": True,
    },
    "thresholds": {
        "fail_on_critical": True,
        "fail_on_high": False,
        "max_critical": 0,
        "max_high": -1,
        "max_medium": -1,
        "max_low": -1,
    },
}


# ── Permissive Mode ───────────────────────────────────────────────
PERMISSIVE_OVERRIDES: Dict[str, Any] = {
    "analyzers": {
        "skill_analyzer": True,
        "script_analyzer": True,
        "hook_analyzer": True,
        "mcp_analyzer": True,
        "lsp_analyzer": True,
        "agent_command_analyzer": True,
        "ast_analyzer": False,       # Skip AST for speed
        "dataflow_analyzer": False,  # Skip dataflow for speed
        "alignment_analyzer": False, # Skip alignment
        "cross_skill_analyzer": False,
        "meta_analyzer": True,
    },
    "components": {
        "skills": True,
        "commands": True,
        "agents": True,
        "hooks": True,
        "mcp_servers": True,
        "lsp_servers": True,
        "scripts": True,
        "resources": False,  # Skip resources
    },
    "rules": {
        "disabled_categories": [
            "unicode-steganography",
            "social-engineering",
        ],
    },
    "thresholds": {
        "fail_on_critical": True,
        "fail_on_high": False,
        "max_critical": 0,
        "max_high": -1,
        "max_medium": -1,
        "max_low": -1,
    },
    "output": {
        "show_snippets": False,
        "max_findings_display": 50,
    },
}


MODE_MAP = {
    "strict": STRICT_OVERRIDES,
    "balanced": BALANCED_OVERRIDES,
    "permissive": PERMISSIVE_OVERRIDES,
}


def get_mode_overrides(mode: str) -> Dict[str, Any]:
    """Get configuration overrides for a scan mode.
    
    Args:
        mode: One of "strict", "balanced", "permissive".
        
    Returns:
        Dict of config overrides to apply.
    """
    return MODE_MAP.get(mode.lower(), BALANCED_OVERRIDES).copy()


def list_modes() -> list:
    """List all available scan modes with descriptions."""
    return [
        {
            "name": "strict",
            "description": "All analyzers, aggressive rules, strict thresholds. For security audits.",
        },
        {
            "name": "balanced",
            "description": "All analyzers, balanced rules. Default for development.",
        },
        {
            "name": "permissive",
            "description": "Reduced analyzers, critical/high only. For quick checks.",
        },
    ]
