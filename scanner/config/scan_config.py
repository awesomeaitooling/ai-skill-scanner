"""
Scan Configuration — Loads and merges configuration from multiple sources.

Priority (highest to lowest):
1. CLI arguments
2. Config file (config.yaml)
3. Environment variables
4. Scan mode defaults (strict/balanced/permissive)
5. Built-in defaults
"""

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

try:
    import yaml
except ImportError:
    yaml = None  # type: ignore


# ── Built-in defaults ──────────────────────────────────────────────

DEFAULT_CONFIG: Dict[str, Any] = {
    "scan_mode": "balanced",

    # Analyzers to enable
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

    # Component types to scan
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

    # Rule configuration
    "rules": {
        "disabled_rules": [],           # Rule IDs to skip
        "disabled_categories": [],      # Categories to skip entirely
        "severity_overrides": {},       # {"rule-id": "new-severity"}
        "custom_rules_dir": None,       # Path to additional YAML rule files
    },

    # File handling
    "files": {
        "script_extensions": [".py", ".sh", ".bash", ".js", ".ts", ".rb", ".pl", ".zsh"],
        "resource_text_extensions": [
            ".yaml", ".yml", ".json", ".toml", ".cfg", ".ini", ".txt",
            ".template", ".tmpl", ".conf", ".properties", ".xml", ".csv",
            ".sql", ".graphql",
        ],
        "binary_extensions": [
            ".exe", ".dll", ".so", ".bin", ".wasm", ".jar", ".apk",
            ".dmg", ".msi", ".iso", ".img", ".deb", ".rpm",
        ],
        "max_file_size_kb": 500,
        "exclude_paths": [
            "node_modules",
            ".git",
            "__pycache__",
            ".venv",
            "venv",
        ],
    },

    # AI settings
    "ai": {
        "enabled": False,
        "provider": None,  # "openai", "anthropic", "bedrock", "azure_openai", "gemini"
        "model": None,
        "max_tokens": 8192,
        "temperature": 0.0,
        "prompt_injection_guard": True,
        "max_content_per_component": 1500,
        "max_total_content": 12000,
    },

    # Output configuration
    "output": {
        "format": "text",       # "text", "json", "sarif", "graph", "csv"
        "output_file": None,
        "verbose": False,
        "show_snippets": True,
        "max_findings_display": 100,
        "color": True,
    },

    # Thresholds
    "thresholds": {
        "fail_on_critical": True,
        "fail_on_high": False,
        "max_critical": 0,
        "max_high": -1,         # -1 = no limit
        "max_medium": -1,
        "max_low": -1,
    },

    # Logging
    "logging": {
        "level": "INFO",
        "file": None,
        "redact_secrets": True,
    },
}


@dataclass
class AnalyzerConfig:
    """Which analyzers to run."""
    skill_analyzer: bool = True
    script_analyzer: bool = True
    hook_analyzer: bool = True
    mcp_analyzer: bool = True
    lsp_analyzer: bool = True
    agent_command_analyzer: bool = True
    ast_analyzer: bool = True
    dataflow_analyzer: bool = True
    alignment_analyzer: bool = True
    cross_skill_analyzer: bool = True
    meta_analyzer: bool = True


@dataclass
class ComponentConfig:
    """Which component types to scan."""
    skills: bool = True
    commands: bool = True
    agents: bool = True
    hooks: bool = True
    mcp_servers: bool = True
    lsp_servers: bool = True
    scripts: bool = True
    resources: bool = True


@dataclass
class RulesConfig:
    """Rule configuration."""
    disabled_rules: List[str] = field(default_factory=list)
    disabled_categories: List[str] = field(default_factory=list)
    severity_overrides: Dict[str, str] = field(default_factory=dict)
    custom_rules_dir: Optional[str] = None


@dataclass
class FilesConfig:
    """File handling configuration."""
    script_extensions: List[str] = field(default_factory=lambda: [
        ".py", ".sh", ".bash", ".js", ".ts", ".rb", ".pl", ".zsh"
    ])
    resource_text_extensions: List[str] = field(default_factory=lambda: [
        ".yaml", ".yml", ".json", ".toml", ".cfg", ".ini", ".txt",
        ".template", ".tmpl", ".conf", ".properties", ".xml", ".csv",
        ".sql", ".graphql",
    ])
    binary_extensions: List[str] = field(default_factory=lambda: [
        ".exe", ".dll", ".so", ".bin", ".wasm", ".jar", ".apk",
        ".dmg", ".msi", ".iso", ".img", ".deb", ".rpm",
    ])
    max_file_size_kb: int = 500
    exclude_paths: List[str] = field(default_factory=lambda: [
        "node_modules", ".git", "__pycache__", ".venv", "venv"
    ])


@dataclass
class AIConfig:
    """AI provider configuration."""
    enabled: bool = False
    provider: Optional[str] = None
    model: Optional[str] = None
    max_tokens: int = 8192
    temperature: float = 0.0
    prompt_injection_guard: bool = True
    max_content_per_component: int = 1500
    max_total_content: int = 12000


@dataclass
class OutputConfig:
    """Output configuration."""
    format: str = "text"
    output_file: Optional[str] = None
    verbose: bool = False
    show_snippets: bool = True
    max_findings_display: int = 100
    color: bool = True


@dataclass
class ThresholdsConfig:
    """Threshold configuration for CI/CD."""
    fail_on_critical: bool = True
    fail_on_high: bool = False
    max_critical: int = 0
    max_high: int = -1
    max_medium: int = -1
    max_low: int = -1


@dataclass
class LoggingConfig:
    """Logging configuration."""
    level: str = "INFO"
    file: Optional[str] = None
    redact_secrets: bool = True


@dataclass
class ScanConfig:
    """Top-level scan configuration."""
    scan_mode: str = "balanced"
    analyzers: AnalyzerConfig = field(default_factory=AnalyzerConfig)
    components: ComponentConfig = field(default_factory=ComponentConfig)
    rules: RulesConfig = field(default_factory=RulesConfig)
    files: FilesConfig = field(default_factory=FilesConfig)
    ai: AIConfig = field(default_factory=AIConfig)
    output: OutputConfig = field(default_factory=OutputConfig)
    thresholds: ThresholdsConfig = field(default_factory=ThresholdsConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)

    def is_analyzer_enabled(self, name: str) -> bool:
        """Check if a specific analyzer is enabled."""
        return getattr(self.analyzers, name, True)

    def is_component_enabled(self, comp_type: str) -> bool:
        """Check if a component type should be scanned."""
        mapping = {
            "skill": "skills",
            "command": "commands",
            "agent": "agents",
            "hook": "hooks",
            "mcp": "mcp_servers",
            "lsp": "lsp_servers",
            "script": "scripts",
            "resource": "resources",
        }
        attr = mapping.get(comp_type, comp_type)
        return getattr(self.components, attr, True)

    def is_rule_disabled(self, rule_id: str) -> bool:
        """Check if a specific rule is disabled."""
        return rule_id in self.rules.disabled_rules

    def is_category_disabled(self, category: str) -> bool:
        """Check if a rule category is disabled."""
        return category in self.rules.disabled_categories

    def get_severity_override(self, rule_id: str) -> Optional[str]:
        """Get severity override for a rule, if any."""
        return self.rules.severity_overrides.get(rule_id)


def _deep_merge(base: dict, override: dict) -> dict:
    """Deep merge override into base (override wins)."""
    result = base.copy()
    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def _load_from_file(config_path: Path) -> Dict[str, Any]:
    """Load configuration from a YAML file."""
    if yaml is None:
        return {}
    try:
        with open(config_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        return data
    except (FileNotFoundError, yaml.YAMLError):
        return {}


def _load_from_env() -> Dict[str, Any]:
    """Load configuration from environment variables."""
    env_config: Dict[str, Any] = {}

    # Scan mode
    mode = os.environ.get("SCANNER_MODE")
    if mode:
        env_config["scan_mode"] = mode

    # AI settings
    if os.environ.get("SCANNER_AI_PROVIDER"):
        env_config.setdefault("ai", {})["provider"] = os.environ["SCANNER_AI_PROVIDER"]
    if os.environ.get("SCANNER_AI_MODEL"):
        env_config.setdefault("ai", {})["model"] = os.environ["SCANNER_AI_MODEL"]
    if os.environ.get("SCANNER_AI_MAX_TOKENS"):
        env_config.setdefault("ai", {})["max_tokens"] = int(os.environ["SCANNER_AI_MAX_TOKENS"])

    # Verbose
    if os.environ.get("SCANNER_VERBOSE", "").lower() in ("1", "true", "yes"):
        env_config.setdefault("output", {})["verbose"] = True

    # Log level
    if os.environ.get("SCANNER_LOG_LEVEL"):
        env_config.setdefault("logging", {})["level"] = os.environ["SCANNER_LOG_LEVEL"]

    return env_config


def _config_dict_to_dataclass(data: Dict[str, Any]) -> ScanConfig:
    """Convert a merged config dict to a ScanConfig dataclass."""
    return ScanConfig(
        scan_mode=data.get("scan_mode", "balanced"),
        analyzers=AnalyzerConfig(**{
            k: v for k, v in data.get("analyzers", {}).items()
            if hasattr(AnalyzerConfig, k)
        }),
        components=ComponentConfig(**{
            k: v for k, v in data.get("components", {}).items()
            if hasattr(ComponentConfig, k)
        }),
        rules=RulesConfig(**{
            k: v for k, v in data.get("rules", {}).items()
            if hasattr(RulesConfig, k)
        }),
        files=FilesConfig(**{
            k: v for k, v in data.get("files", {}).items()
            if hasattr(FilesConfig, k)
        }),
        ai=AIConfig(**{
            k: v for k, v in data.get("ai", {}).items()
            if hasattr(AIConfig, k)
        }),
        output=OutputConfig(**{
            k: v for k, v in data.get("output", {}).items()
            if hasattr(OutputConfig, k)
        }),
        thresholds=ThresholdsConfig(**{
            k: v for k, v in data.get("thresholds", {}).items()
            if hasattr(ThresholdsConfig, k)
        }),
        logging=LoggingConfig(**{
            k: v for k, v in data.get("logging", {}).items()
            if hasattr(LoggingConfig, k)
        }),
    )


def load_config(
    config_path: Optional[str] = None,
    cli_overrides: Optional[Dict[str, Any]] = None,
) -> ScanConfig:
    """Load configuration with proper priority merging.
    
    Priority (highest to lowest):
    1. CLI arguments (cli_overrides)
    2. Config file
    3. Environment variables
    4. Built-in defaults
    
    Args:
        config_path: Path to config.yaml file. Auto-discovers if None.
        cli_overrides: Dict of CLI-level overrides.
    
    Returns:
        Merged ScanConfig instance.
    """
    # Start with built-in defaults
    merged = DEFAULT_CONFIG.copy()

    # Layer 2: Environment variables
    env_config = _load_from_env()
    if env_config:
        merged = _deep_merge(merged, env_config)

    # Layer 3: Config file
    if config_path:
        file_config = _load_from_file(Path(config_path))
    else:
        # Auto-discover config.yaml in CWD or scanner root
        candidates = [
            Path.cwd() / "config.yaml",
            Path.cwd() / ".scanner.yaml",
            Path(__file__).parent.parent.parent / "config.yaml",
        ]
        file_config = {}
        for candidate in candidates:
            if candidate.exists():
                file_config = _load_from_file(candidate)
                break

    if file_config:
        merged = _deep_merge(merged, file_config)

    # Layer 4: CLI overrides (highest priority)
    if cli_overrides:
        merged = _deep_merge(merged, cli_overrides)

    # Apply scan mode defaults if mode was set
    from .modes import get_mode_overrides
    mode = merged.get("scan_mode", "balanced")
    mode_overrides = get_mode_overrides(mode)
    # Mode overrides are LOW priority — only fill in where not explicitly set
    # We reverse the merge: mode is base, merged is override
    final = _deep_merge(mode_overrides, merged)

    return _config_dict_to_dataclass(final)
