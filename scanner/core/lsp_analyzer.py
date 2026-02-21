"""
LSP Analyzer — Analyzes LSP (Language Server Protocol) server configurations.

Detects:
- Insecure transport (HTTP instead of HTTPS)
- Command injection in server commands
- Exposed ports / binding to all interfaces
- Debug mode enabled in production
- Unrestricted access / missing auth
- Path traversal in server config

Mirrors the MCP analyzer structure for consistency.
"""

import re
from typing import Optional, List, Dict, Any

from .plugin_parser import PluginComponent
from .skill_analyzer import SecurityFinding
from ..rules.rule_loader import get_rule_loader, RuleLoader


class LSPAnalyzer:
    """Analyzes LSP server configurations for security vulnerabilities."""

    # Categories to scan for LSP configs
    LSP_SCAN_CATEGORIES = [
        "sensitive-data",
        "command-injection",
        "dangerous-command",
    ]

    def __init__(self, rule_loader: Optional[RuleLoader] = None):
        self.rule_loader = rule_loader or get_rule_loader()
        self.findings: List[SecurityFinding] = []

    def analyze(self, component: PluginComponent) -> List[SecurityFinding]:
        """Analyze an LSP server component for security issues."""
        self.findings = []

        if component.type != "lsp":
            return self.findings

        metadata = component.metadata

        # Analyze command
        self._analyze_command(component, metadata)

        # Analyze arguments
        self._analyze_args(component, metadata)

        # Analyze transport
        self._analyze_transport(component, metadata)

        # Scan config string with YAML rules
        config_str = str(metadata)
        if config_str:
            self._scan_with_rules(config_str, component)

        return self.findings

    def _scan_with_rules(self, content: str, component: PluginComponent) -> None:
        """Scan content using YAML-defined rules."""
        rules = []
        for category in self.LSP_SCAN_CATEGORIES:
            rules.extend(self.rule_loader.get_rules_by_category(category))

        seen_ids: set = set()
        unique_rules = []
        for rule in rules:
            if rule.id not in seen_ids:
                seen_ids.add(rule.id)
                unique_rules.append(rule)

        for rule in unique_rules:
            if not rule.enabled:
                continue
            matches = rule.match(content)
            for match in matches:
                matched_text = match.group()
                if len(matched_text) > 50:
                    matched_text = matched_text[:50] + "..."
                self.findings.append(SecurityFinding(
                    severity=rule.severity,
                    rule_id=rule.id,
                    rule_name=rule.name,
                    message=f"{rule.description}: '{matched_text}'",
                    component_type=component.type,
                    component_name=component.name,
                    component_path=component.path,
                    recommendation=rule.recommendation,
                    references=rule.references if rule.references else None,
                ))

    def _analyze_command(self, component: PluginComponent, metadata: dict) -> None:
        """Analyze the LSP server command."""
        command = metadata.get("command", "")

        if not command:
            self.findings.append(SecurityFinding(
                severity="high",
                rule_id="empty-lsp-command",
                rule_name="Empty LSP Command",
                message="LSP server has no command specified",
                component_type=component.type,
                component_name=component.name,
                component_path=component.path,
                recommendation="Specify a valid command for the LSP server",
            ))
            return

        base_command = command.split()[0].split("/")[-1] if command else ""

        # Path traversal
        if "../" in command:
            self.findings.append(SecurityFinding(
                severity="high",
                rule_id="lsp-path-traversal",
                rule_name="Path Traversal in LSP Command",
                message=f"LSP command contains path traversal: {command}",
                component_type=component.type,
                component_name=component.name,
                component_path=component.path,
                recommendation="Use absolute paths or ${CLAUDE_PLUGIN_ROOT} for plugin-relative paths",
            ))

        # Direct shell execution
        if base_command in ("sh", "bash", "zsh", "fish"):
            self.findings.append(SecurityFinding(
                severity="high",
                rule_id="lsp-shell-execution",
                rule_name="Shell Execution in LSP",
                message=f"LSP server executes shell directly: {command}",
                component_type=component.type,
                component_name=component.name,
                component_path=component.path,
                recommendation="Avoid shell execution; run the target language server directly",
            ))

    def _analyze_args(self, component: PluginComponent, metadata: dict) -> None:
        """Analyze server arguments."""
        args = metadata.get("args", [])
        if not args:
            return

        args_str = " ".join(str(a) for a in args)

        dangerous_patterns = [
            (r"--allow-all", "Unrestricted permissions flag"),
            (r"--no-sandbox", "Sandbox disabled"),
            (r"--disable-security", "Security disabled"),
            (r"-e\s+['\"]", "Inline code execution"),
            (r"--debug", "Debug mode enabled"),
        ]

        for pattern, description in dangerous_patterns:
            if re.search(pattern, args_str, re.IGNORECASE):
                self.findings.append(SecurityFinding(
                    severity="high" if "security" in description.lower() else "medium",
                    rule_id="dangerous-lsp-args",
                    rule_name="Dangerous LSP Arguments",
                    message=f"{description}: {args_str[:100]}",
                    component_type=component.type,
                    component_name=component.name,
                    component_path=component.path,
                    recommendation="Remove dangerous flags; use restrictive configurations",
                ))

    def _analyze_transport(self, component: PluginComponent, metadata: dict) -> None:
        """Analyze transport configuration."""
        transport = metadata.get("transport", "stdio")
        config = metadata.get("config", {})
        args = metadata.get("args", [])
        config_str = str(config) + " " + " ".join(str(a) for a in args)

        # Non-stdio transports are riskier
        if transport != "stdio":
            if transport in ("tcp", "socket"):
                self.findings.append(SecurityFinding(
                    severity="medium",
                    rule_id="lsp-network-transport",
                    rule_name="Network Transport for LSP",
                    message=f"LSP server uses network transport: {transport}",
                    component_type=component.type,
                    component_name=component.name,
                    component_path=component.path,
                    recommendation="Prefer stdio transport; if network is needed, bind to localhost only",
                ))

        # Check for binding to all interfaces
        if re.search(r"0\.0\.0\.0", config_str):
            self.findings.append(SecurityFinding(
                severity="high",
                rule_id="lsp-exposed-port",
                rule_name="LSP Server Exposed on All Interfaces",
                message="LSP server binds to 0.0.0.0 (all interfaces)",
                component_type=component.type,
                component_name=component.name,
                component_path=component.path,
                recommendation="Bind to 127.0.0.1 (localhost) instead of 0.0.0.0",
            ))

        # Check for insecure HTTP
        if re.search(r"http://", config_str, re.IGNORECASE):
            self.findings.append(SecurityFinding(
                severity="medium",
                rule_id="lsp-insecure-transport",
                rule_name="Insecure HTTP Transport for LSP",
                message="LSP configuration references insecure HTTP",
                component_type=component.type,
                component_name=component.name,
                component_path=component.path,
                recommendation="Use HTTPS for network communications",
            ))

    def get_summary(self) -> Dict[str, Any]:
        """Get a summary of findings."""
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for finding in self.findings:
            if finding.severity in severity_counts:
                severity_counts[finding.severity] += 1
        return {"total": len(self.findings), "by_severity": severity_counts}
