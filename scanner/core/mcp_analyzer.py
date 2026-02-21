"""
MCP Analyzer - Analyzes MCP server configurations for security issues.

Detects:
- SSRF vectors
- Credential exposure
- Unrestricted network access
- Missing TLS
- Command injection in server configs

Uses YAML-based rules for easy rule management.
"""

import re
from dataclasses import dataclass
from typing import Optional, List, Dict, Any

from .plugin_parser import PluginComponent
from .skill_analyzer import SecurityFinding
from ..rules.rule_loader import get_rule_loader, RuleLoader


class MCPAnalyzer:
    """Analyzes MCP server configurations for security vulnerabilities using YAML rules."""
    
    # Known safe MCP server commands
    KNOWN_SAFE_COMMANDS = {
        "npx",
        "node",
        "python",
        "python3",
        "uvx",
        "uv",
    }
    
    # Categories to scan for MCP configs
    MCP_SCAN_CATEGORIES = [
        "mcp-tools",
        "mcp-resources",
        "mcp-auth",
        "mcp-transport",
        "mcp-config",
        "sensitive-data",
        "command-injection",
    ]
    
    def __init__(self, rule_loader: Optional[RuleLoader] = None):
        """
        Initialize the MCP analyzer.
        
        Args:
            rule_loader: Optional custom rule loader. Uses global loader if not provided.
        """
        self.rule_loader = rule_loader or get_rule_loader()
        self.findings: List[SecurityFinding] = []
    
    def analyze(self, component: PluginComponent) -> List[SecurityFinding]:
        """Analyze an MCP server component for security issues."""
        self.findings = []
        
        if component.type != "mcp":
            return self.findings
        
        metadata = component.metadata
        config = metadata.get("config", {})
        
        # Analyze command
        self._analyze_command(component, metadata)
        
        # Analyze arguments
        self._analyze_args(component, metadata)
        
        # Analyze environment variables
        self._analyze_env(component, metadata)
        
        # Analyze working directory
        self._analyze_cwd(component, metadata)
        
        # Check for SSRF risks
        self._check_ssrf_risks(component, metadata)
        
        # Scan config with YAML rules
        config_str = str(metadata)
        if config_str:
            self._scan_with_rules(config_str, component)
        
        return self.findings
    
    def _scan_with_rules(
        self,
        content: str,
        component: PluginComponent
    ) -> None:
        """Scan content using YAML-defined rules."""
        # Get rules for MCP-relevant categories
        rules = []
        for category in self.MCP_SCAN_CATEGORIES:
            rules.extend(self.rule_loader.get_rules_by_category(category))
        
        # Deduplicate rules
        seen_ids = set()
        unique_rules = []
        for rule in rules:
            if rule.id not in seen_ids:
                seen_ids.add(rule.id)
                unique_rules.append(rule)
        
        # Scan with each rule
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
                    references=rule.references if rule.references else None
                ))
    
    def _analyze_command(self, component: PluginComponent, metadata: dict) -> None:
        """Analyze the server command."""
        command = metadata.get("command", "")
        
        if not command:
            self.findings.append(SecurityFinding(
                severity="high",
                rule_id="empty-mcp-command",
                rule_name="Empty MCP Command",
                message="MCP server has no command specified",
                component_type=component.type,
                component_name=component.name,
                component_path=component.path,
                recommendation="Specify a valid command for the MCP server"
            ))
            return
        
        # Extract base command (first word)
        base_command = command.split()[0] if command else ""
        base_command = base_command.split("/")[-1]  # Get basename
        
        # Check for path traversal in command
        if "../" in command:
            self.findings.append(SecurityFinding(
                severity="high",
                rule_id="mcp-path-traversal",
                rule_name="Path Traversal in MCP Command",
                message=f"MCP command contains path traversal: {command}",
                component_type=component.type,
                component_name=component.name,
                component_path=component.path,
                recommendation="Use ${CLAUDE_PLUGIN_ROOT} for plugin-relative paths"
            ))
        
        # Check if command uses plugin root variable
        if command.startswith("./") and "${CLAUDE_PLUGIN_ROOT}" not in command:
            self.findings.append(SecurityFinding(
                severity="medium",
                rule_id="mcp-relative-path",
                rule_name="Relative Path Without Root Variable",
                message=f"MCP command uses relative path: {command}",
                component_type=component.type,
                component_name=component.name,
                component_path=component.path,
                recommendation="Prefix with ${CLAUDE_PLUGIN_ROOT} for consistent paths"
            ))
        
        # Check for shell execution
        if base_command in ["sh", "bash", "zsh", "fish"]:
            self.findings.append(SecurityFinding(
                severity="high",
                rule_id="mcp-shell-execution",
                rule_name="Shell Execution in MCP",
                message=f"MCP server executes shell directly: {command}",
                component_type=component.type,
                component_name=component.name,
                component_path=component.path,
                recommendation="Avoid shell execution; run the target command directly"
            ))
        
        # Check for curl/wget (network fetch)
        if base_command in ["curl", "wget"]:
            self.findings.append(SecurityFinding(
                severity="high",
                rule_id="mcp-network-fetch",
                rule_name="Network Fetch as MCP Server",
                message=f"MCP server uses network fetch tool: {base_command}",
                component_type=component.type,
                component_name=component.name,
                component_path=component.path,
                recommendation="MCP servers should be dedicated server binaries, not network tools"
            ))
    
    def _analyze_args(self, component: PluginComponent, metadata: dict) -> None:
        """Analyze server arguments."""
        args = metadata.get("args", [])
        
        if not args:
            return
        
        args_str = " ".join(str(arg) for arg in args)
        
        # Check for dangerous argument patterns
        dangerous_patterns = [
            (r"--allow-all", "Unrestricted permissions flag"),
            (r"--no-sandbox", "Sandbox disabled"),
            (r"--disable-security", "Security disabled"),
            (r"-e\s+['\"]", "Inline code execution"),
            (r"--eval", "Eval flag"),
            (r"--shell", "Shell access flag"),
        ]
        
        for pattern, description in dangerous_patterns:
            if re.search(pattern, args_str, re.IGNORECASE):
                self.findings.append(SecurityFinding(
                    severity="high",
                    rule_id="dangerous-mcp-args",
                    rule_name="Dangerous MCP Arguments",
                    message=f"{description}: {args_str[:100]}",
                    component_type=component.type,
                    component_name=component.name,
                    component_path=component.path,
                    recommendation="Remove dangerous flags; use restrictive configurations"
                ))
        
        # Sensitive patterns for detecting hardcoded credentials
        sensitive_patterns = [
            (r"(?i)(api[_-]?key|apikey)", "API key in environment"),
            (r"(?i)(password|passwd|pwd)", "Password in environment"),
            (r"(?i)(secret)", "Secret in environment"),
            (r"(?i)(token)", "Token in environment"),
            (r"(?i)(private[_-]?key)", "Private key in environment"),
            (r"(?i)(credential)", "Credential in environment"),
            (r"(?i)(auth)", "Auth value in environment"),
            (r"(?i)(connection[_-]?string)", "Connection string in environment"),
        ]
        
        # Check for hardcoded sensitive values in args
        for arg in args:
            arg_str = str(arg)
            for pattern, description in sensitive_patterns:
                if re.search(pattern, arg_str, re.IGNORECASE):
                    # Check if it looks like a value (contains = with non-variable right side)
                    if "=" in arg_str and not arg_str.split("=")[1].startswith("$"):
                        self.findings.append(SecurityFinding(
                            severity="high",
                            rule_id="hardcoded-credential-args",
                            rule_name="Hardcoded Credential in Arguments",
                            message=f"{description} appears hardcoded in args",
                            component_type=component.type,
                            component_name=component.name,
                            component_path=component.path,
                            recommendation="Use environment variables for sensitive values"
                        ))
                    break
        
        # Check for URL arguments
        for arg in args:
            arg_str = str(arg)
            if re.match(r"https?://", arg_str, re.IGNORECASE):
                if arg_str.startswith("http://"):
                    self.findings.append(SecurityFinding(
                        severity="medium",
                        rule_id="insecure-mcp-url",
                        rule_name="Insecure HTTP URL in MCP Args",
                        message=f"MCP server uses insecure HTTP: {arg_str}",
                        component_type=component.type,
                        component_name=component.name,
                        component_path=component.path,
                        recommendation="Use HTTPS for all network communications"
                    ))
                
                # Check for variable interpolation in URLs
                if "${" in arg_str or "$(" in arg_str:
                    self.findings.append(SecurityFinding(
                        severity="high",
                        rule_id="mcp-url-injection",
                        rule_name="URL Injection Risk in MCP",
                        message=f"MCP URL contains variable interpolation: {arg_str}",
                        component_type=component.type,
                        component_name=component.name,
                        component_path=component.path,
                        recommendation="Validate URL construction; avoid user-controlled URL parts"
                    ))
    
    def _analyze_env(self, component: PluginComponent, metadata: dict) -> None:
        """Analyze environment variables."""
        env = metadata.get("env", {})
        
        if not env:
            return
        
        sensitive_patterns = [
            (r"(?i)(api[_-]?key|apikey)", "API key"),
            (r"(?i)(password|passwd|pwd)", "Password"),
            (r"(?i)(secret)", "Secret"),
            (r"(?i)(token)", "Token"),
            (r"(?i)(private[_-]?key)", "Private key"),
            (r"(?i)(credential)", "Credential"),
            (r"(?i)(auth)", "Auth value"),
            (r"(?i)(connection[_-]?string)", "Connection string"),
        ]
        
        for key, value in env.items():
            value_str = str(value)
            
            # Check for hardcoded sensitive values
            for pattern, description in sensitive_patterns:
                if re.search(pattern, key, re.IGNORECASE):
                    # Check if value looks hardcoded (not a variable reference)
                    if not value_str.startswith("$") and not value_str.startswith("${"):
                        if len(value_str) > 0 and value_str not in ["true", "false", "1", "0"]:
                            self.findings.append(SecurityFinding(
                                severity="critical",
                                rule_id="hardcoded-secret-env",
                                rule_name="Hardcoded Secret in Environment",
                                message=f"Sensitive value '{key}' appears hardcoded",
                                component_type=component.type,
                                component_name=component.name,
                                component_path=component.path,
                                recommendation="Use external secrets management; never hardcode credentials"
                            ))
                    break
            
            # Check for path traversal in env values
            if "../" in value_str:
                self.findings.append(SecurityFinding(
                    severity="medium",
                    rule_id="env-path-traversal",
                    rule_name="Path Traversal in Environment",
                    message=f"Environment variable '{key}' contains path traversal",
                    component_type=component.type,
                    component_name=component.name,
                    component_path=component.path,
                    recommendation="Use ${CLAUDE_PLUGIN_ROOT} for plugin paths"
                ))
    
    def _analyze_cwd(self, component: PluginComponent, metadata: dict) -> None:
        """Analyze working directory configuration."""
        cwd = metadata.get("cwd", "")
        
        if not cwd:
            return
        
        # Check for path traversal
        if "../" in cwd:
            self.findings.append(SecurityFinding(
                severity="high",
                rule_id="cwd-path-traversal",
                rule_name="Path Traversal in Working Directory",
                message=f"MCP cwd contains path traversal: {cwd}",
                component_type=component.type,
                component_name=component.name,
                component_path=component.path,
                recommendation="Use ${CLAUDE_PLUGIN_ROOT} for working directory"
            ))
        
        # Check for absolute paths outside plugin
        if cwd.startswith("/") and "${CLAUDE_PLUGIN_ROOT}" not in cwd:
            self.findings.append(SecurityFinding(
                severity="medium",
                rule_id="absolute-cwd",
                rule_name="Absolute Working Directory",
                message=f"MCP uses absolute cwd outside plugin: {cwd}",
                component_type=component.type,
                component_name=component.name,
                component_path=component.path,
                recommendation="Use ${CLAUDE_PLUGIN_ROOT} for portable paths"
            ))
    
    def _check_ssrf_risks(self, component: PluginComponent, metadata: dict) -> None:
        """Check for Server-Side Request Forgery risks."""
        config = metadata.get("config", {})
        args = metadata.get("args", [])
        env = metadata.get("env", {})
        
        # Combine all config for analysis
        config_str = str(config) + str(args) + str(env)
        
        # Check for internal network references
        internal_patterns = [
            (r"localhost", "Reference to localhost"),
            (r"127\.0\.0\.1", "Reference to loopback IP"),
            (r"0\.0\.0\.0", "Reference to all interfaces"),
            (r"192\.168\.\d+\.\d+", "Private network IP (192.168.x.x)"),
            (r"10\.\d+\.\d+\.\d+", "Private network IP (10.x.x.x)"),
            (r"172\.(1[6-9]|2[0-9]|3[01])\.\d+\.\d+", "Private network IP (172.16-31.x.x)"),
            (r"169\.254\.\d+\.\d+", "Link-local IP"),
            (r"metadata\.google", "Cloud metadata endpoint"),
            (r"169\.254\.169\.254", "AWS/Cloud metadata IP"),
        ]
        
        for pattern, description in internal_patterns:
            if re.search(pattern, config_str, re.IGNORECASE):
                self.findings.append(SecurityFinding(
                    severity="high",
                    rule_id="ssrf-risk",
                    rule_name="SSRF Risk",
                    message=f"{description} found in MCP configuration",
                    component_type=component.type,
                    component_name=component.name,
                    component_path=component.path,
                    recommendation="Avoid internal network references; implement URL allowlists"
                ))
    
    def get_summary(self) -> Dict[str, Any]:
        """Get a summary of findings."""
        severity_counts = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
        }
        
        for finding in self.findings:
            if finding.severity in severity_counts:
                severity_counts[finding.severity] += 1
        
        return {
            "total": len(self.findings),
            "by_severity": severity_counts,
        }
