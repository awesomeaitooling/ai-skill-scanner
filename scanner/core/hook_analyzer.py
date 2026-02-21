"""
Hook Analyzer - Analyzes hooks configurations for security issues.

Detects:
- Arbitrary command execution
- Unsafe script paths
- Overly broad matchers
- Missing executable checks
- Event hijacking risks

Uses YAML-based rules for easy rule management.
"""

import re
from dataclasses import dataclass
from typing import Optional, List, Dict, Any

from .plugin_parser import PluginComponent
from .skill_analyzer import SecurityFinding
from ..rules.rule_loader import get_rule_loader, RuleLoader


class HookAnalyzer:
    """Analyzes hook configurations for security vulnerabilities using YAML rules."""
    
    # Valid hook events
    VALID_EVENTS = {
        "PreToolUse",
        "PostToolUse",
        "PostToolUseFailure",
        "PermissionRequest",
        "UserPromptSubmit",
        "Notification",
        "Stop",
        "SubagentStart",
        "SubagentStop",
        "SessionStart",
        "SessionEnd",
        "PreCompact",
    }
    
    # Categories to scan for hooks
    HOOK_SCAN_CATEGORIES = [
        "hook-events",
        "hook-behavior",
        "hook-execution",
        "hook-config",
        "command-injection",
        "dangerous-command",
        "prompt-injection",
    ]
    
    def __init__(self, rule_loader: Optional[RuleLoader] = None):
        """
        Initialize the hook analyzer.
        
        Args:
            rule_loader: Optional custom rule loader. Uses global loader if not provided.
        """
        self.rule_loader = rule_loader or get_rule_loader()
        self.findings: List[SecurityFinding] = []
    
    def analyze(self, component: PluginComponent) -> List[SecurityFinding]:
        """Analyze a hook component for security issues."""
        self.findings = []
        
        if component.type != "hook":
            return self.findings
        
        metadata = component.metadata
        content = component.content or ""
        
        # Check event validity
        event = metadata.get("event", "")
        if event and event not in self.VALID_EVENTS:
            self.findings.append(SecurityFinding(
                severity="medium",
                rule_id="invalid-hook-event",
                rule_name="Invalid Hook Event",
                message=f"Unknown hook event: {event}",
                component_type=component.type,
                component_name=component.name,
                component_path=component.path,
                recommendation="Use only documented hook events"
            ))
        
        # Check matcher patterns
        self._check_matcher(component, metadata)
        
        # Check hook type and configuration
        hook_type = metadata.get("hook_type", "")
        
        if hook_type == "command":
            self._analyze_command_hook(component, metadata)
        elif hook_type == "prompt":
            self._analyze_prompt_hook(component, metadata)
        elif hook_type == "agent":
            self._analyze_agent_hook(component, metadata)
        
        # Scan any script content with YAML rules
        if content:
            self._scan_with_rules(content, component)
        
        return self.findings
    
    def _scan_with_rules(
        self,
        content: str,
        component: PluginComponent
    ) -> None:
        """Scan content using YAML-defined rules."""
        lines = content.split("\n")
        
        # Get rules for hook-relevant categories
        rules = []
        for category in self.HOOK_SCAN_CATEGORIES:
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
                line_num = content[:match.start()].count("\n") + 1
                snippet = self._get_snippet(lines, line_num)
                
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
                    line=line_num,
                    snippet=snippet,
                    recommendation=rule.recommendation,
                    references=rule.references if rule.references else None
                ))
    
    def _check_matcher(self, component: PluginComponent, metadata: dict) -> None:
        """Check matcher pattern for security issues."""
        matcher = metadata.get("matcher", "")
        
        # Check for overly broad matchers
        broad_matchers = [".*", "*", ".+", "\\w+", "\\S+"]
        if matcher in broad_matchers:
            self.findings.append(SecurityFinding(
                severity="medium",
                rule_id="broad-hook-matcher",
                rule_name="Overly Broad Hook Matcher",
                message=f"Hook matches all tools with pattern: {matcher}",
                component_type=component.type,
                component_name=component.name,
                component_path=component.path,
                recommendation="Use specific tool matchers (e.g., 'Write|Edit') instead of wildcards"
            ))
        
        # Check for regex injection in matcher
        if any(c in matcher for c in ["(?", "(?(", "(?P<", "(?#"]):
            self.findings.append(SecurityFinding(
                severity="high",
                rule_id="regex-complexity",
                rule_name="Complex Regex Pattern",
                message=f"Complex regex features in matcher: {matcher}",
                component_type=component.type,
                component_name=component.name,
                component_path=component.path,
                recommendation="Use simple regex patterns; avoid advanced features"
            ))
    
    def _analyze_command_hook(self, component: PluginComponent, metadata: dict) -> None:
        """Analyze command-type hooks."""
        command = metadata.get("command", "")
        
        if not command:
            self.findings.append(SecurityFinding(
                severity="medium",
                rule_id="empty-hook-command",
                rule_name="Empty Hook Command",
                message="Hook has no command specified",
                component_type=component.type,
                component_name=component.name,
                component_path=component.path,
                recommendation="Specify a valid command for the hook"
            ))
            return
        
        # Check for path traversal
        if "../" in command or command.startswith("/"):
            if "${CLAUDE_PLUGIN_ROOT}" not in command:
                self.findings.append(SecurityFinding(
                    severity="high",
                    rule_id="hook-path-traversal",
                    rule_name="Path Traversal in Hook",
                    message=f"Hook command references path outside plugin root: {command}",
                    component_type=component.type,
                    component_name=component.name,
                    component_path=component.path,
                    recommendation="Use ${CLAUDE_PLUGIN_ROOT} for all plugin paths"
                ))
        
        # Check for missing CLAUDE_PLUGIN_ROOT
        if command.startswith("./") and "${CLAUDE_PLUGIN_ROOT}" not in command:
            self.findings.append(SecurityFinding(
                severity="medium",
                rule_id="relative-path-hook",
                rule_name="Relative Path Without Root Variable",
                message=f"Hook uses relative path without ${'{CLAUDE_PLUGIN_ROOT}'}: {command}",
                component_type=component.type,
                component_name=component.name,
                component_path=component.path,
                recommendation="Prefix paths with ${CLAUDE_PLUGIN_ROOT}"
            ))
        
        # Check for dangerous command patterns using YAML rules
        dangerous_patterns = [
            (r"rm\s+-rf", "Recursive delete command"),
            (r"curl\s+.*\|\s*(ba)?sh", "Curl pipe to shell - remote code execution"),
            (r"wget\s+.*\|\s*(ba)?sh", "Wget pipe to shell - remote code execution"),
            (r"eval\s+", "Eval command - arbitrary code execution"),
            (r"nc\s+-e", "Netcat with execute - reverse shell risk"),
            (r"bash\s+-i", "Interactive bash - shell access"),
            (r"/dev/tcp/", "Bash network redirection"),
            (r"python\s+-c", "Python inline execution"),
            (r"node\s+-e", "Node inline execution"),
            (r"perl\s+-e", "Perl inline execution"),
            (r"ruby\s+-e", "Ruby inline execution"),
        ]
        
        for pattern, description in dangerous_patterns:
            if re.search(pattern, command, re.IGNORECASE):
                self.findings.append(SecurityFinding(
                    severity="critical",
                    rule_id="dangerous-hook-command",
                    rule_name="Dangerous Hook Command",
                    message=f"{description}: {command[:100]}",
                    component_type=component.type,
                    component_name=component.name,
                    component_path=component.path,
                    recommendation="Avoid dangerous shell commands; use safe alternatives"
                ))
        
        # Check for environment variable injection
        env_patterns = [
            (r"\$[A-Z_]+[^A-Z_\s/]", "Unquoted environment variable"),
            (r"\$\{[^}]*:-[^}]*\}", "Default value expansion - potential injection"),
            (r"export\s+[A-Z_]+=.*\$", "Export with variable expansion"),
        ]
        
        for pattern, description in env_patterns:
            if re.search(pattern, command):
                self.findings.append(SecurityFinding(
                    severity="high",
                    rule_id="env-injection-hook",
                    rule_name="Environment Variable Injection Risk",
                    message=f"{description} in hook command",
                    component_type=component.type,
                    component_name=component.name,
                    component_path=component.path,
                    recommendation="Quote environment variables; validate before use"
                ))
        
        # Check for command chaining
        if re.search(r"[;&|]{1,2}", command):
            self.findings.append(SecurityFinding(
                severity="high",
                rule_id="command-chaining",
                rule_name="Command Chaining in Hook",
                message=f"Hook command contains chaining operators: {command[:100]}",
                component_type=component.type,
                component_name=component.name,
                component_path=component.path,
                recommendation="Avoid command chaining; use separate hook entries"
            ))
    
    def _analyze_prompt_hook(self, component: PluginComponent, metadata: dict) -> None:
        """Analyze prompt-type hooks."""
        prompt = metadata.get("prompt", "")
        config = metadata.get("config", {})
        
        if not prompt:
            self.findings.append(SecurityFinding(
                severity="medium",
                rule_id="empty-hook-prompt",
                rule_name="Empty Hook Prompt",
                message="Prompt hook has no prompt specified",
                component_type=component.type,
                component_name=component.name,
                component_path=component.path,
                recommendation="Specify a valid prompt for the hook"
            ))
            return
        
        # Check for $ARGUMENTS usage (injection risk)
        if "$ARGUMENTS" in prompt:
            self.findings.append(SecurityFinding(
                severity="medium",
                rule_id="arguments-injection",
                rule_name="Arguments Injection Risk",
                message="Prompt uses $ARGUMENTS placeholder which may contain untrusted data",
                component_type=component.type,
                component_name=component.name,
                component_path=component.path,
                recommendation="Validate and sanitize $ARGUMENTS content before use"
            ))
        
        # Check for system prompt manipulation
        system_patterns = [
            r"you\s+are\s+now",
            r"ignore\s+previous",
            r"new\s+instructions",
        ]
        
        for pattern in system_patterns:
            if re.search(pattern, prompt, re.IGNORECASE):
                self.findings.append(SecurityFinding(
                    severity="high",
                    rule_id="prompt-manipulation",
                    rule_name="Prompt Manipulation Pattern",
                    message=f"Hook prompt contains manipulation pattern: {pattern}",
                    component_type=component.type,
                    component_name=component.name,
                    component_path=component.path,
                    recommendation="Review prompt content for unintended behavior modification"
                ))
    
    def _analyze_agent_hook(self, component: PluginComponent, metadata: dict) -> None:
        """Analyze agent-type hooks."""
        config = metadata.get("config", {})
        
        # Agent hooks are powerful - flag for review
        self.findings.append(SecurityFinding(
            severity="medium",
            rule_id="agent-hook-review",
            rule_name="Agent Hook Requires Review",
            message="Agent-type hooks have full tool access and require security review",
            component_type=component.type,
            component_name=component.name,
            component_path=component.path,
            recommendation="Review agent hook capabilities and tool access permissions"
        ))
        
        # Check if agent has specific tool restrictions
        if "allowedTools" not in config and "tools" not in config:
            self.findings.append(SecurityFinding(
                severity="high",
                rule_id="unrestricted-agent-hook",
                rule_name="Unrestricted Agent Hook",
                message="Agent hook has no tool restrictions defined",
                component_type=component.type,
                component_name=component.name,
                component_path=component.path,
                recommendation="Define explicit tool allowlist for agent hooks"
            ))
    
    def _get_snippet(self, lines: List[str], line_num: int, context: int = 2) -> str:
        """Get a code snippet around the specified line."""
        start = max(0, line_num - context - 1)
        end = min(len(lines), line_num + context)
        snippet_lines = lines[start:end]
        
        return "\n".join(
            f"{i + start + 1}: {line}"
            for i, line in enumerate(snippet_lines)
        )
    
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
