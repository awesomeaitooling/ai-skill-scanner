"""
Skill Analyzer - Analyzes SKILL.md and command files for security issues.

Detects:
- Prompt injection patterns
- Command injection vulnerabilities
- Sensitive data exposure
- Unrestricted file access patterns
- External URL references

Uses YAML-based rules for easy rule management.
"""

import re
from dataclasses import dataclass
from typing import Optional, List, Dict, Any

from .plugin_parser import PluginComponent
from ..rules.rule_loader import get_rule_loader, RuleLoader


@dataclass
class SecurityFinding:
    """Represents a security finding."""
    
    severity: str  # critical, high, medium, low
    rule_id: str
    rule_name: str
    message: str
    component_type: str
    component_name: str
    component_path: str
    line: Optional[int] = None
    column: Optional[int] = None
    snippet: Optional[str] = None
    recommendation: Optional[str] = None
    references: Optional[List[str]] = None
    section: str = "code_security"  # "malicious" or "code_security"
    category: Optional[str] = None  # AI category (e.g. "prompt_injection")


class SkillAnalyzer:
    """Analyzes skills and commands for security vulnerabilities using YAML rules."""
    
    # Categories to scan for skills/commands
    SKILL_SCAN_CATEGORIES = [
        "prompt-injection",
        "command-injection",
        "dangerous-command",
        "sensitive-data",
        "path-traversal",
        "sensitive-file",
        "dangerous-directory",
        "access-control",
        "template-injection",
        "sql-injection",
        "nosql-injection",
        "xxe",
        "remote-code",
        "obfuscation",
    ]
    
    def __init__(self, rule_loader: Optional[RuleLoader] = None):
        """
        Initialize the skill analyzer.
        
        Args:
            rule_loader: Optional custom rule loader. Uses global loader if not provided.
        """
        self.rule_loader = rule_loader or get_rule_loader()
        self.findings: List[SecurityFinding] = []
    
    def analyze(self, component: PluginComponent) -> List[SecurityFinding]:
        """Analyze a skill or command component for security issues."""
        self.findings = []
        
        if not component.content:
            return self.findings
        
        content = component.content
        lines = content.split("\n")
        
        # Scan using YAML rules
        self._scan_with_rules(content, lines, component)
        
        # Additional content-based checks (not in YAML rules)
        self._check_privilege_escalation(content, lines, component)
        self._check_data_exfiltration(content, lines, component)
        self._check_external_urls(content, lines, component)
        
        # Frontmatter checks for skills/commands/agents
        if component.type in ("skill", "command", "agent"):
            self._check_frontmatter(component)
        
        return self.findings
    
    def _scan_with_rules(
        self,
        content: str,
        lines: List[str],
        component: PluginComponent
    ) -> None:
        """Scan content using YAML-defined rules."""
        # Get rules for skill-relevant categories
        rules = []
        for category in self.SKILL_SCAN_CATEGORIES:
            rules.extend(self.rule_loader.get_rules_by_category(category))
        
        # Deduplicate rules (same rule might be in multiple categories)
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
                
                # Truncate long matches
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
    
    def _check_privilege_escalation(
        self,
        content: str,
        lines: List[str],
        component: PluginComponent
    ) -> None:
        """Check for privilege escalation patterns."""
        escalation_patterns = [
            (r"sudo\s+", "Sudo command usage"),
            (r"as\s+root", "Root privilege request"),
            (r"admin\s+access", "Admin access request"),
            (r"elevated\s+privileges?", "Elevated privilege request"),
            (r"run\s+as\s+administrator", "Administrator execution"),
        ]
        
        for pattern, description in escalation_patterns:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                line_num = content[:match.start()].count("\n") + 1
                
                self.findings.append(SecurityFinding(
                    severity="high",
                    rule_id="privilege-escalation",
                    rule_name="Privilege Escalation",
                    message=f"{description} detected",
                    component_type=component.type,
                    component_name=component.name,
                    component_path=component.path,
                    line=line_num,
                    snippet=self._get_snippet(lines, line_num),
                    recommendation="Avoid requiring elevated privileges; follow principle of least privilege"
                ))
    
    def _check_data_exfiltration(
        self,
        content: str,
        lines: List[str],
        component: PluginComponent
    ) -> None:
        """Check for data exfiltration patterns."""
        exfil_patterns = [
            (r"send\s+(to|data|file)\s+.{0,20}(external|remote|server)", "External data transmission"),
            (r"upload\s+.{0,20}(to|server|remote)", "Data upload pattern"),
            (r"post\s+.{0,20}(to|endpoint|api)", "POST to external endpoint"),
            (r"exfiltrat", "Exfiltration keyword"),
        ]
        
        for pattern, description in exfil_patterns:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                line_num = content[:match.start()].count("\n") + 1
                
                self.findings.append(SecurityFinding(
                    severity="high",
                    rule_id="data-exfiltration",
                    rule_name="Data Exfiltration Risk",
                    message=f"{description} pattern detected",
                    component_type=component.type,
                    component_name=component.name,
                    component_path=component.path,
                    line=line_num,
                    snippet=self._get_snippet(lines, line_num),
                    recommendation="Review data transmission; implement data loss prevention controls"
                ))
    
    def _check_external_urls(
        self,
        content: str,
        lines: List[str],
        component: PluginComponent
    ) -> None:
        """Check for external URL patterns."""
        url_patterns = [
            (r"http://[^\s\"']+", "Insecure HTTP URL", "medium"),
            (r"https?://[^\s\"']*\$\{", "URL with variable interpolation", "high"),
            (r"fetch\s*\(\s*['\"]http://", "Fetch from HTTP URL", "medium"),
            (r"curl\s+http://", "Curl HTTP request", "medium"),
            (r"wget\s+http://", "Wget HTTP request", "medium"),
        ]
        
        for pattern, description, severity in url_patterns:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                line_num = content[:match.start()].count("\n") + 1
                
                self.findings.append(SecurityFinding(
                    severity=severity,
                    rule_id="external-url",
                    rule_name="External URL Reference",
                    message=f"{description}: {match.group()[:50]}",
                    component_type=component.type,
                    component_name=component.name,
                    component_path=component.path,
                    line=line_num,
                    snippet=self._get_snippet(lines, line_num),
                    recommendation="Use HTTPS; validate and allowlist external URLs"
                ))
    
    def _check_frontmatter(self, component: PluginComponent) -> None:
        """Check YAML frontmatter for security issues."""
        frontmatter = component.metadata.get("frontmatter")
        if not frontmatter or not isinstance(frontmatter, dict):
            return
        
        name = frontmatter.get("name", "")
        description = frontmatter.get("description", "")
        license_val = frontmatter.get("license")
        allowed_tools = frontmatter.get("allowed-tools", [])
        
        # Name checks
        if name:
            # Impersonation detection
            impersonation_terms = [
                "anthropic", "claude official", "openai official",
                "system", "admin", "root", "security",
            ]
            name_lower = name.lower()
            for term in impersonation_terms:
                if term in name_lower:
                    self.findings.append(SecurityFinding(
                        severity="medium",
                        rule_id="frontmatter-impersonation",
                        rule_name="Potential Impersonation in Name",
                        message=f"Skill name '{name}' contains impersonation term '{term}'",
                        component_type=component.type,
                        component_name=component.name,
                        component_path=component.path,
                        recommendation="Use a descriptive, non-impersonating name",
                    ))
            
            # Excessive name length
            if len(name) > 100:
                self.findings.append(SecurityFinding(
                    severity="low",
                    rule_id="frontmatter-name-length",
                    rule_name="Excessive Name Length",
                    message=f"Name is {len(name)} characters (max recommended: 100)",
                    component_type=component.type,
                    component_name=component.name,
                    component_path=component.path,
                    recommendation="Keep names concise and descriptive",
                ))
        
        # Description checks
        if description:
            if len(description) < 20:
                self.findings.append(SecurityFinding(
                    severity="low",
                    rule_id="frontmatter-vague-description",
                    rule_name="Vague Description",
                    message=f"Description is very short ({len(description)} chars): '{description}'",
                    component_type=component.type,
                    component_name=component.name,
                    component_path=component.path,
                    recommendation="Provide a specific, detailed description of what the skill does",
                ))
        else:
            self.findings.append(SecurityFinding(
                severity="low",
                rule_id="frontmatter-missing-description",
                rule_name="Missing Description",
                message="No description in frontmatter",
                component_type=component.type,
                component_name=component.name,
                component_path=component.path,
                recommendation="Add a description to help users understand the skill's purpose",
            ))
        
        # License check
        if not license_val:
            self.findings.append(SecurityFinding(
                severity="low",
                rule_id="frontmatter-missing-license",
                rule_name="Missing License",
                message="No license specified in frontmatter",
                component_type=component.type,
                component_name=component.name,
                component_path=component.path,
                recommendation="Specify a license for transparency",
            ))
        
        # Allowed-tools validation
        if allowed_tools and isinstance(allowed_tools, list):
            dangerous_tools = {"Bash", "Shell", "Terminal", "Execute"}
            declared = set(allowed_tools)
            risky = declared & dangerous_tools
            if risky:
                self.findings.append(SecurityFinding(
                    severity="medium",
                    rule_id="frontmatter-dangerous-tools",
                    rule_name="Dangerous Tools in allowed-tools",
                    message=f"Skill declares dangerous tools: {', '.join(risky)}",
                    component_type=component.type,
                    component_name=component.name,
                    component_path=component.path,
                    recommendation="Minimize tool access; prefer read-only tools where possible",
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
    
    def get_findings_by_severity(self, severity: str) -> List[SecurityFinding]:
        """Get findings filtered by severity."""
        return [f for f in self.findings if f.severity == severity.lower()]
    
    def get_findings_by_rule(self, rule_id: str) -> List[SecurityFinding]:
        """Get findings filtered by rule ID."""
        return [f for f in self.findings if f.rule_id == rule_id]
    
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
            "unique_rules": len(set(f.rule_id for f in self.findings)),
        }
