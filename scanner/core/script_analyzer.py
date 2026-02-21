"""
Script Analyzer — Analyzes Python, Bash, and JS/TS scripts for security issues.

Applies language-aware rule categories and additional script-specific checks
that go beyond what the generic SkillAnalyzer provides.
"""

import re
from typing import Optional, List, Dict, Any

from .plugin_parser import PluginComponent
from .skill_analyzer import SecurityFinding
from ..rules.rule_loader import get_rule_loader, RuleLoader


class ScriptAnalyzer:
    """Analyzes script files for security vulnerabilities using YAML rules."""

    # Rule categories applied to ALL scripts
    COMMON_CATEGORIES = [
        "command-injection",
        "dangerous-command",
        "sensitive-data",
        "path-traversal",
        "sensitive-file",
        "dangerous-directory",
        "remote-code",
        "obfuscation",
        "data-exfiltration",
        "resource-abuse",
        "unicode-steganography",
    ]

    # Additional categories for Python scripts
    PYTHON_CATEGORIES = [
        "template-injection",
        "sql-injection",
        "nosql-injection",
        "supply-chain",
    ]

    # Additional categories for Bash scripts
    BASH_CATEGORIES = [
        "autonomy-abuse",
    ]

    # Additional categories for JS/TS scripts
    JS_CATEGORIES = [
        "template-injection",
        "supply-chain",
    ]

    def __init__(self, rule_loader: Optional[RuleLoader] = None):
        self.rule_loader = rule_loader or get_rule_loader()
        self.findings: List[SecurityFinding] = []

    def analyze(self, component: PluginComponent) -> List[SecurityFinding]:
        """Analyze a script component for security issues."""
        self.findings = []

        if not component.content:
            # Check for binary scripts
            if component.metadata.get("is_binary"):
                self.findings.append(SecurityFinding(
                    severity="critical",
                    rule_id="binary-in-scripts",
                    rule_name="Binary Executable in Scripts",
                    message=f"Binary file detected in scripts: {component.name}",
                    component_type=component.type,
                    component_name=component.name,
                    component_path=component.path,
                    recommendation="Binary executables in plugin scripts are a significant risk. Review or remove."
                ))
            return self.findings

        content = component.content
        lines = content.split("\n")
        language = component.metadata.get("language", "unknown")

        # Determine which rule categories to apply
        categories = list(self.COMMON_CATEGORIES)
        if language == "python":
            categories.extend(self.PYTHON_CATEGORIES)
        elif language == "bash":
            categories.extend(self.BASH_CATEGORIES)
        elif language in ("javascript", "typescript"):
            categories.extend(self.JS_CATEGORIES)

        # Scan with YAML rules
        self._scan_with_rules(content, lines, component, categories)

        # Language-specific hardcoded checks
        if language == "python":
            self._check_python_specific(content, lines, component)
        elif language == "bash":
            self._check_bash_specific(content, lines, component)

        return self.findings

    def _scan_with_rules(
        self,
        content: str,
        lines: List[str],
        component: PluginComponent,
        categories: List[str],
    ) -> None:
        """Scan content using YAML rules filtered by categories."""
        rules = []
        for category in categories:
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
                line_num = content[: match.start()].count("\n") + 1
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
                    references=rule.references if rule.references else None,
                ))

    # ------------------------------------------------------------------
    # Python-specific checks
    # ------------------------------------------------------------------
    def _check_python_specific(
        self, content: str, lines: List[str], component: PluginComponent
    ) -> None:
        """Additional checks specific to Python scripts."""
        patterns = [
            # Dynamic code execution with non-literal args
            (
                r"eval\s*\([^)\"']+\)",
                "eval() with non-literal argument",
                "critical",
                "eval-dynamic-arg",
            ),
            # __import__ usage (obfuscated imports)
            (
                r"__import__\s*\(",
                "Dynamic __import__() call",
                "high",
                "dynamic-import",
            ),
            # getattr with __import__ (obfuscated exec)
            (
                r"getattr\s*\(\s*__import__",
                "getattr(__import__(...)) — obfuscated execution",
                "critical",
                "obfuscated-exec",
            ),
            # pickle.loads (deserialization attack)
            (
                r"pickle\.(loads?|Unpickler)",
                "Pickle deserialization (arbitrary code execution risk)",
                "high",
                "pickle-deserialize",
            ),
            # marshal.loads
            (
                r"marshal\.loads?\(",
                "Marshal deserialization (code execution risk)",
                "high",
                "marshal-deserialize",
            ),
            # ctypes usage
            (
                r"ctypes\.\w+",
                "ctypes usage (native code execution)",
                "medium",
                "ctypes-usage",
            ),
            # Infinite loop without break
            (
                r"while\s+True\s*:[^}]*?(?:time\.sleep|pass)\s*$",
                "Potential infinite loop",
                "medium",
                "python-infinite-loop",
            ),
        ]

        for pattern, description, severity, rule_id in patterns:
            for match in re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE):
                line_num = content[: match.start()].count("\n") + 1
                self.findings.append(SecurityFinding(
                    severity=severity,
                    rule_id=f"script-{rule_id}",
                    rule_name=description,
                    message=f"{description} in {component.name}",
                    component_type=component.type,
                    component_name=component.name,
                    component_path=component.path,
                    line=line_num,
                    snippet=self._get_snippet(lines, line_num),
                    recommendation="Review and ensure this pattern is intentional and safe",
                ))

    # ------------------------------------------------------------------
    # Bash-specific checks
    # ------------------------------------------------------------------
    def _check_bash_specific(
        self, content: str, lines: List[str], component: PluginComponent
    ) -> None:
        """Additional checks specific to Bash scripts."""
        patterns = [
            # eval with positional args
            (
                r'eval\s+.*\$[@*1-9]',
                "eval with positional arguments (injection risk)",
                "critical",
                "bash-eval-args",
            ),
            # Unquoted variable expansion in commands
            (
                r'(?:rm|mv|cp|cat|chmod|chown)\s+[^"\']*\$\{?\w',
                "Unquoted variable in dangerous command",
                "high",
                "bash-unquoted-var",
            ),
            # Fork bomb patterns
            (
                r':\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;?\s*:',
                "Fork bomb detected",
                "critical",
                "bash-fork-bomb",
            ),
            # System modification commands
            (
                r'(?:sudo\s+)?(?:apt-get|yum|dnf|apk|pacman|brew)\s+install',
                "System package installation",
                "medium",
                "bash-pkg-install",
            ),
            (
                r'(?:sudo\s+)?(?:chmod|chown)\s+.*(?:/etc/|/usr/|/var/)',
                "System file permission/ownership change",
                "high",
                "bash-sys-modify",
            ),
        ]

        for pattern, description, severity, rule_id in patterns:
            for match in re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE):
                line_num = content[: match.start()].count("\n") + 1
                self.findings.append(SecurityFinding(
                    severity=severity,
                    rule_id=f"script-{rule_id}",
                    rule_name=description,
                    message=f"{description} in {component.name}",
                    component_type=component.type,
                    component_name=component.name,
                    component_path=component.path,
                    line=line_num,
                    snippet=self._get_snippet(lines, line_num),
                    recommendation="Review and ensure this pattern is intentional and safe",
                ))

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    def _get_snippet(self, lines: List[str], line_num: int, context: int = 2) -> str:
        start = max(0, line_num - context - 1)
        end = min(len(lines), line_num + context)
        return "\n".join(
            f"{i + start + 1}: {line}" for i, line in enumerate(lines[start:end])
        )
