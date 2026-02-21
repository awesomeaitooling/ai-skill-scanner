"""
Agent & Command Analyzer — Security checks specific to AGENT.md and COMMAND.md.

Agent-specific:
- Unrestricted tool access
- Autonomous behavior detection
- Excessive scope claims
- Cross-context bridging

Command-specific:
- Argument injection ($ARGUMENTS into shell/eval/paths)
- Privilege escalation via commands
- Unsafe argument parsing
- Hidden sub-commands
"""

import re
from typing import Optional, List

from .plugin_parser import PluginComponent
from .skill_analyzer import SecurityFinding
from ..rules.rule_loader import get_rule_loader, RuleLoader


class AgentCommandAnalyzer:
    """Specialized security analysis for agents and commands beyond generic skill scanning."""

    # Patterns indicating autonomous behavior
    AUTONOMY_PATTERNS = [
        (r"act\s+autonomously", "Autonomous action instruction"),
        (r"do\s+not\s+ask\b.*\bconfirm", "Suppresses user confirmation"),
        (r"proceed\s+without\s+(asking|approval|confirmation|permission)", "Bypasses approval"),
        (r"without\s+(user\s+)?confirmation", "No confirmation required"),
        (r"do\s+not\s+wait\s+for\s+(user|approval|input)", "Does not wait for user"),
        (r"automatically\s+(execute|run|perform|apply)", "Automatic execution"),
        (r"keep\s+(trying|retrying|going)\s+(until|indefinitely)", "Unbounded retry loop"),
        (r"retry\s+indefinitely", "Infinite retry"),
        (r"loop\s+until\s+success", "Unbounded loop until success"),
        (r"no\s+iteration\s+limit", "No iteration limit"),
    ]

    # Patterns indicating excessive scope
    EXCESSIVE_SCOPE_PATTERNS = [
        (r"handle\s+any\s+task", "Claims to handle any task"),
        (r"general\s+purpose", "General purpose claim"),
        (r"do\s+anything", "Claims to do anything"),
        (r"all\s+tools?\s+(available|enabled|allowed)", "All tools available"),
        (r"unlimited\s+(access|capabilities|scope)", "Unlimited access"),
        (r"full\s+access\s+to\s+(everything|all|system)", "Full system access"),
    ]

    # Patterns indicating cross-context bridging
    CROSS_CONTEXT_PATTERNS = [
        (r"access\s+(data|files?|info)\s+from\s+(other|another|different)\s+(?:skill|session|context|plugin)",
         "Accesses data from other contexts"),
        (r"share\s+(data|state|context)\s+(?:between|across|with)\s+(?:skill|session|plugin)",
         "Shares data across contexts"),
        (r"persist\s+(across|between)\s+sessions?", "Persists data across sessions"),
        (r"global\s+(state|memory|storage)", "Uses global state"),
    ]

    # Patterns indicating argument injection risk in commands
    ARGUMENT_INJECTION_PATTERNS = [
        (r"\$ARGUMENTS?\s*(?:.*\n)*?.*(?:eval|exec|system|subprocess|os\.system)",
         "Arguments passed to eval/exec/system"),
        (r"\$ARGUMENTS?\s*(?:.*\n)*?.*(?:bash|sh|zsh)\s",
         "Arguments passed to shell"),
        (r"\$\{?ARGUMENTS?\}?\s*(?:.*\n)*?.*open\(",
         "Arguments used in file paths"),
        (r"pass\s+.*argument.*directly\s+to\s+(?:shell|command|bash|terminal)",
         "Instruction to pass args directly to shell"),
        (r"run\s+.*\$ARGUMENTS",
         "Running commands with $ARGUMENTS"),
    ]

    def __init__(self, rule_loader: Optional[RuleLoader] = None):
        self.rule_loader = rule_loader or get_rule_loader()
        self.findings: List[SecurityFinding] = []

    def analyze(self, component: PluginComponent) -> List[SecurityFinding]:
        """Analyze an agent or command component for type-specific security issues."""
        self.findings = []

        if component.type == "agent":
            self._analyze_agent(component)
        elif component.type == "command":
            self._analyze_command(component)

        return self.findings

    # ------------------------------------------------------------------
    # Agent analysis
    # ------------------------------------------------------------------
    def _analyze_agent(self, component: PluginComponent) -> None:
        """Run agent-specific security checks."""
        content = component.content or ""
        lines = content.split("\n")

        # Check capabilities metadata
        self._check_agent_capabilities(component)

        # Check for autonomous behavior patterns
        self._check_patterns(
            content, lines, component,
            self.AUTONOMY_PATTERNS,
            severity="high",
            rule_id="agent-autonomy",
            rule_name="Agent Autonomous Behavior",
            recommendation="Agents should always confirm destructive actions with the user",
        )

        # Check for excessive scope
        self._check_patterns(
            content, lines, component,
            self.EXCESSIVE_SCOPE_PATTERNS,
            severity="medium",
            rule_id="agent-excessive-scope",
            rule_name="Agent Excessive Scope",
            recommendation="Limit agent scope to specific, well-defined tasks",
        )

        # Check for cross-context bridging
        self._check_patterns(
            content, lines, component,
            self.CROSS_CONTEXT_PATTERNS,
            severity="high",
            rule_id="agent-cross-context",
            rule_name="Agent Cross-Context Bridging",
            recommendation="Agents should not access data from other sessions or contexts",
        )

        # Check allowed-tools validation
        self._check_tool_allowlist(component)

    def _check_agent_capabilities(self, component: PluginComponent) -> None:
        """Check agent capabilities metadata for security issues."""
        capabilities = component.metadata.get("capabilities", [])

        if not capabilities:
            # No capabilities declared — check content for broad access
            content = (component.content or "").lower()
            if any(phrase in content for phrase in [
                "all tools", "any tool", "unrestricted", "full access"
            ]):
                self.findings.append(SecurityFinding(
                    severity="high",
                    rule_id="agent-unrestricted-tools",
                    rule_name="Unrestricted Tool Access",
                    message="Agent implies unrestricted tool access but declares no capabilities",
                    component_type=component.type,
                    component_name=component.name,
                    component_path=component.path,
                    recommendation="Explicitly declare required capabilities and limit tool access",
                ))
            return

        # Check for overly broad capabilities
        broad_terms = {"all", "any", "everything", "unrestricted", "full", "admin"}
        for cap in capabilities:
            cap_lower = cap.lower()
            if any(term in cap_lower for term in broad_terms):
                self.findings.append(SecurityFinding(
                    severity="medium",
                    rule_id="agent-broad-capability",
                    rule_name="Overly Broad Agent Capability",
                    message=f"Agent capability is too broad: '{cap}'",
                    component_type=component.type,
                    component_name=component.name,
                    component_path=component.path,
                    recommendation="Define specific, narrow capabilities",
                ))

    def _check_tool_allowlist(self, component: PluginComponent) -> None:
        """Validate agent instructions against declared allowed-tools."""
        frontmatter = component.metadata.get("frontmatter")
        if not frontmatter or not isinstance(frontmatter, dict):
            return

        allowed_tools = frontmatter.get("allowed-tools", [])
        if not allowed_tools or not isinstance(allowed_tools, list):
            return

        content = component.content or ""
        allowed_set = {t.lower() for t in allowed_tools}

        # Check if content references tools not in the allowlist
        tool_mentions = {
            "bash": [r"\bbash\b", r"\bshell\b", r"\bterminal\b"],
            "python": [r"\bpython\b", r"\bpython3\b"],
            "write": [r"\bwrite\s+(?:file|to)\b", r"\bcreate\s+file\b"],
            "read": [r"\bread\s+file\b"],
            "network": [r"\bfetch\b", r"\bcurl\b", r"\bhttp\b", r"\bapi\s+call\b"],
        }

        for tool_name, patterns in tool_mentions.items():
            if tool_name not in allowed_set:
                for pat in patterns:
                    if re.search(pat, content, re.IGNORECASE):
                        self.findings.append(SecurityFinding(
                            severity="medium",
                            rule_id="agent-tool-violation",
                            rule_name="Tool Usage Beyond Allowlist",
                            message=f"Agent references '{tool_name}' which is not in allowed-tools: {allowed_tools}",
                            component_type=component.type,
                            component_name=component.name,
                            component_path=component.path,
                            recommendation=f"Either add '{tool_name}' to allowed-tools or remove references from instructions",
                        ))
                        break

    # ------------------------------------------------------------------
    # Command analysis
    # ------------------------------------------------------------------
    def _analyze_command(self, component: PluginComponent) -> None:
        """Run command-specific security checks."""
        content = component.content or ""
        lines = content.split("\n")

        # Check for argument injection
        self._check_patterns(
            content, lines, component,
            self.ARGUMENT_INJECTION_PATTERNS,
            severity="high",
            rule_id="command-arg-injection",
            rule_name="Command Argument Injection",
            recommendation="Sanitize and validate all arguments before use in shell commands or file paths",
        )

        # Check for privilege escalation via command instructions
        priv_patterns = [
            (r"run\s+(this\s+)?(?:as|with)\s+(?:sudo|root|admin)", "Runs with elevated privileges"),
            (r"requires?\s+(?:sudo|root|admin)\s+(?:access|privileges?)", "Requires elevated privileges"),
            (r"sudo\s+", "Uses sudo"),
        ]
        self._check_patterns(
            content, lines, component,
            priv_patterns,
            severity="high",
            rule_id="command-privilege-escalation",
            rule_name="Command Privilege Escalation",
            recommendation="Commands should not require elevated privileges; follow least-privilege principle",
        )

        # Check for hidden sub-commands
        self._check_hidden_subcommands(component)

    def _check_hidden_subcommands(self, component: PluginComponent) -> None:
        """Check if command has sub-behaviors not described in its name."""
        content = component.content or ""
        name = component.name.lower()
        frontmatter = component.metadata.get("frontmatter", {})
        description = ""
        if isinstance(frontmatter, dict):
            description = (frontmatter.get("description", "") or "").lower()

        # Dangerous actions that should be declared in the name/description
        hidden_action_patterns = [
            (r"delete\s+(?:file|dir|folder|data)", "delete", "Deletes files/data"),
            (r"send\s+(?:to|data|file)\s+(?:external|remote|server)", "send", "Sends data externally"),
            (r"install\s+(?:package|dependency|module)", "install", "Installs packages"),
            (r"modify\s+(?:system|config|permission)", "modify", "Modifies system config"),
        ]

        for pattern, keyword, description_text in hidden_action_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                if keyword not in name and keyword not in description:
                    self.findings.append(SecurityFinding(
                        severity="medium",
                        rule_id="command-hidden-behavior",
                        rule_name="Hidden Command Behavior",
                        message=f"Command '{component.name}' performs '{description_text}' but this is not reflected in its name/description",
                        component_type=component.type,
                        component_name=component.name,
                        component_path=component.path,
                        recommendation="Command name and description should accurately reflect all behaviors",
                    ))

    # ------------------------------------------------------------------
    # Shared helpers
    # ------------------------------------------------------------------
    def _check_patterns(
        self,
        content: str,
        lines: List[str],
        component: PluginComponent,
        patterns: list,
        severity: str,
        rule_id: str,
        rule_name: str,
        recommendation: str,
    ) -> None:
        """Check content against a list of (pattern, description) tuples."""
        for pattern, description in patterns:
            for match in re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE):
                line_num = content[: match.start()].count("\n") + 1
                self.findings.append(SecurityFinding(
                    severity=severity,
                    rule_id=rule_id,
                    rule_name=rule_name,
                    message=f"{description}: '{match.group()[:60]}'",
                    component_type=component.type,
                    component_name=component.name,
                    component_path=component.path,
                    line=line_num,
                    snippet=self._get_snippet(lines, line_num),
                    recommendation=recommendation,
                ))

    def _get_snippet(self, lines: List[str], line_num: int, context: int = 2) -> str:
        start = max(0, line_num - context - 1)
        end = min(len(lines), line_num + context)
        return "\n".join(
            f"{i + start + 1}: {line}" for i, line in enumerate(lines[start:end])
        )
