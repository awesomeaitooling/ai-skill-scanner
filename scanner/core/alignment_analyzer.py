"""
Alignment Analyzer — Checks for mismatches between component descriptions
and actual code behavior.

Detects:
- Skills that claim to be "read-only" but execute write/delete operations
- Skills that say "local only" but make network requests
- Descriptions that omit dangerous capabilities
- Commands whose names don't match their actual behavior
"""

import re
from typing import List, Optional, Set, Tuple

from .plugin_parser import PluginComponent
from .skill_analyzer import SecurityFinding


# Keywords in descriptions that imply safety/restrictions
SAFE_CLAIMS = {
    "read-only": {"write", "delete", "remove", "modify", "create", "mkdir", "rmdir", "truncate"},
    "read only": {"write", "delete", "remove", "modify", "create", "mkdir", "rmdir", "truncate"},
    "local only": {"http", "https", "fetch", "curl", "wget", "requests", "socket", "network", "api"},
    "local-only": {"http", "https", "fetch", "curl", "wget", "requests", "socket", "network", "api"},
    "no network": {"http", "https", "fetch", "curl", "wget", "requests", "socket", "api"},
    "offline": {"http", "https", "fetch", "curl", "wget", "requests", "socket", "network"},
    "safe": {"eval", "exec", "system", "subprocess", "popen", "shell", "rm -rf", "sudo"},
    "harmless": {"eval", "exec", "system", "subprocess", "popen", "shell", "rm -rf", "sudo"},
    "non-destructive": {"delete", "remove", "rm", "rmdir", "drop", "truncate", "destroy"},
    "no file access": {"open(", "read(", "write(", "pathlib", "os.path", "file"},
}

# Capabilities that should be disclosed in descriptions
UNDISCLOSED_CAPABILITIES = [
    (r"(?:subprocess|os\.system|os\.popen|shutil\.rmtree)", "command_execution", "executes system commands"),
    (r"(?:requests\.\w+|urllib|httpx|fetch|curl|wget)", "network_access", "makes network requests"),
    (r"(?:open\s*\([^)]*[\"']w|write\s*\(|\.write\()", "file_write", "writes to files"),
    (r"(?:os\.remove|os\.unlink|shutil\.rmtree|rmdir)", "file_delete", "deletes files"),
    (r"(?:eval|exec|compile)\s*\(", "code_execution", "executes dynamic code"),
    (r"(?:os\.environ|os\.getenv|dotenv)", "env_access", "accesses environment variables"),
    (r"(?:sqlite3|psycopg|pymysql|sqlalchemy)", "database_access", "accesses databases"),
    (r"(?:smtplib|email\.mime)", "email_send", "sends emails"),
    (r"(?:sudo|as\s+root|chmod\s+777)", "privilege_escalation", "uses elevated privileges"),
    (r"(?:pickle\.load|marshal\.load|yaml\.(?:unsafe_)?load)", "deserialization", "deserializes untrusted data"),
]


class AlignmentAnalyzer:
    """Checks alignment between component descriptions and actual behavior."""

    def __init__(self):
        self.findings: List[SecurityFinding] = []

    def analyze(self, component: PluginComponent) -> List[SecurityFinding]:
        """Analyze a component for description-vs-behavior mismatches."""
        self.findings = []

        content = component.content or ""
        if not content:
            return self.findings

        description = self._get_description(component)
        content_lower = content.lower()

        # Check safe claims vs actual behavior
        if description:
            self._check_safe_claims(description, content_lower, component)
            self._check_undisclosed_capabilities(description, content, component)

        # Check name vs behavior for commands
        if component.type == "command":
            self._check_command_name_alignment(component, content_lower)

        return self.findings

    def _get_description(self, component: PluginComponent) -> str:
        """Extract description from component metadata or frontmatter."""
        # From frontmatter
        frontmatter = component.metadata.get("frontmatter")
        if isinstance(frontmatter, dict):
            desc = frontmatter.get("description", "")
            if desc:
                return desc.lower()

        # From metadata
        desc = component.metadata.get("description", "")
        if desc:
            return desc.lower()

        # Try extracting first paragraph from markdown content
        content = component.content or ""
        lines = content.split("\n")
        for line in lines:
            stripped = line.strip()
            if stripped and not stripped.startswith("#") and not stripped.startswith("---"):
                return stripped[:200].lower()

        return ""

    def _check_safe_claims(
        self, description: str, content_lower: str, component: PluginComponent
    ) -> None:
        """Check if claims of safety in description are contradicted by code."""
        for claim, contradicting_keywords in SAFE_CLAIMS.items():
            if claim in description:
                for keyword in contradicting_keywords:
                    if keyword in content_lower:
                        self.findings.append(SecurityFinding(
                            severity="high",
                            rule_id="alignment-safe-claim-violation",
                            rule_name="Safety Claim Contradicted by Code",
                            message=(
                                f"Description claims '{claim}' but code contains '{keyword}'. "
                                f"This mismatch may indicate deception or an oversight."
                            ),
                            component_type=component.type,
                            component_name=component.name,
                            component_path=component.path,
                            recommendation=(
                                f"Either update the description to disclose the '{keyword}' "
                                f"capability, or remove the capability to match the claim."
                            ),
                        ))
                        break  # One contradiction per claim is enough

    def _check_undisclosed_capabilities(
        self, description: str, content: str, component: PluginComponent
    ) -> None:
        """Check for capabilities in code not mentioned in description."""
        found_capabilities: List[Tuple[str, str]] = []

        for pattern, capability_id, capability_desc in UNDISCLOSED_CAPABILITIES:
            if re.search(pattern, content, re.IGNORECASE):
                # Check if the capability is mentioned in description
                mention_patterns = {
                    "command_execution": ["command", "exec", "run", "shell", "terminal"],
                    "network_access": ["network", "http", "api", "request", "fetch", "remote"],
                    "file_write": ["write", "create", "save", "output"],
                    "file_delete": ["delete", "remove", "clean"],
                    "code_execution": ["eval", "exec", "dynamic", "interpret"],
                    "env_access": ["environment", "env", "config", "variable"],
                    "database_access": ["database", "db", "sql", "query"],
                    "email_send": ["email", "mail", "smtp", "notify"],
                    "privilege_escalation": ["sudo", "root", "admin", "privilege"],
                    "deserialization": ["deserializ", "pickle", "marshal", "load"],
                }

                mentions = mention_patterns.get(capability_id, [])
                if not any(m in description for m in mentions):
                    found_capabilities.append((capability_id, capability_desc))

        # Only report if there are undisclosed capabilities
        if found_capabilities:
            cap_list = ", ".join(desc for _, desc in found_capabilities[:5])
            self.findings.append(SecurityFinding(
                severity="medium",
                rule_id="alignment-undisclosed-capability",
                rule_name="Undisclosed Capabilities",
                message=f"Component {component.name} has capabilities not mentioned in its description: {cap_list}",
                component_type=component.type,
                component_name=component.name,
                component_path=component.path,
                recommendation="Update the description to disclose all capabilities for transparency",
            ))

    def _check_command_name_alignment(
        self, component: PluginComponent, content_lower: str
    ) -> None:
        """Check if a command's name aligns with what it actually does."""
        name_lower = component.name.lower().replace(".md", "").replace("-", " ").replace("_", " ")

        # Dangerous actions that should be reflected in the name
        dangerous_actions = [
            ("delete", ["delete", "remov", "rm ", "unlink", "rmdir", "destroy"]),
            ("install", ["install", "pip install", "npm install", "apt-get"]),
            ("send", ["send", "post", "upload", "transmit", "email"]),
            ("deploy", ["deploy", "publish", "release", "push"]),
            ("modify system", ["chmod", "chown", "/etc/", "/usr/", "systemctl"]),
        ]

        for action_name, indicators in dangerous_actions:
            for indicator in indicators:
                if indicator in content_lower and action_name not in name_lower:
                    frontmatter = component.metadata.get("frontmatter", {})
                    desc = ""
                    if isinstance(frontmatter, dict):
                        desc = (frontmatter.get("description", "") or "").lower()

                    if action_name not in desc:
                        self.findings.append(SecurityFinding(
                            severity="medium",
                            rule_id="alignment-command-name-mismatch",
                            rule_name="Command Name Does Not Reflect Behavior",
                            message=(
                                f"Command '{component.name}' performs '{action_name}' "
                                f"operations but this is not reflected in its name or description"
                            ),
                            component_type=component.type,
                            component_name=component.name,
                            component_path=component.path,
                            recommendation="Update the command name/description to accurately reflect its behavior",
                        ))
                        break
