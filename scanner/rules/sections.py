"""
Section classification for security findings.

Maps each security category to one of two top-level sections:

- **malicious**: Intentional attack patterns (prompt injection, data exfiltration,
  obfuscation, tool poisoning, etc.). Aligned with the Snyk research paper's
  CRITICAL-level threat categories.
- **code_security**: Bugs, misconfigurations, and poor practices (injection vulns,
  credential exposure, supply chain risks, etc.). Aligned with the paper's
  HIGH/MEDIUM-level categories.

Reference: "Exploring the Emerging Threats of the Agent Skill Ecosystem" (Snyk, Feb 2026)
"""

# ---------------------------------------------------------------------------
# Category → Section mapping
# ---------------------------------------------------------------------------

MALICIOUS_CATEGORIES: set[str] = {
    "prompt_injection",
    "social_engineering",
    "unicode_steganography",
    "tool_poisoning",
    "data_exfiltration",
    "obfuscation",
    "autonomy_abuse",
    "malicious_code",
    "suspicious_downloads",
    "system_modification",
}

CODE_SECURITY_CATEGORIES: set[str] = {
    "command_injection",
    "path_traversal",
    "credential_exposure",
    "privilege_escalation",
    "supply_chain",
    "third_party_exposure",
    "financial_access",
}

# ---------------------------------------------------------------------------
# Display names for terminal / report output
# ---------------------------------------------------------------------------

SECTION_DISPLAY_NAMES: dict[str, str] = {
    "malicious": "Malicious Check",
    "code_security": "Code Security Issues",
}

# Ordered list for consistent display (malicious first — higher priority)
SECTION_ORDER: list[str] = ["malicious", "code_security"]


def get_section(category: str) -> str:
    """Return the section for a given security category.

    Categories in ``MALICIOUS_CATEGORIES`` map to ``"malicious"``.
    Everything else (including unknown categories) defaults to ``"code_security"``.
    """
    if category in MALICIOUS_CATEGORIES:
        return "malicious"
    return "code_security"
