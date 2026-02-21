"""
Secret redaction utilities for scan reports.

Prevents accidental leakage of secrets (API keys, tokens, passwords) that
are detected as findings and would otherwise appear verbatim in report
snippets and messages.
"""

import re
from typing import Optional

_SECRET_PATTERNS: list[tuple[re.Pattern, str]] = [
    # AWS access key IDs
    (re.compile(r"(?<=['\"\s=:])AKIA[0-9A-Z]{16}(?=['\"\s,;\n])"), "***AWS_KEY_REDACTED***"),
    # GitHub personal access tokens
    (re.compile(r"ghp_[A-Za-z0-9]{36,}"), "***GITHUB_TOKEN_REDACTED***"),
    (re.compile(r"gho_[A-Za-z0-9]{36,}"), "***GITHUB_TOKEN_REDACTED***"),
    (re.compile(r"ghs_[A-Za-z0-9]{36,}"), "***GITHUB_TOKEN_REDACTED***"),
    (re.compile(r"github_pat_[A-Za-z0-9_]{22,}"), "***GITHUB_TOKEN_REDACTED***"),
    # OpenAI / Anthropic API keys
    (re.compile(r"sk-[A-Za-z0-9]{20,}"), "***API_KEY_REDACTED***"),
    (re.compile(r"sk-ant-[A-Za-z0-9\-]{20,}"), "***API_KEY_REDACTED***"),
    # Slack tokens
    (re.compile(r"xox[bpas]-[A-Za-z0-9\-]{10,}"), "***SLACK_TOKEN_REDACTED***"),
    # Generic bearer / auth tokens (long hex or base64 after "Bearer")
    (re.compile(r"(?i)(Bearer\s+)[A-Za-z0-9\-_\.]{20,}"), r"\1***TOKEN_REDACTED***"),
    # password / secret / token / api_key assignments in code
    (
        re.compile(
            r'(?i)((?:password|passwd|secret|token|api_key|apikey|auth_token|access_token)'
            r'\s*[=:]\s*["\'])([^"\']{8,})(["\'])'
        ),
        r"\1***REDACTED***\3",
    ),
    # Generic long high-entropy strings that look like secrets (40+ hex chars)
    (re.compile(r"(?<=['\"\s=:])[0-9a-fA-F]{40,}(?=['\"\s,;\n])"), "***HEX_REDACTED***"),
]


def redact_secrets(text: Optional[str]) -> str:
    """
    Redact common secret patterns from text.

    Designed to be applied to ``snippet`` and ``message`` fields in scan
    reports before serialization.
    """
    if not text:
        return text or ""

    result = text
    for pattern, replacement in _SECRET_PATTERNS:
        result = pattern.sub(replacement, result)
    return result
