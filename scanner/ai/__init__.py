"""
AI-powered security analysis modules.

Supports multiple LLM providers via LangChain:
- Google Gemini
- Azure OpenAI
- AWS Bedrock (Claude)
- OpenAI

Includes prompt injection protection via random delimiter sandboxing.
"""

from scanner.ai.triage import AITriager
from scanner.ai.reviewer import AISecurityReviewer
from scanner.ai.component_scanner import AIComponentScanner
from scanner.ai.review_triage import AIReviewTriager, TriagedIssue
from scanner.ai.providers import (
    get_llm_provider,
    SUPPORTED_PROVIDERS,
    RateLimiter,
    invoke_with_retry,
)
from scanner.ai.prompt_guard import PromptGuard

__all__ = [
    "AITriager",
    "AISecurityReviewer",
    "AIComponentScanner",
    "AIReviewTriager",
    "TriagedIssue",
    "get_llm_provider",
    "SUPPORTED_PROVIDERS",
    "RateLimiter",
    "invoke_with_retry",
    "PromptGuard",
]

