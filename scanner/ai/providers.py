"""
LLM Provider configuration for AI-powered analysis.

Supports multiple providers via LangChain.
Includes thread-safe rate limiting and retry with exponential backoff.
"""

import os
import re
import time
import random
import threading
from collections import deque
from typing import Optional
from dataclasses import dataclass


@dataclass
class ProviderConfig:
    """Configuration for an LLM provider."""
    name: str
    default_model: str
    env_var: str
    description: str


SUPPORTED_PROVIDERS = {
    "openai": ProviderConfig(
        name="openai",
        default_model="gpt-4o",
        env_var="OPENAI_API_KEY",
        description="OpenAI GPT models"
    ),
    "azure": ProviderConfig(
        name="azure",
        default_model="gpt-4o",
        env_var="AZURE_OPENAI_API_KEY",
        description="Azure OpenAI Service"
    ),
    "gemini": ProviderConfig(
        name="gemini",
        default_model="gemini-2.0-flash",
        env_var="GOOGLE_API_KEY",
        description="Google Gemini models"
    ),
    "bedrock": ProviderConfig(
        name="bedrock",
        default_model="us.anthropic.claude-sonnet-4-20250514-v1:0",
        env_var="AWS_ACCESS_KEY_ID",
        description="AWS Bedrock (Claude, etc.)"
    ),
    "anthropic": ProviderConfig(
        name="anthropic",
        default_model="claude-3-5-sonnet-20241022",
        env_var="ANTHROPIC_API_KEY",
        description="Anthropic Claude models"
    ),
}


def get_llm_provider(
    provider: str = "openai",
    model: Optional[str] = None,
    temperature: float = 0.1,
    max_tokens: int = 8192,
):
    """
    Get a LangChain LLM instance for the specified provider.
    
    Args:
        provider: Provider name (openai, azure, gemini, bedrock, anthropic)
        model: Model name (uses provider default if not specified)
        temperature: Temperature for generation (default 0.1 for deterministic output)
        max_tokens: Maximum tokens in response (default 8192 to avoid truncation)
    
    Returns:
        LangChain LLM instance
    
    Raises:
        ValueError: If provider is not supported
        ImportError: If required dependencies are not installed
    """
    if provider not in SUPPORTED_PROVIDERS:
        raise ValueError(
            f"Unsupported provider: {provider}. "
            f"Supported: {', '.join(SUPPORTED_PROVIDERS.keys())}"
        )
    
    config = SUPPORTED_PROVIDERS[provider]
    model_name = model or config.default_model
    
    # Check for API key
    if not os.environ.get(config.env_var):
        raise ValueError(
            f"Missing API key for {provider}. "
            f"Set the {config.env_var} environment variable."
        )
    
    if provider == "openai":
        try:
            from langchain_openai import ChatOpenAI
            return ChatOpenAI(
                model=model_name,
                temperature=temperature,
                max_tokens=max_tokens,
            )
        except ImportError:
            raise ImportError(
                "OpenAI support requires: pip install langchain-openai"
            )
    
    elif provider == "azure":
        try:
            from langchain_openai import AzureChatOpenAI
            return AzureChatOpenAI(
                azure_deployment=model_name,
                temperature=temperature,
                max_tokens=max_tokens,
                api_version=os.environ.get("AZURE_OPENAI_API_VERSION", "2024-02-01"),
            )
        except ImportError:
            raise ImportError(
                "Azure OpenAI support requires: pip install langchain-openai"
            )
    
    elif provider == "gemini":
        try:
            from langchain_google_genai import ChatGoogleGenerativeAI
            return ChatGoogleGenerativeAI(
                model=model_name,
                temperature=temperature,
                max_output_tokens=max_tokens,
            )
        except ImportError:
            raise ImportError(
                "Gemini support requires: pip install langchain-google-genai"
            )
    
    elif provider == "bedrock":
        try:
            from langchain_aws import ChatBedrock
            
            # Strip common prefixes that users might accidentally include
            bedrock_model_id = model_name
            for prefix in ["bedrock/", "aws/", "amazon/"]:
                if bedrock_model_id.startswith(prefix):
                    bedrock_model_id = bedrock_model_id[len(prefix):]
                    break
            
            return ChatBedrock(
                model_id=bedrock_model_id,
                model_kwargs={
                    "temperature": temperature,
                    "max_tokens": max_tokens,
                },
                region_name=os.environ.get("AWS_REGION", "us-east-1"),
            )
        except ImportError:
            raise ImportError(
                "Bedrock support requires: pip install langchain-aws"
            )
    
    elif provider == "anthropic":
        try:
            from langchain_anthropic import ChatAnthropic
            return ChatAnthropic(
                model=model_name,
                temperature=temperature,
                max_tokens=max_tokens,
            )
        except ImportError:
            raise ImportError(
                "Anthropic support requires: pip install langchain-anthropic"
            )
    
    raise ValueError(f"Provider {provider} not implemented")


def extract_text_content(content) -> str:
    """
    Normalize LLM response content to a plain text string.
    
    Some providers (notably newer Gemini models) return ``response.content``
    as a list of content parts like::
    
        [{"type": "text", "text": "...", "extras": {...}}]
    
    instead of a plain string.  This helper handles both formats so callers
    can always work with ``str``.
    """
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        # Concatenate all text parts
        parts: list[str] = []
        for item in content:
            if isinstance(item, str):
                parts.append(item)
            elif isinstance(item, dict):
                # {"type": "text", "text": "..."} format
                text = item.get("text", "")
                if text:
                    parts.append(str(text))
        return "\n".join(parts) if parts else ""
    # Fallback: coerce to string
    return str(content)


class RateLimiter:
    """
    Thread-safe sliding-window rate limiter.

    Tracks request timestamps in a deque and blocks callers via
    ``threading.Condition`` when the window is full.  ``rpm=0``
    disables throttling entirely.
    """

    def __init__(self, rpm: int = 0):
        self.rpm = rpm
        self._window = 60.0  # seconds
        self._timestamps: deque[float] = deque()
        self._cond = threading.Condition(threading.Lock())

    def acquire(self) -> None:
        """Block until a request slot is available."""
        if self.rpm <= 0:
            return

        with self._cond:
            while True:
                now = time.monotonic()
                # Evict timestamps older than the window
                while self._timestamps and self._timestamps[0] <= now - self._window:
                    self._timestamps.popleft()

                if len(self._timestamps) < self.rpm:
                    self._timestamps.append(now)
                    return

                # Wait until the oldest request expires
                wait = self._timestamps[0] - (now - self._window) + 0.05
                self._cond.wait(timeout=max(wait, 0.1))


# ------------------------------------------------------------------ #
# Retryable error detection
# ------------------------------------------------------------------ #

_RETRYABLE_PATTERNS = re.compile(
    r"429|RESOURCE_EXHAUSTED|rate.limit|quota.exceeded|"
    r"too.many.requests|"
    r"\b50[023]\b|529|internal.server.error|service.unavailable|"
    r"timeout|timed?.out|connection.error|connection.reset|"
    r"RemoteDisconnected|ConnectionRefused",
    re.IGNORECASE,
)

_NON_RETRYABLE_PATTERNS = re.compile(
    r"\b40[0134]\b|InvalidArgument|PermissionDenied|"
    r"AuthenticationError|Forbidden|NotFound",
    re.IGNORECASE,
)

_RETRY_DELAY_RE = re.compile(r"retryDelay[\"']?\s*[:=]\s*[\"']?(\d+)", re.IGNORECASE)


def _is_retryable(exc: Exception) -> bool:
    """Return True if the exception looks like a transient/rate-limit error."""
    msg = str(exc)
    if _NON_RETRYABLE_PATTERNS.search(msg):
        return False
    return bool(_RETRYABLE_PATTERNS.search(msg))


def _parse_retry_delay(exc: Exception) -> Optional[float]:
    """Extract a server-suggested retry delay (seconds) from the error message."""
    m = _RETRY_DELAY_RE.search(str(exc))
    if m:
        return float(m.group(1))
    return None


def invoke_with_retry(
    llm,
    messages: list[dict],
    *,
    max_retries: int = 3,
    base_delay: float = 2.0,
    rate_limiter: Optional[RateLimiter] = None,
    verbose: bool = False,
):
    """
    Call ``llm.invoke(messages)`` with retry + exponential backoff.

    Respects an optional :class:`RateLimiter` (called before every attempt)
    and honours ``retryDelay`` hints from the API error body.

    Returns the LLM response object on success; re-raises on final failure.
    """
    last_exc: Optional[Exception] = None

    for attempt in range(max_retries + 1):
        if rate_limiter is not None:
            rate_limiter.acquire()

        try:
            return llm.invoke(messages)
        except Exception as exc:
            last_exc = exc

            if attempt >= max_retries or not _is_retryable(exc):
                raise

            # Compute delay: exponential backoff with jitter
            delay = base_delay * (2 ** attempt)
            jitter = random.uniform(0.5, 1.5)
            delay *= jitter

            # Respect server-suggested delay if larger
            server_delay = _parse_retry_delay(exc)
            if server_delay is not None and server_delay > delay:
                delay = server_delay + random.uniform(0.5, 2.0)

            if verbose:
                print(
                    f"        [RETRY {attempt + 1}/{max_retries}] "
                    f"{type(exc).__name__}: retrying in {delay:.1f}s..."
                )

            time.sleep(delay)

    raise last_exc  # type: ignore[misc]


def list_providers() -> str:
    """Get a formatted list of supported providers."""
    lines = ["Supported AI Providers:"]
    for name, config in SUPPORTED_PROVIDERS.items():
        lines.append(f"  {name}: {config.description}")
        lines.append(f"    Default model: {config.default_model}")
        lines.append(f"    Requires: {config.env_var}")
    return "\n".join(lines)

