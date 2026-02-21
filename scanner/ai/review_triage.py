"""
AI-powered triage of AI review findings.

Re-examines each SecurityIssue produced by AISecurityReviewer or
AIComponentScanner against the actual component content to filter
hallucinated or false-positive issues before they enter the final report.

Uses all three PromptGuard layers (pre-scan, wrapping, system guard)
since component content is untrusted.

Supports parallel triage via ThreadPoolExecutor with configurable
workers and rate limiting.
"""

import json
import re
import sys
import time
import threading
from typing import Optional
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor, as_completed

from scanner.core.plugin_parser import ParsedPlugin
from scanner.ai.reviewer import SecurityIssue
from scanner.ai.prompt_guard import PromptGuard, sanitize_for_prompt
from scanner.ai.providers import extract_text_content, invoke_with_retry, RateLimiter


@dataclass
class TriagedIssue:
    """An AI review issue with triage/validation information."""

    original: SecurityIssue
    is_true_positive: bool
    confidence: float  # 0.0–1.0
    adjusted_severity: str  # critical, high, medium, low
    explanation: str
    evidence: Optional[str]  # exact quoted line(s) proving the issue

    def to_dict(self) -> dict:
        return {
            "original": self.original.to_dict(),
            "triage": {
                "is_true_positive": self.is_true_positive,
                "confidence": self.confidence,
                "adjusted_severity": self.adjusted_severity,
                "explanation": self.explanation,
                "evidence": self.evidence,
            },
        }


REVIEW_TRIAGE_SYSTEM_PROMPT = """\
You are a senior security engineer performing a second-opinion review of \
findings produced by an automated AI security scanner.

Your job is to verify whether each flagged issue is a REAL vulnerability or \
a false positive hallucinated by the scanner.

Be SKEPTICAL. AI scanners frequently:
- Flag benign patterns as vulnerabilities (e.g. documentation mentioning "sudo")
- Invent issues that don't actually exist in the source content
- Exaggerate severity of theoretical risks
- Confuse example/test code with production attack surface

You MUST:
1. Find the EXACT line(s) in the component content that demonstrate the \
vulnerability. Quote them verbatim.
2. If you cannot find concrete evidence in the content, mark it as a false \
positive.
3. Consider whether the pattern is actually benign in the context of a Claude \
Code plugin (e.g. a skill file describing how to use a CLI tool is not itself \
a command injection vulnerability).
4. Assess whether the issue is exploitable by an attacker or is simply an \
informational observation.

Context about Claude Code plugins:
- Skills are markdown files with instructions for Claude
- Hooks intercept tool-use events (PreToolUse, PostToolUse, etc.)
- MCP servers are external processes providing tools
- Scripts may be executed by hooks or referenced by skills
- Not all shell commands are dangerous — many are intentional functionality\
"""

REVIEW_TRIAGE_USER_PROMPT = """\
Verify whether this AI-flagged security issue is real or a false positive.

**Flagged Issue:**
- Title: {title}
- Severity: {severity}
- Category: {category}
- Section: {section}
- Component: {component}
- Location: {location}
- Description: {description}
- Exploitation scenario: {exploitation}
- Original confidence: {confidence:.0%}

**Full component content:**
```
{content}
```

Search the content above for concrete evidence of this vulnerability.
If you cannot find the specific code/pattern described in the issue, \
it is a false positive.

Respond with ONLY valid JSON (no markdown, no explanation outside JSON):
{{
  "is_true_positive": true or false,
  "confidence": 0.0 to 1.0,
  "adjusted_severity": "critical" or "high" or "medium" or "low",
  "explanation": "Brief explanation of why this is or is not a real issue",
  "evidence": "Exact quoted line(s) from the content, or null if false positive"
}}"""


class AIReviewTriager:
    """Validates AI review findings against actual component content."""

    MAX_CONTENT_LENGTH = 10000

    def __init__(
        self,
        llm,
        verbose: bool = False,
        max_workers: int = 4,
        rate_limiter: Optional[RateLimiter] = None,
    ):
        self.llm = llm
        self.verbose = verbose
        self.max_workers = max(1, max_workers)
        self.rate_limiter = rate_limiter
        self.guard = PromptGuard()
        self._print_lock = threading.Lock()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def triage_issue(
        self,
        issue: SecurityIssue,
        component_content: Optional[str] = None,
    ) -> TriagedIssue:
        """Validate a single AI review issue against the component content."""

        content = (component_content or "")[:self.MAX_CONTENT_LENGTH]

        # PromptGuard layer 1: pre-scan for injection
        if content:
            detection = self.guard.scan_content(
                content,
                component_name=issue.component or "unknown",
            )
            if detection:
                if self.verbose:
                    with self._print_lock:
                        print(
                            f"  [ALERT] Prompt injection in '{issue.component}': "
                            f"{detection.pattern_matched}"
                        )
                return TriagedIssue(
                    original=issue,
                    is_true_positive=True,
                    confidence=0.95,
                    adjusted_severity="high",
                    explanation=(
                        f"Component content contains a prompt injection attempt: "
                        f"{detection.pattern_matched}. Content was NOT sent to "
                        f"the triage LLM to prevent manipulation."
                    ),
                    evidence=detection.matched_text,
                )

        # PromptGuard layer 2: wrap untrusted content
        wrapped_content = (
            self.guard.wrap_untrusted(content) if content else "Not available"
        )

        # PromptGuard layer 3: system guard addendum
        guarded_system = (
            REVIEW_TRIAGE_SYSTEM_PROMPT + self.guard.get_system_guard_prompt()
        )

        user_prompt = REVIEW_TRIAGE_USER_PROMPT.format(
            title=sanitize_for_prompt(issue.title),
            severity=sanitize_for_prompt(issue.severity),
            category=sanitize_for_prompt(issue.category),
            section=sanitize_for_prompt(issue.section or "unknown"),
            component=sanitize_for_prompt(issue.component or "unknown"),
            location=sanitize_for_prompt(issue.location or "N/A"),
            description=sanitize_for_prompt(issue.description),
            exploitation=sanitize_for_prompt(issue.exploitation),
            confidence=issue.confidence,
            content=wrapped_content,
        )

        messages = [
            {"role": "system", "content": guarded_system},
            {"role": "user", "content": user_prompt},
        ]

        try:
            response = invoke_with_retry(
                self.llm,
                messages,
                rate_limiter=self.rate_limiter,
                verbose=self.verbose,
            )
            raw = extract_text_content(response.content)
            result = self._parse_response(raw)
        except Exception as e:
            if self.verbose:
                with self._print_lock:
                    print(f"  AI review triage error: {e}")
            result = {
                "is_true_positive": True,
                "confidence": 0.5,
                "adjusted_severity": issue.severity,
                "explanation": f"Triage failed: {e}",
                "evidence": None,
            }

        return TriagedIssue(
            original=issue,
            is_true_positive=result.get("is_true_positive", True),
            confidence=result.get("confidence", 0.5),
            adjusted_severity=result.get("adjusted_severity", issue.severity),
            explanation=result.get("explanation", ""),
            evidence=result.get("evidence"),
        )

    def triage_issues(
        self,
        issues: list[SecurityIssue],
        plugin: ParsedPlugin,
    ) -> list[TriagedIssue]:
        """
        Triage all AI review issues in parallel.

        Returns a list of TriagedIssue objects in the original order.
        """
        total = len(issues)
        if total == 0:
            return []

        # Build component-name → content lookup
        component_contents: dict[str, str] = {}
        for comp in plugin.components:
            if comp.content:
                component_contents[comp.name] = comp.content

        completed = 0
        timings: list[float] = []
        ordered: dict[int, TriagedIssue] = {}
        effective_workers = min(self.max_workers, total)
        phase_start = time.monotonic()

        with ThreadPoolExecutor(max_workers=effective_workers) as pool:
            future_map = {}
            for idx, issue in enumerate(issues):
                content = component_contents.get(issue.component or "")
                future = pool.submit(self._triage_timed, issue, content)
                future_map[future] = (idx, issue)

            for future in as_completed(future_map):
                idx, issue = future_map[future]
                triaged, elapsed = future.result()
                ordered[idx] = triaged
                timings.append(elapsed)
                completed += 1

                if self.verbose:
                    with self._print_lock:
                        verdict = "TP" if triaged.is_true_positive else "FP"
                        print(
                            f"  [{completed}/{total}] {verdict} "
                            f"({triaged.confidence:.0%}): "
                            f"{issue.title} ({elapsed:.1f}s)"
                        )
                elif sys.stderr.isatty():
                    bar_w = 20
                    filled = int(bar_w * completed / total) if total else bar_w
                    bar = (
                        "=" * filled
                        + (">" if filled < bar_w else "")
                        + " " * max(0, bar_w - filled - 1)
                    )
                    avg = sum(timings) / len(timings)
                    print(
                        f"\r      Validating AI issues: [{bar}] "
                        f"{completed}/{total} (avg {avg:.1f}s/issue)",
                        end="",
                        flush=True,
                    )

        if not self.verbose and sys.stderr.isatty() and total > 0:
            print()

        phase_elapsed = time.monotonic() - phase_start
        if total > 0:
            avg_t = sum(timings) / len(timings)
            speedup = sum(timings) / phase_elapsed if phase_elapsed > 0 else 1.0
            with self._print_lock:
                tp = sum(1 for t in ordered.values() if t.is_true_positive)
                fp = total - tp
                print(
                    f"      Validated {total} AI issue(s) in {phase_elapsed:.1f}s "
                    f"(avg {avg_t:.1f}s, ~{speedup:.1f}x parallel speedup)"
                )
                print(
                    f"      Result: {tp} true positive(s), "
                    f"{fp} false positive(s) removed"
                )

        return [ordered[i] for i in range(total)]

    def generate_triage_report(
        self,
        triaged_issues: list[TriagedIssue],
    ) -> str:
        """Generate a human-readable triage report for AI review issues."""
        lines = [
            "=" * 60,
            "AI REVIEW TRIAGE REPORT",
            "=" * 60,
            "",
        ]

        true_positives = [t for t in triaged_issues if t.is_true_positive]
        false_positives = [t for t in triaged_issues if not t.is_true_positive]

        lines.extend([
            f"Total AI issues validated: {len(triaged_issues)}",
            f"True positives: {len(true_positives)}",
            f"False positives: {len(false_positives)}",
            "",
        ])

        if true_positives:
            lines.extend([
                "-" * 60,
                "CONFIRMED ISSUES",
                "-" * 60,
                "",
            ])
            for t in true_positives:
                lines.extend([
                    f"[{t.adjusted_severity.upper()}] {t.original.title}",
                    f"  Component: {t.original.component}",
                    f"  Confidence: {t.confidence:.0%}",
                    f"  Explanation: {t.explanation[:200]}",
                    "",
                ])

        if false_positives:
            lines.extend([
                "-" * 60,
                "FALSE POSITIVES (removed)",
                "-" * 60,
                "",
            ])
            for t in false_positives:
                lines.extend([
                    f"  - {t.original.title}: {t.explanation[:120]}",
                ])

        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _triage_timed(
        self,
        issue: SecurityIssue,
        content: Optional[str],
    ) -> tuple[TriagedIssue, float]:
        start = time.monotonic()
        result = self.triage_issue(issue, content)
        return result, time.monotonic() - start

    def _parse_response(self, content: str) -> dict:
        """Parse LLM response JSON with robust error handling."""
        content = content.strip()

        if "```" in content:
            match = re.search(r"```(?:json)?\s*([\s\S]*?)```", content)
            if match:
                content = match.group(1).strip()

        try:
            return json.loads(content)
        except json.JSONDecodeError:
            pass

        json_match = re.search(r"\{[\s\S]*\}", content)
        if json_match:
            json_str = json_match.group()
            try:
                return json.loads(json_str)
            except json.JSONDecodeError:
                pass

            fixed = self._fix_json(json_str)
            try:
                return json.loads(fixed)
            except json.JSONDecodeError as e:
                if self.verbose:
                    print(f"      JSON parse error: {e}")

        return {
            "is_true_positive": False,
            "confidence": 0.0,
            "reasoning": "Failed to parse LLM response",
            "evidence": "",
        }

    @staticmethod
    def _fix_json(json_str: str) -> str:
        json_str = re.sub(r",(\s*[\]}])", r"\1", json_str)
        json_str = re.sub(r"//[^\n]*\n", "\n", json_str)
        json_str = re.sub(r"/\*[\s\S]*?\*/", "", json_str)
        json_str = re.sub(
            r"(\{|,)\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*:", r'\1"\2":', json_str
        )
        json_str = re.sub(r":\s*'([^']*)'", r': "\1"', json_str)
        json_str = re.sub(r"[\x00-\x1f\x7f-\x9f]", "", json_str)
        return json_str
