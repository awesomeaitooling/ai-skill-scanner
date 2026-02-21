"""
AI-powered triaging of security findings.

Uses LLM to analyze and prioritize security issues found by the scanner.
Includes prompt injection protection via random delimiter sandboxing.
Supports parallel triage via ThreadPoolExecutor with configurable workers
and rate limiting.
"""

import json
import sys
import time
import threading
from typing import Optional
from dataclasses import dataclass, asdict
from concurrent.futures import ThreadPoolExecutor, as_completed

from scanner.core.skill_analyzer import SecurityFinding
from scanner.ai.prompt_guard import PromptGuard, sanitize_for_prompt
from scanner.ai.providers import extract_text_content, invoke_with_retry, RateLimiter


@dataclass
class TriagedFinding:
    """A security finding with AI triage information."""
    original: SecurityFinding
    
    # AI triage fields
    is_true_positive: bool
    confidence: float  # 0.0 to 1.0
    adjusted_severity: str  # critical, high, medium, low
    explanation: str
    exploitation_scenario: Optional[str]
    remediation_steps: list[str]
    priority_score: int  # 1-10
    evidence: Optional[str] = None  # exact quoted code proving the issue
    
    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "original": {
                "severity": self.original.severity,
                "rule_id": self.original.rule_id,
                "rule_name": self.original.rule_name,
                "message": self.original.message,
                "component_type": self.original.component_type,
                "component_name": self.original.component_name,
                "line": self.original.line,
            },
            "triage": {
                "is_true_positive": self.is_true_positive,
                "confidence": self.confidence,
                "adjusted_severity": self.adjusted_severity,
                "explanation": self.explanation,
                "exploitation_scenario": self.exploitation_scenario,
                "remediation_steps": self.remediation_steps,
                "priority_score": self.priority_score,
                "evidence": self.evidence,
            }
        }


TRIAGE_SYSTEM_PROMPT = """\
You are a senior security engineer performing a second-opinion review of \
findings produced by an automated static analysis scanner for Claude Code plugins.

Your job is to verify whether each flagged finding is a REAL vulnerability or \
a false positive by cross-checking it against the actual component source code.

Be SKEPTICAL. Static analysis scanners frequently:
- Match keywords or patterns that look dangerous but are harmless in context
- Flag documentation, comments, or example code as live vulnerabilities
- Report theoretical risks that are not actually exploitable
- Trigger on benign uses of shell commands, filesystem paths, or network APIs
- Misidentify configuration or test fixtures as production attack surface

You MUST:
1. Find the EXACT line(s) in the component content that demonstrate the \
vulnerability. Quote them verbatim in the "evidence" field.
2. If you cannot find concrete evidence in the content, mark it as a false \
positive with evidence set to null.
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

TRIAGE_USER_PROMPT = """\
Verify whether this static-analysis finding is real or a false positive.

**Finding:**
- Rule: {rule_name} ({rule_id})
- Severity: {severity}
- Component: {component_type} - {component_name}
- Message: {message}
- Line: {line}

**Full component content:**
```
{component_content}
```

Search the content above for concrete evidence of this vulnerability. \
If you cannot find the specific code/pattern described in the finding, \
it is a false positive.

Respond with ONLY valid JSON (no markdown, no explanation outside JSON):
{{
  "is_true_positive": true or false,
  "confidence": 0.0 to 1.0,
  "adjusted_severity": "critical" or "high" or "medium" or "low",
  "explanation": "Brief explanation of why this is or is not a real issue",
  "evidence": "Exact quoted line(s) from the content proving the issue, or null if false positive",
  "exploitation_scenario": "How an attacker could exploit this, or null if false positive",
  "remediation_steps": ["Step 1", "Step 2"],
  "priority_score": 1 to 10
}}"""


class AITriager:
    """AI-powered security finding triager with evidence-based cross-checking."""

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
    
    def triage_finding(
        self,
        finding: SecurityFinding,
        component_content: Optional[str] = None,
    ) -> TriagedFinding:
        """
        Triage a single security finding by cross-checking it against
        the actual component content.
        """
        content = (component_content or "")[:self.MAX_CONTENT_LENGTH]

        # PromptGuard layer 1: pre-scan for injection
        if content:
            detection = self.guard.scan_content(
                content,
                component_name=finding.component_name,
            )
            if detection:
                if self.verbose:
                    with self._print_lock:
                        print(f"  [ALERT] Prompt injection in component '{finding.component_name}': "
                              f"{detection.pattern_matched}")
                return TriagedFinding(
                    original=finding,
                    is_true_positive=True,
                    confidence=0.95,
                    adjusted_severity="high",
                    explanation=(
                        f"Component content contains a prompt injection attempt: "
                        f"{detection.pattern_matched} (matched: '{detection.matched_text}'). "
                        f"Content was NOT sent to LLM to prevent analyzer manipulation."
                    ),
                    exploitation_scenario=(
                        "Attacker embeds instructions in plugin content to trick "
                        "the AI triage into classifying malicious findings as false positives."
                    ),
                    remediation_steps=[
                        "Remove manipulative content from the component",
                        "Manually review the original finding",
                        "Treat this plugin as potentially hostile",
                    ],
                    priority_score=9,
                    evidence=detection.matched_text,
                )

        # PromptGuard layer 2: wrap untrusted content
        wrapped_content = (
            self.guard.wrap_untrusted(content) if content else "Not available"
        )
        
        # PromptGuard layer 3: system guard addendum
        guarded_system_prompt = (
            TRIAGE_SYSTEM_PROMPT + self.guard.get_system_guard_prompt()
        )
        
        user_prompt = TRIAGE_USER_PROMPT.format(
            rule_name=sanitize_for_prompt(finding.rule_name),
            rule_id=sanitize_for_prompt(finding.rule_id),
            severity=sanitize_for_prompt(finding.severity),
            component_type=sanitize_for_prompt(finding.component_type),
            component_name=sanitize_for_prompt(finding.component_name),
            message=sanitize_for_prompt(finding.message),
            line=finding.line or "N/A",
            component_content=wrapped_content,
        )
        
        messages = [
            {"role": "system", "content": guarded_system_prompt},
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
                    print(f"  AI triage error: {e}")
            result = {
                "is_true_positive": True,
                "confidence": 0.5,
                "adjusted_severity": finding.severity,
                "explanation": f"AI triage failed: {e}",
                "evidence": None,
                "exploitation_scenario": None,
                "remediation_steps": [finding.recommendation] if finding.recommendation else [],
                "priority_score": 5,
            }
        
        return TriagedFinding(
            original=finding,
            is_true_positive=result.get("is_true_positive", True),
            confidence=result.get("confidence", 0.5),
            adjusted_severity=result.get("adjusted_severity", finding.severity),
            explanation=result.get("explanation", ""),
            exploitation_scenario=result.get("exploitation_scenario"),
            remediation_steps=result.get("remediation_steps", []),
            priority_score=result.get("priority_score", 5),
            evidence=result.get("evidence"),
        )
    
    def triage_findings(
        self,
        findings: list[SecurityFinding],
        component_contents: Optional[dict[str, str]] = None,
    ) -> list[TriagedFinding]:
        """
        Triage multiple findings in parallel.
        
        Args:
            findings: List of findings to triage
            component_contents: Dict mapping component_name to content
        
        Returns:
            List of triaged findings sorted by priority score (descending)
        """
        total = len(findings)
        if total == 0:
            return []

        completed = 0
        finding_times: list[float] = []
        ordered_results: dict[int, TriagedFinding] = {}

        effective_workers = min(self.max_workers, total)
        phase_start = time.monotonic()

        with ThreadPoolExecutor(max_workers=effective_workers) as pool:
            future_to_idx = {}
            for idx, finding in enumerate(findings):
                content = None
                if component_contents:
                    content = component_contents.get(finding.component_name)
                future = pool.submit(self._triage_finding_timed, finding, content)
                future_to_idx[future] = (idx, finding)

            for future in as_completed(future_to_idx):
                idx, finding = future_to_idx[future]
                triaged_finding, elapsed = future.result()
                ordered_results[idx] = triaged_finding
                finding_times.append(elapsed)
                completed += 1

                if self.verbose:
                    with self._print_lock:
                        print(
                            f"  [{completed}/{total}] Triaged: "
                            f"{finding.rule_name} ({elapsed:.1f}s)"
                        )
                elif sys.stderr.isatty():
                    bar_width = 20
                    filled = int(bar_width * completed / total) if total else bar_width
                    bar = "=" * filled + ">" * (1 if filled < bar_width else 0) + " " * (bar_width - filled - (1 if filled < bar_width else 0))
                    avg = sum(finding_times) / len(finding_times)
                    print(
                        f"\r      Triaging: [{bar}] {completed}/{total} "
                        f"(avg {avg:.1f}s/finding)",
                        end="", flush=True,
                    )

        # Clear progress line
        if not self.verbose and sys.stderr.isatty() and total > 0:
            print()

        phase_elapsed = time.monotonic() - phase_start
        sequential_estimate = sum(finding_times) if finding_times else 0
        speedup = sequential_estimate / phase_elapsed if phase_elapsed > 0 else 1.0

        if total > 0:
            avg_time = sum(finding_times) / len(finding_times)
            with self._print_lock:
                print(
                    f"      Triaged {total} finding(s) in {phase_elapsed:.1f}s "
                    f"(avg {avg_time:.1f}s, ~{speedup:.1f}x parallel speedup)"
                )

        # Collect in original order, then sort by priority
        triaged = [ordered_results[i] for i in range(total)]
        triaged.sort(key=lambda t: t.priority_score, reverse=True)
        return triaged

    def _triage_finding_timed(
        self,
        finding: SecurityFinding,
        content: Optional[str],
    ) -> tuple[TriagedFinding, float]:
        """Triage a single finding and return (result, elapsed_seconds)."""
        start = time.monotonic()
        result = self.triage_finding(finding, content)
        elapsed = time.monotonic() - start
        return result, elapsed
    
    def _parse_response(self, content: str) -> dict:
        """Parse LLM response JSON with robust error handling."""
        import re
        
        content = content.strip()
        
        # Handle markdown code blocks (```json or ```)
        if "```" in content:
            code_block_match = re.search(r'```(?:json)?\s*([\s\S]*?)```', content)
            if code_block_match:
                content = code_block_match.group(1).strip()
        
        # Try direct parse first
        try:
            return json.loads(content)
        except json.JSONDecodeError:
            pass
        
        # Try to extract JSON object from mixed content
        json_match = re.search(r'\{[\s\S]*\}', content)
        if json_match:
            json_str = json_match.group()
            
            try:
                return json.loads(json_str)
            except json.JSONDecodeError:
                pass
            
            # Fix common JSON issues from LLMs
            fixed_json = self._fix_json_issues(json_str)
            try:
                return json.loads(fixed_json)
            except json.JSONDecodeError as e:
                if self.verbose:
                    print(f"      JSON parse error: {e}")
        
        return {
            "is_true_positive": False,
            "confidence": 0.0,
            "reasoning": "Failed to parse LLM response",
            "evidence": "",
        }
    
    def _fix_json_issues(self, json_str: str) -> str:
        """Attempt to fix common JSON formatting issues from LLMs."""
        import re
        
        # Remove trailing commas before ] or }
        json_str = re.sub(r',(\s*[\]}])', r'\1', json_str)
        
        # Remove JavaScript-style comments
        json_str = re.sub(r'//[^\n]*\n', '\n', json_str)
        json_str = re.sub(r'/\*[\s\S]*?\*/', '', json_str)
        
        # Fix unquoted keys
        json_str = re.sub(r'(\{|\,)\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*:', r'\1"\2":', json_str)
        
        # Fix single quotes to double quotes for string values
        json_str = re.sub(r":\s*'([^']*)'", r': "\1"', json_str)
        
        # Remove control characters
        json_str = re.sub(r'[\x00-\x1f\x7f-\x9f]', '', json_str)
        
        return json_str
    
    def generate_triage_report(
        self,
        triaged_findings: list[TriagedFinding],
    ) -> str:
        """Generate a human-readable triage report."""
        lines = [
            "=" * 60,
            "AI TRIAGE REPORT",
            "=" * 60,
            "",
        ]
        
        # Summary
        true_positives = [t for t in triaged_findings if t.is_true_positive]
        false_positives = [t for t in triaged_findings if not t.is_true_positive]
        
        lines.extend([
            f"Total findings analyzed: {len(triaged_findings)}",
            f"True positives: {len(true_positives)}",
            f"False positives: {len(false_positives)}",
            "",
        ])
        
        # Severity breakdown for true positives
        severity_counts = {}
        for t in true_positives:
            sev = t.adjusted_severity
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
        
        lines.append("Severity breakdown (true positives):")
        for sev in ["critical", "high", "medium", "low"]:
            count = severity_counts.get(sev, 0)
            if count > 0:
                lines.append(f"  {sev.upper()}: {count}")
        lines.append("")
        
        # Top priority findings
        lines.extend([
            "-" * 60,
            "TOP PRIORITY FINDINGS",
            "-" * 60,
            "",
        ])
        
        for t in triaged_findings[:10]:
            if not t.is_true_positive:
                continue
            lines.extend([
                f"[{t.adjusted_severity.upper()}] {t.original.rule_name}",
                f"  Component: {t.original.component_type}/{t.original.component_name}",
                f"  Priority: {t.priority_score}/10 | Confidence: {t.confidence:.0%}",
                f"  Explanation: {t.explanation[:200]}...",
                "",
            ])
        
        # False positives
        if false_positives:
            lines.extend([
                "-" * 60,
                "FALSE POSITIVES",
                "-" * 60,
                "",
            ])
            for t in false_positives:
                lines.extend([
                    f"  - {t.original.rule_name}: {t.explanation[:100]}...",
                ])
        
        return "\n".join(lines)

