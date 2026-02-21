"""
Per-component AI security scanner with full prompt injection protection.

Orchestrates component-by-component LLM analysis using type-specific prompts
from the prompt registry, enforcing all 3 PromptGuard layers on every call:

  1. Pre-scan detection  — block content with injection patterns before LLM call
  2. Random delimiter wrapping — sandbox untrusted content so LLM treats it as data
  3. System prompt guard  — instruct LLM to never follow delimited content

Used by ``--ai-only`` mode for deep, structured analysis of each plugin component.
Supports parallel scanning via ThreadPoolExecutor with configurable workers and
rate limiting.
"""

import json
import re
import sys
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional

from scanner.core.plugin_parser import ParsedPlugin, PluginComponent
from scanner.ai.prompt_guard import PromptGuard, InjectionDetection
from scanner.ai.reviewer import AIReviewResult, SecurityIssue, _safe_int, _add_line_numbers
from scanner.ai.prompts import (
    get_system_prompt,
    get_user_prompt,
    get_cross_component_prompts,
)
from scanner.rules.sections import get_section
from scanner.ai.providers import extract_text_content, invoke_with_retry, RateLimiter
from scanner.utils.redaction import redact_secrets


class AIComponentScanner:
    """
    Per-component AI security scanner.

    Unlike :class:`AISecurityReviewer` (which sends all components in a
    single monolithic prompt), this scanner makes **one LLM call per
    component** with a type-specific prompt, then a final cross-component
    call to detect attack chains.

    Every piece of untrusted content goes through all three PromptGuard
    layers before reaching the LLM.
    """

    # Content limits to keep within LLM token budgets
    MAX_CONTENT_PER_COMPONENT = 8000
    MAX_CROSS_COMPONENT_SUMMARY = 12000

    def __init__(
        self,
        llm,
        verbose: bool = False,
        max_workers: int = 4,
        rate_limiter: Optional[RateLimiter] = None,
    ):
        """
        Initialise the scanner.

        Args:
            llm: LangChain LLM instance (any supported provider).
            verbose: Whether to print progress and debug information.
            max_workers: Maximum parallel LLM calls for component scanning.
            rate_limiter: Optional shared rate limiter for API throttling.
        """
        self.llm = llm
        self.verbose = verbose
        self.max_workers = max(1, max_workers)
        self.rate_limiter = rate_limiter
        # Single PromptGuard instance — one random delimiter for the session
        self.guard = PromptGuard()
        # Lock for thread-safe verbose output
        self._print_lock = threading.Lock()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def scan_plugin(self, plugin: ParsedPlugin) -> AIReviewResult:
        """
        Scan an entire plugin component-by-component, then run
        cross-component analysis.

        Components are scanned in parallel using up to ``max_workers``
        threads.  A shared :class:`RateLimiter` throttles API calls
        when ``--rpm`` is set.

        Returns a merged :class:`AIReviewResult` combining all findings.
        """
        all_issues: list[SecurityIssue] = []
        all_recommendations: list[str] = []
        all_positives: list[str] = []
        per_component_summaries: list[str] = []
        max_risk = 0
        total = len(plugin.components)

        if self.verbose:
            print(f"\n      Per-component AI scan — {total} component(s)")
            print(f"      PromptGuard: enabled")
            print(f"      Workers: {self.max_workers}")

        # --- Phase 1: Per-component scans (parallel) ---
        phase1_start = time.monotonic()
        completed = 0
        component_times: list[float] = []

        # Ordered results: index -> (result, component)
        ordered_results: dict[int, tuple[AIReviewResult, PluginComponent]] = {}

        effective_workers = min(self.max_workers, total) if total > 0 else 1

        with ThreadPoolExecutor(max_workers=effective_workers) as pool:
            future_to_idx = {}
            for idx, comp in enumerate(plugin.components):
                future = pool.submit(self._scan_component_timed, comp, idx, total)
                future_to_idx[future] = (idx, comp)

            for future in as_completed(future_to_idx):
                idx, comp = future_to_idx[future]
                result, elapsed = future.result()
                ordered_results[idx] = (result, comp)
                component_times.append(elapsed)
                completed += 1

                # Progress output
                if self.verbose:
                    with self._print_lock:
                        print(
                            f"      [{completed}/{total}] "
                            f"{comp.type}: {comp.name} ({elapsed:.1f}s) "
                            f"— {len(result.issues)} issue(s)"
                        )
                elif not self.verbose and sys.stderr.isatty():
                    bar_width = 20
                    filled = int(bar_width * completed / total) if total else bar_width
                    bar = "=" * filled + ">" * (1 if filled < bar_width else 0) + " " * (bar_width - filled - (1 if filled < bar_width else 0))
                    avg = sum(component_times) / len(component_times)
                    print(
                        f"\r      Scanning: [{bar}] {completed}/{total} "
                        f"(avg {avg:.1f}s/component)",
                        end="", flush=True,
                    )

        # Clear progress line if we printed one
        if not self.verbose and sys.stderr.isatty() and total > 0:
            print()

        # Collect results in original order
        for idx in range(total):
            result, comp = ordered_results[idx]
            all_issues.extend(result.issues)
            all_recommendations.extend(result.recommendations)
            all_positives.extend(result.positive_findings)
            max_risk = max(max_risk, result.risk_score)

            issue_briefs = "; ".join(
                f"{i.severity}/{i.category}: {i.title}"
                for i in result.issues[:5]
            ) or "no issues"
            per_component_summaries.append(
                f"[{comp.type}] {comp.name} — risk {result.risk_score}/10 — {issue_briefs}"
            )

        phase1_elapsed = time.monotonic() - phase1_start
        sequential_estimate = sum(component_times) if component_times else 0
        speedup = sequential_estimate / phase1_elapsed if phase1_elapsed > 0 else 1.0

        if total > 0:
            avg_time = sum(component_times) / len(component_times)
            with self._print_lock:
                print(
                    f"      Scanned {total} component(s) in {phase1_elapsed:.1f}s "
                    f"(avg {avg_time:.1f}s, ~{speedup:.1f}x parallel speedup)"
                )

        # --- Phase 2: Cross-component analysis ---
        if total >= 2:
            if self.verbose:
                print(f"\n      Running cross-component analysis...")
            cross_result = self._cross_component_analysis(
                plugin, per_component_summaries
            )
            if cross_result:
                all_issues.extend(cross_result.issues)
                all_recommendations.extend(cross_result.recommendations)
                max_risk = max(max_risk, cross_result.risk_score)

        # --- Merge ---
        seen_recs: set[str] = set()
        unique_recs: list[str] = []
        for rec in all_recommendations:
            key = rec.strip().lower()
            if key not in seen_recs:
                seen_recs.add(key)
                unique_recs.append(rec)

        n_issues = len(all_issues)
        severity_counts: dict[str, int] = {}
        for iss in all_issues:
            severity_counts[iss.severity] = severity_counts.get(iss.severity, 0) + 1
        severity_desc = ", ".join(
            f"{count} {sev}" for sev, count in severity_counts.items()
        )
        summary = (
            f"AI per-component scan of {total} component(s) found "
            f"{n_issues} issue(s) ({severity_desc or 'none'}). "
            f"Overall risk: {max_risk}/10."
        )

        return AIReviewResult(
            plugin_name=plugin.manifest.name,
            summary=summary,
            risk_score=max_risk,
            issues=all_issues,
            recommendations=unique_recs[:10],
            positive_findings=list(dict.fromkeys(all_positives))[:10],
        )

    def _scan_component_timed(
        self,
        component: PluginComponent,
        idx: int,
        total: int,
    ) -> tuple[AIReviewResult, float]:
        """Scan a single component and return (result, elapsed_seconds)."""
        start = time.monotonic()
        result = self.scan_component(component)
        elapsed = time.monotonic() - start
        return result, elapsed

    def scan_component(self, component: PluginComponent) -> AIReviewResult:
        """
        Scan a single component with its type-specific prompt.

        Enforces all 3 PromptGuard layers:
          1. Pre-scan content for injection patterns -> block if detected
          2. Wrap clean content in random delimiters
          3. Append system guard instructions to the system prompt

        Thread-safe: can be called from multiple worker threads.
        Returns an :class:`AIReviewResult` for this component.
        """
        comp_name = component.name
        comp_type = component.type
        content = component.content or json.dumps(component.metadata, indent=2)

        # Buffer verbose output to print atomically
        log: list[str] = []

        # ============================================================
        # LAYER 1: Pre-scan -- detect injection BEFORE calling LLM
        # ============================================================
        detection = self.guard.scan_content(content, component_name=comp_name)
        if detection:
            detection.file_path = component.path
            if self.verbose:
                log.append(
                    f"        [BLOCKED] Injection detected in '{comp_name}': "
                    f"{detection.pattern_matched} -> '{detection.matched_text}'"
                )
                self._flush_log(log)
            return self._make_injection_result(comp_name, [detection])

        if self.verbose:
            log.append(f"        Pre-scan clean. Content size: {len(content):,} chars")

        # Truncate to stay within token limits
        if len(content) > self.MAX_CONTENT_PER_COMPONENT:
            content = content[: self.MAX_CONTENT_PER_COMPONENT] + "\n...(truncated)"

        # Add line numbers so the LLM can reference exact lines
        numbered_content = _add_line_numbers(content)

        # ============================================================
        # LAYER 2: Wrap untrusted content in random delimiters
        # ============================================================
        wrapped_content = self.guard.wrap_untrusted(numbered_content)

        # ============================================================
        # LAYER 3: Build prompts with system guard addendum
        # ============================================================
        system_prompt = (
            get_system_prompt(comp_type)
            + self.guard.get_system_guard_prompt()
        )
        user_prompt = get_user_prompt(
            component_type=comp_type,
            component_name=comp_name,
            component_path=component.path or "",
            wrapped_content=wrapped_content,
        )

        if self.verbose:
            log.append(f"        Prompt type: {comp_type}")
            log.append(f"        User prompt size: {len(user_prompt):,} chars")
            log.append(f"        Sending to LLM...")

        # ============================================================
        # LLM call with retry + rate limiting
        # ============================================================
        messages = [
            {"role": "system", "content": system_prompt},
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

            if self.verbose:
                log.append(f"        Response size: {len(raw):,} chars")
                if raw:
                    log.append(f"        --- PREVIEW ---")
                    log.append(redact_secrets(raw[:500]))
                    log.append(f"        --- END PREVIEW ---")

            result = self._parse_response(raw)

        except Exception as e:
            if self.verbose:
                log.append(f"        [ERROR] LLM call failed: {e}")
                self._flush_log(log)
            return AIReviewResult(
                plugin_name=comp_name,
                summary=f"AI scan of {comp_type}/{comp_name} failed: {e}",
                risk_score=5,
                issues=[],
                recommendations=["Manual security review recommended"],
                positive_findings=[],
            )

        if self.verbose:
            self._flush_log(log)

        # Convert parsed dict -> SecurityIssue objects
        issues: list[SecurityIssue] = []
        for item in result.get("issues", []):
            category = item.get("category", "unknown")
            issues.append(
                SecurityIssue(
                    severity=item.get("severity", "medium"),
                    category=category,
                    title=item.get("title", "Untitled"),
                    description=item.get("description", ""),
                    component=comp_name,
                    location=item.get("location"),
                    exploitation=item.get("exploitation", ""),
                    remediation=item.get("remediation", ""),
                    confidence=item.get("confidence", 0.5),
                    section=item.get("section", get_section(category)),
                    line_number=_safe_int(item.get("line_number")),
                    file_path=item.get("file_path") or component.path,
                    code_snippet=item.get("code_snippet") or None,
                )
            )

        return AIReviewResult(
            plugin_name=comp_name,
            summary=result.get("summary", ""),
            risk_score=result.get("risk_score", 5),
            issues=issues,
            recommendations=result.get("recommendations", []),
            positive_findings=result.get("positive_findings", []),
        )

    def _flush_log(self, log: list[str]) -> None:
        """Print buffered log lines atomically under the print lock."""
        if log:
            with self._print_lock:
                print("\n".join(log), flush=True)

    # ------------------------------------------------------------------
    # Cross-component analysis (also fully guarded)
    # ------------------------------------------------------------------

    def _cross_component_analysis(
        self,
        plugin: ParsedPlugin,
        per_component_summaries: list[str],
    ) -> Optional[AIReviewResult]:
        """
        Final LLM call to detect cross-component attack patterns.

        The per-component summaries are treated as untrusted data and
        go through all 3 PromptGuard layers.
        """
        # Build a components-summary string (type counts, names)
        by_type: dict[str, list[str]] = {}
        for comp in plugin.components:
            by_type.setdefault(comp.type, []).append(comp.name)
        components_summary_lines = []
        for ctype, names in by_type.items():
            components_summary_lines.append(
                f"  {ctype.upper()}S ({len(names)}): {', '.join(names[:5])}"
                + ("..." if len(names) > 5 else "")
            )
        components_summary = "\n".join(components_summary_lines)

        # Combine per-component summaries into a single block
        raw_summaries = "\n".join(per_component_summaries)

        # ============================================================
        # LAYER 1: Pre-scan the combined summaries
        # ============================================================
        # Summaries are derived from LLM output + component names, so they
        # may inadvertently carry through injected text from component content.
        detection = self.guard.scan_content(
            raw_summaries, component_name="cross-component-summaries"
        )
        if detection:
            if self.verbose:
                print(
                    f"        [BLOCKED] Injection in cross-component summaries: "
                    f"{detection.pattern_matched}"
                )
            return self._make_injection_result(
                plugin.manifest.name, [detection]
            )

        # Truncate if needed
        if len(raw_summaries) > self.MAX_CROSS_COMPONENT_SUMMARY:
            raw_summaries = (
                raw_summaries[: self.MAX_CROSS_COMPONENT_SUMMARY]
                + "\n...(truncated)"
            )

        # ============================================================
        # LAYER 2: Wrap summaries in random delimiters
        # ============================================================
        wrapped_summaries = self.guard.wrap_untrusted(raw_summaries)

        # ============================================================
        # LAYER 3: Build prompts with system guard addendum
        # ============================================================
        cross_system, cross_user = get_cross_component_prompts(
            plugin_name=plugin.manifest.name,
            version=plugin.manifest.version,
            description=plugin.manifest.description or "",
            components_summary=components_summary,
            per_component_summaries=wrapped_summaries,
        )
        cross_system += self.guard.get_system_guard_prompt()

        if self.verbose:
            print(f"        Cross-component prompt size: {len(cross_user):,} chars")
            print(f"        Sending to LLM...")

        messages = [
            {"role": "system", "content": cross_system},
            {"role": "user", "content": cross_user},
        ]

        try:
            response = invoke_with_retry(
                self.llm,
                messages,
                rate_limiter=self.rate_limiter,
                verbose=self.verbose,
            )
            raw = extract_text_content(response.content)

            if self.verbose:
                print(f"        Cross-component response: {len(raw):,} chars")

            result = self._parse_response(raw)

        except Exception as e:
            if self.verbose:
                print(f"        [ERROR] Cross-component analysis failed: {e}")
            return None

        # Convert to AIReviewResult
        issues: list[SecurityIssue] = []
        for item in result.get("issues", []):
            category = item.get("category", "cross_component")
            issues.append(
                SecurityIssue(
                    severity=item.get("severity", "medium"),
                    category=category,
                    title=item.get("title", "Untitled"),
                    description=item.get("description", ""),
                    component=item.get("component", "cross-component"),
                    location=item.get("location"),
                    exploitation=item.get("exploitation", ""),
                    remediation=item.get("remediation", ""),
                    confidence=item.get("confidence", 0.5),
                    section=item.get("section", get_section(category)),
                    line_number=_safe_int(item.get("line_number")),
                    file_path=item.get("file_path") or None,
                    code_snippet=item.get("code_snippet") or None,
                )
            )

        return AIReviewResult(
            plugin_name=plugin.manifest.name,
            summary=result.get("summary", ""),
            risk_score=result.get("risk_score", 5),
            issues=issues,
            recommendations=result.get("recommendations", []),
            positive_findings=result.get("positive_findings", []),
        )

    # ------------------------------------------------------------------
    # Injection result builder
    # ------------------------------------------------------------------

    def _make_injection_result(
        self,
        name: str,
        detections: list[InjectionDetection],
    ) -> AIReviewResult:
        """Build an AIReviewResult for detected prompt injection attempts."""
        issues = []
        for det in detections:
            issues.append(
                SecurityIssue(
                    severity="high",
                    category="prompt_injection",
                    title=f"Prompt injection detected: {det.pattern_matched}",
                    description=(
                        f"Component '{det.component_name}' contains content "
                        f"that attempts to manipulate the AI analyzer. "
                        f"Matched pattern: {det.pattern_matched}. "
                        f"Matched text: '{det.matched_text}'"
                    ),
                    component=det.component_name,
                    location=None,
                    exploitation=(
                        "An attacker could embed instructions in plugin content "
                        "to trick the AI security reviewer into reporting a "
                        "malicious plugin as safe."
                    ),
                    remediation=(
                        "Remove or sanitize the manipulative content. Plugin "
                        "content should not contain instructions aimed at AI "
                        "analyzers."
                    ),
                    confidence=0.95,
                    section=get_section("prompt_injection"),
                    line_number=det.line_number,
                    file_path=det.file_path,
                    code_snippet=det.context_snippet or det.matched_text,
                )
            )

        return AIReviewResult(
            plugin_name=name,
            summary=(
                f"PROMPT INJECTION DETECTED in {len(detections)} component(s). "
                "Analysis was blocked to prevent bypass. Manual review required."
            ),
            risk_score=9,
            issues=issues,
            recommendations=[
                "Manually review flagged components for malicious instructions",
                "Remove any content that attempts to manipulate AI analyzers",
                "Treat this plugin as potentially hostile",
            ],
            positive_findings=[],
        )

    # ------------------------------------------------------------------
    # JSON response parsing (reused from reviewer.py logic)
    # ------------------------------------------------------------------

    def _parse_response(self, content: str) -> dict:
        """Parse LLM JSON response with robust error handling."""
        if not content:
            return self._default_response("Empty response from LLM")

        original = content
        content = content.strip()

        # Strip markdown code fences
        if "```" in content:
            m = re.search(r"```(?:json)?\s*([\s\S]*?)```", content)
            if m:
                content = m.group(1).strip()

        # Direct parse
        try:
            return json.loads(content)
        except json.JSONDecodeError:
            pass

        # Extract outermost JSON object
        m = re.search(r"\{[\s\S]*\}", content)
        if m:
            extracted = m.group()
            try:
                return json.loads(extracted)
            except json.JSONDecodeError:
                pass

            # Fix common LLM JSON issues and retry
            fixed = self._fix_json(extracted)
            try:
                return json.loads(fixed)
            except json.JSONDecodeError:
                pass

        # Last resort: extract from text
        return self._extract_from_text(original)

    @staticmethod
    def _default_response(msg: str) -> dict:
        return {
            "summary": msg,
            "risk_score": 5,
            "issues": [],
            "recommendations": ["Manual security review recommended"],
            "positive_findings": [],
        }

    @staticmethod
    def _fix_json(s: str) -> str:
        """Fix common LLM JSON formatting mistakes."""
        # Trailing commas
        s = re.sub(r",(\s*[\]}])", r"\1", s)
        # JS comments
        s = re.sub(r"//[^\n]*\n", "\n", s)
        s = re.sub(r"/\*[\s\S]*?\*/", "", s)
        # Unquoted keys
        s = re.sub(r'(\{|,)\s*([a-zA-Z_]\w*)\s*:', r'\1"\2":', s)
        # Single-quoted string values
        s = re.sub(r":\s*'([^']*)'", r': "\1"', s)
        # Control chars
        s = re.sub(r"[\x00-\x1f\x7f-\x9f]", "", s)
        return s

    @staticmethod
    def _extract_from_text(content: str) -> dict:
        """Fallback: try to extract useful info from non-JSON response."""
        risk_m = re.search(r"risk\s*(?:score)?[:\s]*(\d+)", content, re.I)
        risk_score = int(risk_m.group(1)) if risk_m else 5

        issues: list[dict] = []
        for pattern, severity in [
            (r"critical[:\s]+([^\n]+)", "critical"),
            (r"high[:\s]+([^\n]+)", "high"),
            (r"medium[:\s]+([^\n]+)", "medium"),
        ]:
            for m in re.finditer(pattern, content, re.I):
                issues.append(
                    {
                        "severity": severity,
                        "category": "ai_extracted",
                        "title": m.group(1)[:100].strip(),
                        "description": m.group(1).strip(),
                        "component": "unknown",
                        "location": None,
                        "line_number": None,
                        "file_path": None,
                        "code_snippet": None,
                        "exploitation": "",
                        "remediation": "",
                        "confidence": 0.3,
                    }
                )

        paragraphs = content.split("\n\n")
        summary = paragraphs[0][:500] if paragraphs else "Could not parse AI response"

        return {
            "summary": summary,
            "risk_score": risk_score,
            "issues": issues[:10],
            "recommendations": ["Review AI output manually — JSON parsing failed"],
            "positive_findings": [],
        }

    # ------------------------------------------------------------------
    # Report generation
    # ------------------------------------------------------------------

    def generate_review_report(self, result: AIReviewResult) -> str:
        """Generate a human-readable report (delegates to reviewer format)."""
        # Re-use the same report format as AISecurityReviewer
        from scanner.ai.reviewer import AISecurityReviewer

        # Create a temporary reviewer just for formatting
        dummy = AISecurityReviewer.__new__(AISecurityReviewer)
        dummy.verbose = False
        return dummy.generate_review_report(result)
