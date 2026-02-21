"""
AI-powered security review of plugins and skills.

Uses LLM to perform deep security analysis beyond pattern matching.
Includes prompt injection protection via random delimiter sandboxing.
"""

import json
from typing import Optional
from dataclasses import dataclass

from scanner.core.plugin_parser import ParsedPlugin, PluginComponent
from scanner.ai.prompt_guard import PromptGuard, InjectionDetection
from scanner.ai.prompts import get_system_prompt, get_user_prompt
from scanner.rules.sections import get_section
from scanner.ai.providers import extract_text_content, invoke_with_retry, RateLimiter
from scanner.utils.redaction import redact_secrets


def _add_line_numbers(content: str) -> str:
    """Prefix each line with its 1-based line number so the LLM can reference exact lines."""
    lines = content.split('\n')
    return '\n'.join(f"{i+1:4d} | {line}" for i, line in enumerate(lines))


def _safe_int(value) -> Optional[int]:
    """Safely convert a value to int, returning None on failure."""
    if value is None:
        return None
    try:
        return int(value)
    except (ValueError, TypeError):
        return None


@dataclass
class SecurityIssue:
    """A security issue found by AI review."""
    severity: str  # critical, high, medium, low, info
    category: str  # e.g., "prompt_injection", "command_injection", "data_exposure"
    title: str
    description: str
    component: str
    location: Optional[str]
    exploitation: str
    remediation: str
    confidence: float  # 0.0 to 1.0
    section: str = "code_security"  # "malicious" or "code_security"
    line_number: Optional[int] = None
    file_path: Optional[str] = None
    code_snippet: Optional[str] = None
    
    def to_dict(self) -> dict:
        return {
            "severity": self.severity,
            "category": self.category,
            "section": self.section,
            "title": self.title,
            "description": self.description,
            "component": self.component,
            "location": self.location,
            "line_number": self.line_number,
            "file_path": self.file_path,
            "code_snippet": self.code_snippet,
            "exploitation": self.exploitation,
            "remediation": self.remediation,
            "confidence": self.confidence,
        }


@dataclass
class AIReviewResult:
    """Result of AI security review."""
    plugin_name: str
    summary: str
    risk_score: int  # 1-10
    issues: list[SecurityIssue]
    recommendations: list[str]
    positive_findings: list[str]  # Good security practices found
    
    def to_dict(self) -> dict:
        return {
            "plugin_name": self.plugin_name,
            "summary": self.summary,
            "risk_score": self.risk_score,
            "issues": [i.to_dict() for i in self.issues],
            "recommendations": self.recommendations,
            "positive_findings": self.positive_findings,
        }


REVIEW_SYSTEM_PROMPT = """You are an expert security researcher specializing in AI/LLM security, plugin security, and application security.

You're reviewing a Claude Code plugin/skill for security vulnerabilities. Claude Code plugins can:
- Define skills (markdown files with instructions for Claude)
- Define agents (AGENT.md with autonomous capabilities)
- Define commands (COMMAND.md with parameterized operations)
- Define hooks that intercept tool usage and user prompts
- Configure MCP/LSP servers for external tools
- Include scripts (Python, Bash, JS/TS)
- Bundle resources (config files, templates)
- Execute shell commands and access the filesystem

Analyze across all 17 security categories:
1. **Prompt Injection**: Instructions manipulating Claude's behavior, jailbreak attempts
2. **Command Injection**: Unsafe shell command construction, unsanitized arguments
3. **Path Traversal**: Accessing files outside intended directories, symlink attacks
4. **Credential Exposure**: Hardcoded secrets, insecure credential handling, env var leaks
5. **Privilege Escalation**: Hooks/tools granting excessive permissions, sudo usage
6. **Data Exfiltration**: Unauthorized data access/transmission, covert channels (DNS, WebSocket)
7. **Supply Chain**: Unsafe dependencies, typosquatting, external resource risks
8. **Autonomy Abuse**: Unbounded retries, no confirmation on destructive actions, self-modification
9. **Tool Poisoning**: Shadowing built-in tools, misleading descriptions, excessive permissions
10. **Obfuscation**: XOR encoding, chr() chains, dynamic getattr, reversed string execution
11. **Unicode Steganography**: Zero-width chars, RTL overrides, homoglyphs, tag characters
12. **Social Engineering**: Impersonation, trust-inducing language, hidden instructions, urgency
13. **Malicious Code**: Backdoors, RCE, credential theft in scripts, typosquatted packages
14. **Suspicious Downloads**: Downloads from unknown/untrusted domains, password-protected archives
15. **Third-Party Exposure**: Fetching untrusted third-party content enabling indirect prompt injection
16. **System Modification**: Modifying systemctl services, startup scripts, critical system files
17. **Financial Access**: Direct access to crypto wallets, trading platforms, bank accounts

Also check for:
- Alignment mismatches between descriptions and actual code behavior
- Cross-component attack chains (e.g., hook enabling script exfil)
- Agent-specific risks (unrestricted tool access, autonomous behavior without limits)
- Command-specific risks (argument injection via $ARGUMENTS)

Be thorough but avoid false positives. Focus on actual exploitable vulnerabilities. If you think there is an issue which is not related to security, you should not report. Mark it as a false positive."""

REVIEW_PLUGIN_PROMPT = """Review this Claude Code plugin for security vulnerabilities across all 17 categories.

**Plugin: {plugin_name}** (v{version})
{description}

**Components:**
{components_summary}

**Content (each line is prefixed with its line number):**
{detailed_content}

IMPORTANT: Respond with ONLY valid JSON (no markdown, no explanations). Keep descriptions brief (1-2 sentences max). Limit to top 10 most critical issues.

The content above has line numbers prefixed (e.g. "  42 | code here"). Use the exact line number from the prefix for line_number. Quote the exact vulnerable code in code_snippet (without the line number prefix).

{{
  "summary": "Brief security assessment (2-3 sentences)",
  "risk_score": 1-10,
  "issues": [
    {{
      "severity": "critical|high|medium|low",
      "category": "prompt_injection|command_injection|path_traversal|credential_exposure|privilege_escalation|data_exfiltration|supply_chain|autonomy_abuse|tool_poisoning|obfuscation|unicode_steganography|social_engineering|malicious_code|suspicious_downloads|third_party_exposure|system_modification|financial_access",
      "section": "malicious|code_security (malicious = intentional attack patterns like prompt injection, data exfiltration, obfuscation; code_security = bugs, misconfigurations, poor practices like injection vulns, credential exposure, supply chain risks)",
      "title": "Short title",
      "description": "Brief description",
      "component": "component name",
      "file_path": "path to the file containing the issue",
      "line_number": 42,
      "code_snippet": "exact vulnerable line(s) of code from the content",
      "exploitation": "Brief exploitation scenario",
      "remediation": "Brief fix",
      "confidence": 0.0-1.0
    }}
  ],
  "recommendations": ["Top 3-5 recommendations"],
  "positive_findings": ["Good practices found"]
}}
"""

REVIEW_SKILL_PROMPT = """Review this Claude Code skill/component for security vulnerabilities across all 17 categories.

**Component: {skill_name}** ({path})

Content (each line is prefixed with its line number):
{content}

IMPORTANT: Respond with ONLY valid JSON. Keep descriptions brief. Limit to top 5 issues.

The content above has line numbers prefixed (e.g. "  42 | code here"). Use the exact line number from the prefix for line_number. Quote the exact vulnerable code in code_snippet (without the line number prefix).

{{
  "summary": "Brief assessment (1-2 sentences)",
  "risk_score": 1-10,
  "issues": [
    {{
      "severity": "critical|high|medium|low",
      "category": "prompt_injection|command_injection|path_traversal|credential_exposure|privilege_escalation|data_exfiltration|supply_chain|autonomy_abuse|tool_poisoning|obfuscation|unicode_steganography|social_engineering|malicious_code|suspicious_downloads|third_party_exposure|system_modification|financial_access",
      "section": "malicious|code_security",
      "title": "Short title",
      "description": "Brief description",
      "file_path": "{path}",
      "line_number": 42,
      "code_snippet": "exact vulnerable line(s) of code from the content",
      "exploitation": "Brief scenario",
      "remediation": "Brief fix",
      "confidence": 0.0-1.0
    }}
  ],
  "recommendations": ["Top recommendations"],
  "positive_findings": ["Good practices"]
}}
"""


class AISecurityReviewer:
    """AI-powered security reviewer for plugins and skills."""
    
    def __init__(
        self,
        llm,
        verbose: bool = False,
        rate_limiter: Optional[RateLimiter] = None,
    ):
        """
        Initialize the reviewer.
        
        Args:
            llm: LangChain LLM instance
            verbose: Whether to print progress
            rate_limiter: Optional shared rate limiter for API throttling.
        """
        self.llm = llm
        self.verbose = verbose
        self.rate_limiter = rate_limiter
        self.guard = PromptGuard()
    
    def _make_injection_result(
        self,
        plugin_name: str,
        detections: list[InjectionDetection],
    ) -> AIReviewResult:
        """Build an AIReviewResult for detected prompt injection attempts."""
        issues = []
        for det in detections:
            issues.append(SecurityIssue(
                severity="high",
                category="prompt_injection",
                title=f"Prompt injection detected: {det.pattern_matched}",
                description=(
                    f"Component '{det.component_name}' contains content that attempts "
                    f"to manipulate the AI analyzer. Matched pattern: {det.pattern_matched}. "
                    f"Matched text: '{det.matched_text}'"
                ),
                component=det.component_name,
                location=None,
                exploitation=(
                    "An attacker could embed instructions in plugin content to trick "
                    "the AI security reviewer into reporting a malicious plugin as safe."
                ),
                remediation=(
                    "Remove or sanitize the manipulative content. "
                    "Plugin content should not contain instructions aimed at AI analyzers."
                ),
                confidence=0.95,
                section=get_section("prompt_injection"),
                line_number=det.line_number,
                file_path=det.file_path,
                code_snippet=det.context_snippet or det.matched_text,
            ))

        return AIReviewResult(
            plugin_name=plugin_name,
            summary=(
                f"PROMPT INJECTION DETECTED — {len(detections)} component(s) contain "
                "content designed to manipulate the AI analyzer. Analysis was blocked "
                "to prevent bypass. Manual review is required."
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

    def review_plugin(self, plugin: ParsedPlugin) -> AIReviewResult:
        """
        Perform comprehensive AI security review of a plugin.
        
        Args:
            plugin: Parsed plugin to review
        
        Returns:
            AIReviewResult with findings
        """
        if self.verbose:
            print(f"      Plugin: {plugin.manifest.name} v{plugin.manifest.version}")
            print(f"      Description: {plugin.manifest.description or 'N/A'}")
        
        # --- Prompt injection pre-scan ---
        if self.verbose:
            print(f"      Scanning for prompt injection attempts...")
        
        content_map: dict[str, str] = {}
        path_map: dict[str, str] = {}
        for comp in plugin.components:
            comp_content = comp.content or json.dumps(comp.metadata, indent=2)
            content_map[comp.name] = comp_content
            path_map[comp.name] = comp.path
        
        detections = self.guard.scan_multiple(content_map)
        if detections:
            for det in detections:
                det.file_path = path_map.get(det.component_name)
            if self.verbose:
                print(f"      [ALERT] Prompt injection detected in {len(detections)} component(s)!")
                for det in detections:
                    print(f"        - {det.component_name}: {det.pattern_matched} -> '{det.matched_text}'")
            return self._make_injection_result(plugin.manifest.name, detections)

        if self.verbose:
            print(f"      No injection attempts detected. Proceeding with analysis.")
        
        # Prepare components summary
        if self.verbose:
            print(f"      Preparing component summary...")
        components_summary = self._format_components_summary(plugin.components)
        
        # Prepare detailed content (limited to avoid token limits)
        if self.verbose:
            print(f"      Preparing detailed content for analysis...")
        detailed_content = self._format_detailed_content(plugin.components)
        
        if self.verbose:
            # Show component breakdown
            by_type = {}
            for comp in plugin.components:
                by_type.setdefault(comp.type, []).append(comp.name)
            print(f"      Components breakdown:")
            for comp_type, names in by_type.items():
                print(f"        - {comp_type}: {len(names)} ({', '.join(names[:3])}{'...' if len(names) > 3 else ''})")
        
        # Build guarded system prompt
        guarded_system_prompt = REVIEW_SYSTEM_PROMPT + self.guard.get_system_guard_prompt()
        
        # Format prompt — detailed_content is already wrapped by _format_detailed_content
        user_prompt = REVIEW_PLUGIN_PROMPT.format(
            plugin_name=plugin.manifest.name,
            version=plugin.manifest.version,
            description=plugin.manifest.description or "No description",
            components_summary=components_summary,
            detailed_content=detailed_content,
        )
        
        if self.verbose:
            prompt_size = len(user_prompt)
            print(f"      Prompt size: {prompt_size:,} characters")
            print(f"      Sending request to LLM...")
        
        # Call LLM
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
            
            if self.verbose:
                response_size = len(raw)
                print(f"      Received response: {response_size:,} characters")
                print(f"      Parsing AI response...")
                print(f"      --- RAW RESPONSE PREVIEW ---")
                preview = redact_secrets(raw[:500]) if raw else "(empty)"
                print(preview)
                print(f"      --- END PREVIEW ---")
            
            result = self._parse_response(raw)
            
            if self.verbose:
                issues_count = len(result.get("issues", []))
                print(f"      Found {issues_count} potential issues")
                
        except Exception as e:
            if self.verbose:
                print(f"      [ERROR] AI review error: {e}")
            return AIReviewResult(
                plugin_name=plugin.manifest.name,
                summary=f"AI review failed: {e}",
                risk_score=5,
                issues=[],
                recommendations=["Manual security review recommended"],
                positive_findings=[],
            )
        
        # Convert to result object
        issues = []
        for issue_data in result.get("issues", []):
            category = issue_data.get("category", "unknown")
            issues.append(SecurityIssue(
                severity=issue_data.get("severity", "medium"),
                category=category,
                title=issue_data.get("title", "Untitled"),
                description=issue_data.get("description", ""),
                component=issue_data.get("component", "unknown"),
                location=issue_data.get("location"),
                exploitation=issue_data.get("exploitation", ""),
                remediation=issue_data.get("remediation", ""),
                confidence=issue_data.get("confidence", 0.5),
                section=issue_data.get("section", get_section(category)),
                line_number=_safe_int(issue_data.get("line_number")),
                file_path=issue_data.get("file_path") or None,
                code_snippet=issue_data.get("code_snippet") or None,
            ))
        
        return AIReviewResult(
            plugin_name=plugin.manifest.name,
            summary=result.get("summary", ""),
            risk_score=result.get("risk_score", 5),
            issues=issues,
            recommendations=result.get("recommendations", []),
            positive_findings=result.get("positive_findings", []),
        )
    
    def review_skill(
        self,
        skill_name: str,
        skill_path: str,
        content: str,
    ) -> AIReviewResult:
        """
        Perform focused AI security review of a single skill.
        
        Args:
            skill_name: Name of the skill
            skill_path: Path to the skill
            content: Skill content (markdown)
        
        Returns:
            AIReviewResult with findings
        """
        if self.verbose:
            print(f"  AI reviewing skill: {skill_name}")
        
        # --- Prompt injection pre-scan ---
        detection = self.guard.scan_content(content, component_name=skill_name)
        if detection:
            detection.file_path = skill_path
            if self.verbose:
                print(f"  [ALERT] Prompt injection in skill '{skill_name}': {detection.pattern_matched}")
            return self._make_injection_result(skill_name, [detection])
        
        # Add line numbers and wrap untrusted content
        numbered_content = _add_line_numbers(content[:8000])
        wrapped_content = self.guard.wrap_untrusted(numbered_content)
        guarded_system_prompt = REVIEW_SYSTEM_PROMPT + self.guard.get_system_guard_prompt()
        
        # Format prompt
        user_prompt = REVIEW_SKILL_PROMPT.format(
            skill_name=skill_name,
            path=skill_path,
            content=wrapped_content,
        )
        
        # Call LLM
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
                print(f"  AI review error: {e}")
            return AIReviewResult(
                plugin_name=skill_name,
                summary=f"AI review failed: {e}",
                risk_score=5,
                issues=[],
                recommendations=["Manual security review recommended"],
                positive_findings=[],
            )
        
        # Convert to result object
        issues = []
        for issue_data in result.get("issues", []):
            category = issue_data.get("category", "unknown")
            issues.append(SecurityIssue(
                severity=issue_data.get("severity", "medium"),
                category=category,
                title=issue_data.get("title", "Untitled"),
                description=issue_data.get("description", ""),
                component=skill_name,
                location=issue_data.get("location"),
                exploitation=issue_data.get("exploitation", ""),
                remediation=issue_data.get("remediation", ""),
                confidence=issue_data.get("confidence", 0.5),
                section=issue_data.get("section", get_section(category)),
                line_number=_safe_int(issue_data.get("line_number")),
                file_path=issue_data.get("file_path") or skill_path,
                code_snippet=issue_data.get("code_snippet") or None,
            ))
        
        return AIReviewResult(
            plugin_name=skill_name,
            summary=result.get("summary", ""),
            risk_score=result.get("risk_score", 5),
            issues=issues,
            recommendations=result.get("recommendations", []),
            positive_findings=result.get("positive_findings", []),
        )
    
    def review_component(self, component: PluginComponent) -> AIReviewResult:
        """
        Review a single plugin component using type-specific prompts.

        Enforces all 3 PromptGuard layers:
          1. Pre-scan content for injection patterns -> block if detected
          2. Wrap clean content in random delimiters
          3. Append system guard instructions to the system prompt

        Args:
            component: Plugin component to review

        Returns:
            AIReviewResult with findings
        """
        comp_name = component.name
        comp_type = component.type
        content = component.content or json.dumps(component.metadata, indent=2)

        if self.verbose:
            print(f"  AI reviewing {comp_type}: {comp_name}")

        # --- LAYER 1: Pre-scan for injection ---
        detection = self.guard.scan_content(content, component_name=comp_name)
        if detection:
            detection.file_path = component.path
            if self.verbose:
                print(f"  [ALERT] Prompt injection in '{comp_name}': {detection.pattern_matched}")
            return self._make_injection_result(comp_name, [detection])

        # Truncate large content
        max_content = 8000
        if len(content) > max_content:
            content = content[:max_content] + "\n...(truncated)"

        # Add line numbers so the LLM can reference exact lines
        numbered_content = _add_line_numbers(content)

        # --- LAYER 2: Wrap untrusted content in random delimiters ---
        wrapped_content = self.guard.wrap_untrusted(numbered_content)

        # --- LAYER 3: Build prompts with system guard addendum ---
        system_prompt = get_system_prompt(comp_type) + self.guard.get_system_guard_prompt()
        user_prompt = get_user_prompt(
            component_type=comp_type,
            component_name=comp_name,
            component_path=component.path or "",
            wrapped_content=wrapped_content,
        )

        # Call LLM
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
            result = self._parse_response(raw)
        except Exception as e:
            if self.verbose:
                print(f"  AI review error for {comp_type}/{comp_name}: {e}")
            return AIReviewResult(
                plugin_name=comp_name,
                summary=f"AI review failed: {e}",
                risk_score=5,
                issues=[],
                recommendations=["Manual security review recommended"],
                positive_findings=[],
            )

        # Convert to result object
        issues = []
        for issue_data in result.get("issues", []):
            category = issue_data.get("category", "unknown")
            issues.append(SecurityIssue(
                severity=issue_data.get("severity", "medium"),
                category=category,
                title=issue_data.get("title", "Untitled"),
                description=issue_data.get("description", ""),
                component=comp_name,
                location=issue_data.get("location"),
                exploitation=issue_data.get("exploitation", ""),
                remediation=issue_data.get("remediation", ""),
                confidence=issue_data.get("confidence", 0.5),
                section=issue_data.get("section", get_section(category)),
                line_number=_safe_int(issue_data.get("line_number")),
                file_path=issue_data.get("file_path") or component.path,
                code_snippet=issue_data.get("code_snippet") or None,
            ))

        return AIReviewResult(
            plugin_name=comp_name,
            summary=result.get("summary", ""),
            risk_score=result.get("risk_score", 5),
            issues=issues,
            recommendations=result.get("recommendations", []),
            positive_findings=result.get("positive_findings", []),
        )
    
    def _format_components_summary(self, components: list[PluginComponent]) -> str:
        """Format a summary of plugin components."""
        lines = []
        by_type = {}
        for comp in components:
            by_type.setdefault(comp.type, []).append(comp)
        
        for comp_type, comps in by_type.items():
            lines.append(f"\n**{comp_type.upper()}S ({len(comps)}):**")
            for comp in comps:
                lines.append(f"  - {comp.name} ({comp.path})")
        
        return "\n".join(lines)
    
    def _format_detailed_content(
        self,
        components: list[PluginComponent],
        max_per_component: int = 1500,
        max_total: int = 12000,
    ) -> str:
        """Format detailed content of components with size limits.
        
        Each component's content is wrapped in random delimiters
        to protect against prompt injection from malicious plugins.
        """
        sections = []
        total_size = 0
        
        # Prioritize by security relevance
        priority_types = ["skill", "hook", "mcp", "agent", "command", "script", "lsp", "resource"]
        
        for comp_type in priority_types:
            for comp in components:
                if comp.type != comp_type:
                    continue
                
                # Check if we're approaching limit
                if total_size >= max_total:
                    break
                
                content = comp.content or json.dumps(comp.metadata, indent=2)
                if len(content) > max_per_component:
                    content = content[:max_per_component] + "\n...(truncated)"
                
                numbered_content = _add_line_numbers(content)
                
                # Wrap each component's content in delimiters
                wrapped = self.guard.wrap_untrusted(numbered_content)
                
                file_label = f" ({comp.path})" if comp.path else ""
                section = f"[{comp.type.upper()}] {comp.name}{file_label}\n{wrapped}\n"
                sections.append(section)
                total_size += len(section)
        
        result = "\n".join(sections)
        if len(result) > max_total:
            result = result[:max_total] + "\n...(truncated)"
        
        return result
    
    def _parse_response(self, content: str) -> dict:
        """Parse LLM response JSON with robust error handling."""
        import re
        
        if not content:
            return self._default_error_response("Empty response from LLM")
        
        original_content = content
        content = content.strip()
        
        # Handle markdown code blocks (```json or ```)
        if "```" in content:
            # Extract content between code fences
            code_block_match = re.search(r'```(?:json)?\s*([\s\S]*?)```', content)
            if code_block_match:
                content = code_block_match.group(1).strip()
        
        # Try direct parse first
        try:
            return json.loads(content)
        except json.JSONDecodeError as e:
            if self.verbose:
                print(f"      Direct parse failed: {e}")
        
        # Try to extract JSON object from mixed content
        json_match = re.search(r'\{[\s\S]*\}', content)
        if json_match:
            json_str = json_match.group()
            
            # Try parsing the extracted JSON
            try:
                return json.loads(json_str)
            except json.JSONDecodeError as e:
                if self.verbose:
                    print(f"      Extracted JSON parse failed: {e}")
            
            # Fix common JSON issues from LLMs
            fixed_json = self._fix_json_issues(json_str)
            try:
                return json.loads(fixed_json)
            except json.JSONDecodeError as e:
                if self.verbose:
                    print(f"      Fixed JSON parse failed: {e}")
                    print(f"      Fixed JSON preview: {fixed_json[:500]}...")
        
        # Try to build response from text analysis as last resort
        return self._extract_from_text(original_content)
    
    def _default_error_response(self, error_msg: str) -> dict:
        """Return default error response structure."""
        return {
            "summary": f"AI review failed: {error_msg}",
            "risk_score": 5,
            "issues": [],
            "recommendations": ["Manual security review recommended"],
            "positive_findings": []
        }
    
    def _extract_from_text(self, content: str) -> dict:
        """Try to extract useful info from non-JSON response."""
        import re
        
        # Try to find risk score mentions
        risk_match = re.search(r'risk\s*(?:score)?[:\s]*(\d+)', content, re.IGNORECASE)
        risk_score = int(risk_match.group(1)) if risk_match else 5
        
        # Try to find severity mentions for issues
        issues = []
        severity_patterns = [
            (r'critical[:\s]+([^\n]+)', 'critical'),
            (r'high[:\s]+([^\n]+)', 'high'),
            (r'medium[:\s]+([^\n]+)', 'medium'),
        ]
        
        for pattern, severity in severity_patterns:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                issues.append({
                    "severity": severity,
                    "category": "ai_extracted",
                    "title": match.group(1)[:100].strip(),
                    "description": match.group(1).strip(),
                    "component": "unknown",
                    "location": None,
                    "line_number": None,
                    "file_path": None,
                    "code_snippet": None,
                    "exploitation": "",
                    "remediation": "",
                    "confidence": 0.3
                })
        
        # Extract summary from first paragraph
        paragraphs = content.split('\n\n')
        summary = paragraphs[0][:500] if paragraphs else "Could not parse AI response"
        
        if self.verbose:
            print(f"      Falling back to text extraction, found {len(issues)} potential issues")
        
        return {
            "summary": summary,
            "risk_score": risk_score,
            "issues": issues[:10],  # Limit to 10
            "recommendations": ["Review AI output manually - JSON parsing failed"],
            "positive_findings": []
        }
    
    def _fix_json_issues(self, json_str: str) -> str:
        """Attempt to fix common JSON formatting issues from LLMs."""
        import re
        
        # Remove trailing commas before ] or }
        json_str = re.sub(r',(\s*[\]}])', r'\1', json_str)
        
        # Remove JavaScript-style comments
        json_str = re.sub(r'//[^\n]*\n', '\n', json_str)
        json_str = re.sub(r'/\*[\s\S]*?\*/', '', json_str)
        
        # Fix unquoted keys (common LLM mistake)
        json_str = re.sub(r'(\{|\,)\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*:', r'\1"\2":', json_str)
        
        # Fix single quotes to double quotes (but be careful with apostrophes)
        # Only replace single quotes that look like string delimiters
        json_str = re.sub(r":\s*'([^']*)'", r': "\1"', json_str)
        
        # Remove any control characters that might have slipped in
        json_str = re.sub(r'[\x00-\x1f\x7f-\x9f]', '', json_str)
        
        return json_str
    
    def generate_review_report(self, result: AIReviewResult) -> str:
        """Generate a human-readable security review report."""
        import re
        
        # Clean summary of any markdown artifacts
        summary = result.summary
        summary = re.sub(r'^```(?:json)?\s*', '', summary)
        summary = re.sub(r'```\s*$', '', summary)
        summary = summary.strip()
        
        # Truncate if too long
        if len(summary) > 500:
            summary = summary[:500] + "..."
        
        lines = [
            "=" * 60,
            "AI SECURITY REVIEW REPORT",
            "=" * 60,
            "",
            f"Plugin: {result.plugin_name}",
            f"Risk Score: {result.risk_score}/10",
            "",
            "EXECUTIVE SUMMARY",
            "-" * 40,
            summary,
            "",
        ]
        
        # Issues by severity
        if result.issues:
            lines.extend([
                "SECURITY ISSUES FOUND",
                "-" * 40,
                "",
            ])
            
            for severity in ["critical", "high", "medium", "low", "info"]:
                sev_issues = [i for i in result.issues if i.severity == severity]
                if not sev_issues:
                    continue
                
                lines.append(f"[{severity.upper()}] ({len(sev_issues)} issues)")
                for issue in sev_issues:
                    lines.extend([
                        f"",
                        f"  • {issue.title}",
                        f"    Category: {issue.category}",
                        f"    Component: {issue.component}",
                    ])
                    if issue.file_path:
                        lines.append(f"    File: {issue.file_path}")
                    if issue.line_number:
                        lines.append(f"    Line: {issue.line_number}")
                    lines.extend([
                        f"    Confidence: {issue.confidence:.0%}",
                        f"    Description: {issue.description[:200]}",
                    ])
                    if issue.code_snippet:
                        lines.append(f"    Code: {issue.code_snippet[:200]}")
                    lines.extend([
                        f"    Exploitation: {issue.exploitation[:150]}",
                        f"    Remediation: {issue.remediation[:150]}",
                    ])
                lines.append("")
        else:
            lines.extend([
                "No security issues found.",
                "",
            ])
        
        # Recommendations
        if result.recommendations:
            lines.extend([
                "RECOMMENDATIONS",
                "-" * 40,
            ])
            for rec in result.recommendations:
                lines.append(f"  • {rec}")
            lines.append("")
        
        # Positive findings
        if result.positive_findings:
            lines.extend([
                "POSITIVE FINDINGS",
                "-" * 40,
            ])
            for pos in result.positive_findings:
                lines.append(f"  ✓ {pos}")
            lines.append("")
        
        return "\n".join(lines)

