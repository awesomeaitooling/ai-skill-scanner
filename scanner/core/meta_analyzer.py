"""
Meta-Analyzer — Post-processing layer for findings.

Performs:
1. False-positive filtering (common benign patterns)
2. Deduplication of findings across analyzers
3. Severity adjustment based on context
4. Prioritization scoring
5. Correlation of related findings into attack chains
"""

import re
from typing import List, Dict, Set, Tuple, Optional
from dataclasses import dataclass, field

from .skill_analyzer import SecurityFinding


@dataclass
class CorrelatedChain:
    """A group of correlated findings that form an attack chain."""
    chain_id: str
    title: str
    description: str
    combined_severity: str
    findings: List[SecurityFinding]
    chain_type: str  # "data_exfil", "privilege_escalation", "command_injection_chain"


# Patterns commonly seen in comments, documentation, or test code
FALSE_POSITIVE_INDICATORS = [
    # Code comments explaining security
    (r"^#.*(?:example|TODO|FIXME|NOTE|WARNING|SECURITY)", "comment_pattern"),
    # Markdown documentation
    (r"^>\s*(?:Note|Warning|Caution|Tip):", "documentation_note"),
    # Test/example strings
    (r"(?:test|example|sample|demo|placeholder|dummy)", "test_code"),
    # Log/debug statements
    (r"(?:log|debug|print|console\.log)\s*\(.*(?:error|warn|info)", "logging"),
]

# Common false positive rule IDs and their benign contexts
RULE_FP_CONTEXTS = {
    "external-url": {
        # URLs in documentation or comments are usually benign
        "benign_patterns": [
            r"#\s*(?:Reference|See|Docs|Link):",
            r"<!--.*-->",
            r"\[.*\]\(http",  # Markdown links
        ]
    },
    "privilege-escalation": {
        # Documented warnings about sudo are not actual escalation
        "benign_patterns": [
            r"(?:do\s+not|don't|never|avoid)\s+(?:use\s+)?sudo",
            r"instead\s+of\s+sudo",
        ]
    },
}


class MetaAnalyzer:
    """Post-processes findings from all analyzers."""

    def __init__(self, verbose: bool = False):
        self.verbose = verbose

    def process(self, findings: List[SecurityFinding]) -> List[SecurityFinding]:
        """Process findings through all meta-analysis stages.
        
        Returns a filtered, deduplicated, and prioritized list.
        """
        if self.verbose:
            print(f"    Meta-analyzer: processing {len(findings)} raw findings")

        # Stage 1: Deduplicate
        findings = self._deduplicate(findings)
        if self.verbose:
            print(f"    After deduplication: {len(findings)}")

        # Stage 2: Filter false positives
        findings = self._filter_false_positives(findings)
        if self.verbose:
            print(f"    After FP filtering: {len(findings)}")

        # Stage 3: Adjust severities based on context
        findings = self._adjust_severities(findings)

        # Stage 4: Prioritize
        findings = self._prioritize(findings)

        if self.verbose:
            print(f"    Final findings: {len(findings)}")

        return findings

    def correlate(self, findings: List[SecurityFinding]) -> List[CorrelatedChain]:
        """Identify correlated findings that form attack chains."""
        chains: List[CorrelatedChain] = []

        # Group findings by component
        by_component: Dict[str, List[SecurityFinding]] = {}
        for f in findings:
            key = f"{f.component_type}:{f.component_name}"
            by_component.setdefault(key, []).append(f)

        # Check for data exfiltration chains
        chain = self._check_exfil_chain(findings)
        if chain:
            chains.append(chain)

        # Check for privilege escalation chains
        chain = self._check_priv_esc_chain(findings)
        if chain:
            chains.append(chain)

        # Check for injection-to-execution chains
        chain = self._check_injection_chain(findings)
        if chain:
            chains.append(chain)

        return chains

    # ----------------------------------------------------------------
    # Stage 1: Deduplication
    # ----------------------------------------------------------------
    def _deduplicate(self, findings: List[SecurityFinding]) -> List[SecurityFinding]:
        """Remove duplicate findings (same rule, same component, same line)."""
        seen: Set[str] = set()
        unique: List[SecurityFinding] = []

        for f in findings:
            key = f"{f.rule_id}|{f.component_name}|{f.line or 'none'}"
            if key not in seen:
                seen.add(key)
                unique.append(f)

        return unique

    # ----------------------------------------------------------------
    # Stage 2: False-positive filtering
    # ----------------------------------------------------------------
    def _filter_false_positives(
        self, findings: List[SecurityFinding]
    ) -> List[SecurityFinding]:
        """Filter out likely false positives based on context."""
        filtered: List[SecurityFinding] = []

        for f in findings:
            if self._is_likely_false_positive(f):
                if self.verbose:
                    print(f"    [FP] Filtered: {f.rule_id} in {f.component_name}")
                continue
            filtered.append(f)

        return filtered

    def _is_likely_false_positive(self, finding: SecurityFinding) -> bool:
        """Check if a finding is likely a false positive."""
        snippet = finding.snippet or ""
        message = finding.message or ""

        # Check snippet against known FP indicators
        for pattern, fp_type in FALSE_POSITIVE_INDICATORS:
            if re.search(pattern, snippet, re.IGNORECASE | re.MULTILINE):
                # Only filter low/medium findings in known benign contexts
                if finding.severity in ("low", "medium"):
                    return True

        # Check rule-specific FP contexts
        rule_fp = RULE_FP_CONTEXTS.get(finding.rule_id)
        if rule_fp:
            for pattern in rule_fp.get("benign_patterns", []):
                if re.search(pattern, snippet, re.IGNORECASE):
                    return True

        # Markdown/docs patterns: low severity findings in markdown are often FPs
        if finding.component_type in ("skill", "agent", "command"):
            if finding.severity == "low" and finding.rule_id.startswith("frontmatter-"):
                # Frontmatter findings below medium are informational
                pass  # Keep them

        return False

    # ----------------------------------------------------------------
    # Stage 3: Severity adjustment
    # ----------------------------------------------------------------
    def _adjust_severities(
        self, findings: List[SecurityFinding]
    ) -> List[SecurityFinding]:
        """Adjust severities based on cross-finding context."""
        # Build context
        has_network = any(
            "network" in (f.rule_id or "") or "exfil" in (f.rule_id or "")
            for f in findings
        )
        has_exec = any(
            "exec" in (f.rule_id or "") or "eval" in (f.rule_id or "") or "subprocess" in (f.rule_id or "")
            for f in findings
        )
        has_file_io = any(
            "file" in (f.rule_id or "") or "path" in (f.rule_id or "")
            for f in findings
        )

        adjusted = []
        for f in findings:
            new_f = f  # Immutable dataclass would need replacement; we'll modify in-place

            # Escalate: file read + network = data exfil risk
            if has_network and has_file_io:
                if "file" in (f.rule_id or "") and f.severity == "medium":
                    new_f = SecurityFinding(
                        severity="high",
                        rule_id=f.rule_id,
                        rule_name=f.rule_name,
                        message=f.message + " [severity escalated: network+file I/O combination]",
                        component_type=f.component_type,
                        component_name=f.component_name,
                        component_path=f.component_path,
                        line=f.line,
                        column=f.column,
                        snippet=f.snippet,
                        recommendation=f.recommendation,
                        references=f.references,
                    )

            # Escalate: exec + no try/except = unhandled dangerous code
            if has_exec:
                if "exec" in (f.rule_id or "") or "eval" in (f.rule_id or ""):
                    if f.severity == "high":
                        # Already high, but escalate to critical if also has network
                        if has_network:
                            new_f = SecurityFinding(
                                severity="critical",
                                rule_id=f.rule_id,
                                rule_name=f.rule_name,
                                message=f.message + " [severity escalated: exec+network combination]",
                                component_type=f.component_type,
                                component_name=f.component_name,
                                component_path=f.component_path,
                                line=f.line,
                                column=f.column,
                                snippet=f.snippet,
                                recommendation=f.recommendation,
                                references=f.references,
                            )

            adjusted.append(new_f)

        return adjusted

    # ----------------------------------------------------------------
    # Stage 4: Prioritization
    # ----------------------------------------------------------------
    def _prioritize(self, findings: List[SecurityFinding]) -> List[SecurityFinding]:
        """Sort findings by priority (severity, then confidence-related heuristics)."""
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}

        def priority_key(f: SecurityFinding) -> Tuple:
            sev = severity_order.get(f.severity, 4)
            # Prefer findings with specific lines over vague ones
            has_line = 0 if f.line else 1
            # Prefer findings with snippets
            has_snippet = 0 if f.snippet else 1
            # Prefer findings in code (script) over documentation (skill)
            comp_priority = {"script": 0, "hook": 1, "mcp": 2, "lsp": 3, "command": 4, "agent": 5, "skill": 6, "resource": 7}
            comp_p = comp_priority.get(f.component_type, 8)
            return (sev, comp_p, has_line, has_snippet)

        return sorted(findings, key=priority_key)

    # ----------------------------------------------------------------
    # Correlation: Attack chain detection
    # ----------------------------------------------------------------
    def _check_exfil_chain(self, findings: List[SecurityFinding]) -> Optional[CorrelatedChain]:
        """Check for data exfiltration chain: file read + network send."""
        file_findings = [f for f in findings if any(
            k in (f.rule_id or "") for k in ["file", "path", "sensitive"]
        )]
        network_findings = [f for f in findings if any(
            k in (f.rule_id or "") for k in ["exfil", "network", "http", "socket", "curl"]
        )]

        if file_findings and network_findings:
            chain_findings = file_findings[:3] + network_findings[:3]
            return CorrelatedChain(
                chain_id="chain-data-exfil",
                title="Potential Data Exfiltration Chain",
                description=(
                    f"Found {len(file_findings)} file access finding(s) combined with "
                    f"{len(network_findings)} network finding(s), indicating a potential "
                    "data exfiltration path."
                ),
                combined_severity="critical",
                findings=chain_findings,
                chain_type="data_exfil",
            )
        return None

    def _check_priv_esc_chain(self, findings: List[SecurityFinding]) -> Optional[CorrelatedChain]:
        """Check for privilege escalation chain."""
        priv_findings = [f for f in findings if any(
            k in (f.rule_id or "") for k in ["privilege", "sudo", "root", "admin"]
        )]
        exec_findings = [f for f in findings if any(
            k in (f.rule_id or "") for k in ["exec", "eval", "subprocess", "system"]
        )]

        if priv_findings and exec_findings:
            chain_findings = priv_findings[:2] + exec_findings[:2]
            return CorrelatedChain(
                chain_id="chain-priv-esc",
                title="Potential Privilege Escalation Chain",
                description=(
                    f"Found {len(priv_findings)} privilege-related finding(s) combined with "
                    f"{len(exec_findings)} code execution finding(s)."
                ),
                combined_severity="critical",
                findings=chain_findings,
                chain_type="privilege_escalation",
            )
        return None

    def _check_injection_chain(self, findings: List[SecurityFinding]) -> Optional[CorrelatedChain]:
        """Check for injection-to-execution chain."""
        injection_findings = [f for f in findings if any(
            k in (f.rule_id or "") for k in ["injection", "taint", "dataflow"]
        )]
        exec_findings = [f for f in findings if any(
            k in (f.rule_id or "") for k in ["exec", "eval", "subprocess", "command"]
        )]

        if injection_findings and exec_findings:
            chain_findings = injection_findings[:3] + exec_findings[:3]
            return CorrelatedChain(
                chain_id="chain-injection-exec",
                title="Injection to Execution Chain",
                description=(
                    f"Found {len(injection_findings)} injection finding(s) that may feed into "
                    f"{len(exec_findings)} execution sink(s)."
                ),
                combined_severity="critical",
                findings=chain_findings,
                chain_type="command_injection_chain",
            )
        return None
