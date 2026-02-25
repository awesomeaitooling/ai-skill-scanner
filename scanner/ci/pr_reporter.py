"""
PR-specific reporting: markdown comment, SARIF, and JSON output.

Generates reports from PRScanResult data produced by the DiffScanner,
highlighting new and worsened vulnerabilities introduced by a PR.
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from scanner.ci.diff_scanner import (
    ImpactFinding,
    PRScanResult,
    TargetImpactResult,
)
from scanner.reporters.json_reporter import _validate_output_path
from scanner.utils.redaction import redact_secrets


# ── Markdown PR comment ──────────────────────────────────────────────

_SEVERITY_EMOJI = {
    "critical": "🔴",
    "high": "🟠",
    "medium": "🟡",
    "low": "🔵",
}

_RISK_BADGE = {
    "increased": "⚠️ **Risk Increased**",
    "decreased": "✅ **Risk Decreased**",
    "unchanged": "➖ **Risk Unchanged**",
}

_VERDICT_BADGE = {
    "pass": "✅ **PASS** — No new malicious findings",
    "fail": "❌ **FAIL** — New or worsened malicious findings detected",
}


def generate_pr_comment(pr_result: PRScanResult) -> str:
    """Generate a markdown-formatted PR comment from scan results."""
    s = pr_result.summary
    lines: list[str] = []

    # Header
    lines.append("## 🔍 AI Skill Security Scan")
    lines.append("")
    lines.append(_VERDICT_BADGE.get(s.verdict, s.verdict))
    lines.append(f" | {_RISK_BADGE.get(s.overall_risk_delta, s.overall_risk_delta)}")
    lines.append("")

    # Summary table
    lines.append("| Metric | Count |")
    lines.append("|--------|-------|")
    lines.append(f"| Targets scanned | {s.total_targets_affected} |")
    lines.append(f"| **New vulnerabilities** | **{s.new_count}** |")
    lines.append(f"| **Worsened vulnerabilities** | **{s.worsened_count}** |")
    lines.append(f"| Resolved (fixed) | {s.resolved_count} |")
    lines.append(f"| Unchanged (pre-existing) | {s.unchanged_count} |")
    lines.append("")

    # Per-target details
    for tr in pr_result.target_results:
        lines.append(f"### {tr.target.target_type.title()}: `{tr.target.name}`")
        lines.append("")
        lines.append(f"**Scenario:** {tr.target.change_scenario.replace('_', ' ')}")
        delta = _RISK_BADGE.get(tr.risk_delta, tr.risk_delta)
        lines.append(f" | {delta}")
        lines.append("")

        if tr.impact_summary:
            lines.append(f"> {tr.impact_summary}")
            lines.append("")

        # New findings
        if tr.new_findings:
            lines.append(f"#### 🆕 New Vulnerabilities ({len(tr.new_findings)})")
            lines.append("")
            for nf in tr.new_findings:
                _render_finding(lines, nf)

        # Worsened findings
        if tr.worsened_findings:
            lines.append(f"#### ⬆️ Worsened Vulnerabilities ({len(tr.worsened_findings)})")
            lines.append("")
            for wf in tr.worsened_findings:
                _render_finding(lines, wf)

        # Resolved (collapsible)
        if tr.resolved_findings:
            lines.append(f"<details><summary>✅ Resolved ({len(tr.resolved_findings)})</summary>")
            lines.append("")
            for rf in tr.resolved_findings:
                _render_finding(lines, rf)
            lines.append("</details>")
            lines.append("")

        # Unchanged (collapsible)
        if tr.unchanged_findings:
            lines.append(f"<details><summary>➖ Unchanged ({len(tr.unchanged_findings)})</summary>")
            lines.append("")
            for uf in tr.unchanged_findings:
                _render_finding(lines, uf)
            lines.append("</details>")
            lines.append("")

        # Reasoning
        if tr.target.reasoning:
            lines.append(f"<details><summary>🤖 LLM reasoning</summary>")
            lines.append("")
            lines.append(f"{tr.target.reasoning}")
            lines.append("")
            lines.append("</details>")
            lines.append("")

        lines.append("---")
        lines.append("")

    lines.append(f"*Scan completed at {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC*")
    return "\n".join(lines)


def _render_finding(lines: list[str], impact_finding: ImpactFinding) -> None:
    f = impact_finding.finding
    emoji = _SEVERITY_EMOJI.get(impact_finding.severity, "⚪")
    lines.append(f"- {emoji} **[{impact_finding.severity.upper()}]** {f.rule_name}")

    if f.component_name:
        lines.append(f"  - Component: `{f.component_type}/{f.component_name}`")
    if f.component_path:
        lines.append(f"  - File: `{f.component_path}`")
    if f.line:
        lines.append(f"  - Line: {f.line}")

    msg = redact_secrets(f.message)
    if msg:
        lines.append(f"  - {msg[:300]}")

    if impact_finding.description:
        lines.append(f"  - *Impact:* {impact_finding.description[:300]}")

    if f.snippet:
        snippet = redact_secrets(f.snippet)[:200]
        lines.append(f"  - ```{snippet}```")

    if f.recommendation:
        lines.append(f"  - **Fix:** {f.recommendation[:200]}")

    lines.append("")


# ── SARIF output ─────────────────────────────────────────────────────

_SEVERITY_TO_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
}


def generate_pr_sarif(pr_result: PRScanResult) -> dict[str, Any]:
    """Generate SARIF including only new and worsened findings."""
    actionable: list[ImpactFinding] = []
    for tr in pr_result.target_results:
        actionable.extend(tr.new_findings)
        actionable.extend(tr.worsened_findings)

    rules: list[dict] = []
    results: list[dict] = []
    rule_ids_seen: set[str] = set()

    for impact_f in actionable:
        f = impact_f.finding
        rule_id = f.rule_id

        if rule_id not in rule_ids_seen:
            rule_ids_seen.add(rule_id)
            rules.append({
                "id": rule_id,
                "name": f.rule_name,
                "shortDescription": {"text": f.rule_name},
                "fullDescription": {"text": f.message[:500]},
                "defaultConfiguration": {
                    "level": _SEVERITY_TO_LEVEL.get(impact_f.severity, "warning"),
                },
                "properties": {
                    "section": f.section,
                    "category": f.category or "",
                    "impact_status": impact_f.status,
                },
            })

        location: dict[str, Any] = {}
        if f.component_path:
            artifact = {"uri": f.component_path}
            region = {}
            if f.line:
                region["startLine"] = f.line
            location = {
                "physicalLocation": {
                    "artifactLocation": artifact,
                    **({"region": region} if region else {}),
                }
            }

        result_entry: dict[str, Any] = {
            "ruleId": rule_id,
            "level": _SEVERITY_TO_LEVEL.get(impact_f.severity, "warning"),
            "message": {"text": redact_secrets(f.message)[:1000]},
            "properties": {
                "impact_status": impact_f.status,
                "impact_description": impact_f.description[:500],
                "severity": impact_f.severity,
                "section": f.section,
                "category": f.category or "",
            },
        }
        if location:
            result_entry["locations"] = [location]

        results.append(result_entry)

    sarif: dict[str, Any] = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "AI Skill Security Scanner (CI)",
                        "version": "1.0.0",
                        "informationUri": "https://github.com/skills-scanner/skills-scanner",
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }
    return sarif


# ── Text findings report (artifact) ───────────────────────────────────

_SCENARIO_LABELS = {
    "new_target": "New skill/plugin introduced",
    "modified": "Existing skill/plugin modified",
    "file_added": "File(s) added to existing skill/plugin",
    "file_removed": "File(s) removed from existing skill/plugin",
    "deleted_target": "Skill/plugin removed",
}
_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
_SECTION_ORDER = {"malicious": 0, "code_security": 1}


def generate_pr_findings_txt(pr_result: PRScanResult) -> str:
    """Generate a text report with header (repo, PR, scan summary) and findings list ordered by severity."""
    s = pr_result.summary
    lines: list[str] = []

    # ── Header: repository and PR details ──
    lines.append("=" * 72)
    lines.append("AI Skill Security Scan — PR Scan Results")
    lines.append("=" * 72)
    lines.append("")
    repo = getattr(s, "repository", "") or ""
    pr_num = getattr(s, "pr_number", None)
    base_ref = getattr(s, "base_ref", "") or ""
    head_ref = getattr(s, "head_ref", "") or ""
    if repo or pr_num is not None or base_ref or head_ref:
        lines.append("Repository / PR details")
        lines.append("-" * 72)
        if repo:
            lines.append(f"  Repository:  {repo}")
        if pr_num is not None:
            lines.append(f"  PR number:   {pr_num}")
        if base_ref:
            lines.append(f"  Base ref:    {base_ref}")
        if head_ref:
            lines.append(f"  Head ref:    {head_ref}")
        lines.append("")
    # ── High-level scan summary ──
    lines.append("Scan summary")
    lines.append("-" * 72)
    lines.append(f"  Verdict:              {s.verdict.upper()}")
    lines.append(f"  Targets scanned:      {s.total_targets_affected}")
    lines.append(f"  New:                  {s.new_count}")
    lines.append(f"  Worsened:             {s.worsened_count}")
    lines.append(f"  Resolved:             {s.resolved_count}")
    lines.append(f"  Unchanged:            {s.unchanged_count}")
    lines.append(f"  Overall risk delta:   {s.overall_risk_delta}")
    cost = getattr(s, "cost_estimate_usd", None)
    total_in = getattr(s, "total_input_tokens", 0) or 0
    total_out = getattr(s, "total_output_tokens", 0) or 0
    if cost is not None or total_in or total_out:
        if total_in or total_out:
            lines.append(f"  Token usage:          {total_in} input / {total_out} output")
        if cost is not None:
            lines.append(f"  Estimated cost:       ${cost:.4f} USD")
    lines.append(f"  Generated:            {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC")
    lines.append("")
    lines.append("=" * 72)
    lines.append("Findings (new + worsened) — by severity (Critical → Low), Malicious first")
    lines.append("=" * 72)
    lines.append("")

    # ── Findings list (sorted) ──
    paired: list[tuple[ImpactFinding, TargetImpactResult]] = []
    for tr in pr_result.target_results:
        for imp in tr.new_findings:
            paired.append((imp, tr))
        for imp in tr.worsened_findings:
            paired.append((imp, tr))

    def sort_key(item: tuple[ImpactFinding, TargetImpactResult]) -> tuple[int, int]:
        imp, _ = item
        sev = imp.severity or imp.finding.severity
        sec = imp.finding.section or "code_security"
        return (_SEVERITY_ORDER.get(sev, 4), _SECTION_ORDER.get(sec, 1))

    paired.sort(key=sort_key)

    for imp, tr in paired:
        t = tr.target
        f = imp.finding
        sev = imp.severity or f.severity
        sec_label = "Malicious" if f.section == "malicious" else "Code security"
        scenario = _SCENARIO_LABELS.get(t.change_scenario, t.change_scenario)
        target_name = f"{t.target_type}: {t.name}"

        lines.append("-" * 72)
        lines.append(f"[{sev.upper()}] {sec_label} — {f.rule_name}")
        lines.append(f"  Target: {target_name}  |  Scenario: {scenario}  |  Impact: {imp.status}")
        lines.append(f"  Component: {f.component_type}/{f.component_name or '-'}")
        if f.component_path:
            lines.append(f"  File: {f.component_path}" + (f" (line {f.line})" if f.line else ""))
        msg = redact_secrets(f.message)
        if msg:
            lines.append(f"  Message: {msg[:500]}")
        if imp.description:
            lines.append(f"  Impact: {imp.description[:300]}")
        if f.recommendation:
            lines.append(f"  Fix: {f.recommendation[:300]}")
        if f.snippet:
            lines.append(f"  Snippet: {redact_secrets(f.snippet)[:200]}")
        lines.append("")

    lines.append("=" * 72)
    lines.append(f"Total actionable findings: {len(paired)}")
    lines.append(f"Generated at {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC")
    return "\n".join(lines)


def write_pr_findings_txt(pr_result: PRScanResult, output_path: str) -> None:
    """Write the full findings text report (with header and repo/PR details) to a file."""
    content = generate_pr_findings_txt(pr_result)
    validated = _validate_output_path(output_path)
    validated.write_text(content, encoding="utf-8")


# ── JSON output ──────────────────────────────────────────────────────


def generate_pr_json(pr_result: PRScanResult) -> dict[str, Any]:
    """Generate full JSON report with impact partitioning."""
    s = pr_result.summary

    target_reports = []
    for tr in pr_result.target_results:
        target_reports.append({
            "target": {
                "path": tr.target.path,
                "type": tr.target.target_type,
                "name": tr.target.name,
                "change_scenario": tr.target.change_scenario,
                "reasoning": tr.target.reasoning,
                "changed_files": [
                    {"path": cf.path, "status": cf.status}
                    for cf in tr.target.changed_files
                ],
            },
            "impact_summary": tr.impact_summary,
            "risk_delta": tr.risk_delta,
            "head_verdict": tr.head_verdict,
            "base_verdict": tr.base_verdict,
            "new_findings": [_impact_finding_to_dict(f) for f in tr.new_findings],
            "worsened_findings": [_impact_finding_to_dict(f) for f in tr.worsened_findings],
            "resolved_findings": [_impact_finding_to_dict(f) for f in tr.resolved_findings],
            "unchanged_findings": [_impact_finding_to_dict(f) for f in tr.unchanged_findings],
        })

    return {
        "ci_scan": True,
        "scan_timestamp": datetime.utcnow().isoformat() + "Z",
        "summary": {
            "total_targets_affected": s.total_targets_affected,
            "new_count": s.new_count,
            "worsened_count": s.worsened_count,
            "resolved_count": s.resolved_count,
            "unchanged_count": s.unchanged_count,
            "overall_risk_delta": s.overall_risk_delta,
            "verdict": s.verdict,
        },
        "targets": target_reports,
    }


def _impact_finding_to_dict(impact_f: ImpactFinding) -> dict[str, Any]:
    f = impact_f.finding
    return {
        "status": impact_f.status,
        "severity": impact_f.severity,
        "description": impact_f.description,
        "finding": {
            "severity": f.severity,
            "section": f.section,
            "category": f.category,
            "rule_id": f.rule_id,
            "rule_name": f.rule_name,
            "message": redact_secrets(f.message),
            "component": {
                "type": f.component_type,
                "name": f.component_name,
                "path": f.component_path,
            },
            "line": f.line,
            "snippet": redact_secrets(f.snippet) if f.snippet else None,
            "recommendation": f.recommendation,
        },
    }


# ── File writing helpers ─────────────────────────────────────────────


def write_pr_comment(pr_result: PRScanResult, output_path: str) -> None:
    """Write the PR comment markdown to a file."""
    comment = generate_pr_comment(pr_result)
    validated = _validate_output_path(output_path)
    validated.write_text(comment, encoding="utf-8")


def write_pr_sarif(pr_result: PRScanResult, output_path: str) -> None:
    """Write the SARIF report to a file."""
    sarif = generate_pr_sarif(pr_result)
    validated = _validate_output_path(output_path)
    with open(validated, "w", encoding="utf-8") as f:
        json.dump(sarif, f, indent=2)


def write_pr_json(pr_result: PRScanResult, output_path: str) -> None:
    """Write the full JSON report to a file."""
    report = generate_pr_json(pr_result)
    validated = _validate_output_path(output_path)
    with open(validated, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
