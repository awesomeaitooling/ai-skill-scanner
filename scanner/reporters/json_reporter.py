"""
JSON Reporter - Outputs scan results in JSON format.
"""

import json
import os
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from typing import Any

from scanner.core.plugin_parser import ParsedPlugin
from scanner.core.skill_analyzer import SecurityFinding
from scanner.utils.redaction import redact_secrets


def _validate_output_path(output_path: str) -> Path:
    """
    Validate and sanitize output file path.
    
    Args:
        output_path: User-provided output path
        
    Returns:
        Validated Path object
        
    Raises:
        ValueError: If path is invalid or potentially dangerous
    """
    if not output_path:
        raise ValueError("Output path cannot be empty")
    
    # Resolve to absolute path
    resolved = Path(output_path).resolve()
    
    # Block writes to sensitive system directories
    sensitive_dirs = [
        "/etc", "/usr", "/bin", "/sbin", "/var", "/root",
        "/System", "/Library",  # macOS
        "C:\\Windows", "C:\\Program Files",  # Windows
    ]
    
    resolved_str = str(resolved)
    for sensitive in sensitive_dirs:
        if resolved_str.startswith(sensitive):
            raise ValueError(f"Cannot write to sensitive directory: {sensitive}")
    
    # Ensure parent directory exists and is writable
    parent = resolved.parent
    if not parent.exists():
        raise ValueError(f"Parent directory does not exist: {parent}")
    
    if not os.access(parent, os.W_OK):
        raise ValueError(f"Parent directory is not writable: {parent}")
    
    # Block overwriting certain file types
    dangerous_extensions = [".exe", ".dll", ".so", ".sh", ".bash", ".zsh", ".py", ".rb"]
    if resolved.suffix.lower() in dangerous_extensions and resolved.exists():
        raise ValueError(f"Cannot overwrite executable file: {resolved}")
    
    return resolved


class JSONReporter:
    """Generates JSON reports from scan results."""
    
    def __init__(self):
        """Initialize the JSON reporter."""
        pass
    
    def generate(
        self,
        plugin: ParsedPlugin,
        findings: list[SecurityFinding],
        output_path: str | None = None,
        verdict: str = "safe",
    ) -> dict[str, Any]:
        """Generate a JSON report."""
        severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        sorted_findings = sorted(findings, key=lambda f: (
            0 if f.section == "malicious" else 1,
            severity_rank.get(f.severity, 4),
        ))

        malicious_count = sum(1 for f in findings if f.section == "malicious")

        report = {
            "metadata": {
                "scanner_version": "1.0.0",
                "scan_timestamp": datetime.utcnow().isoformat() + "Z",
                "plugin_path": Path(plugin.path).name if plugin.path else "unknown",
            },
            "plugin": {
                "name": plugin.manifest.name,
                "version": plugin.manifest.version,
                "description": plugin.manifest.description,
                "author": plugin.manifest.author,
            },
            "verdict": {
                "safe": verdict == "safe",
                "summary": (
                    "No malicious findings detected"
                    if verdict == "safe"
                    else f"UNSAFE: {malicious_count} malicious finding(s) detected"
                ),
                "malicious_count": malicious_count,
            },
            "summary": self._generate_summary(findings),
            "findings": [self._finding_to_dict(f) for f in sorted_findings],
            "components": self._generate_components_summary(plugin),
            "errors": plugin.errors,
        }
        
        if output_path:
            validated_path = _validate_output_path(output_path)
            with open(validated_path, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=2)
        
        return report
    
    def generate_multi(
        self,
        scan_results: list[dict],
        output_path: str | None = None,
    ) -> dict[str, Any]:
        """
        Generate a combined JSON report wrapping multiple scan results.

        Each entry in *scan_results* is a dict with keys:
            plugin (ParsedPlugin), findings (list[SecurityFinding]),
            verdict (str), target_type (str).
        """
        individual_reports: list[dict] = []
        total_findings = 0
        total_malicious = 0
        total_code_security = 0
        safe_count = 0

        for sr in scan_results:
            single = self.generate(sr["plugin"], sr["findings"], verdict=sr["verdict"])
            single["scanType"] = sr.get("target_type", "plugin")
            individual_reports.append(single)

            findings = sr["findings"]
            total_findings += len(findings)
            mal = sum(1 for f in findings if f.section == "malicious")
            total_malicious += mal
            total_code_security += sum(
                1 for f in findings
                if (f.section or "code_security") == "code_security"
            )
            if sr["verdict"] == "safe":
                safe_count += 1

        report: dict[str, Any] = {
            "multi_scan": True,
            "aggregate": {
                "total_scans": len(scan_results),
                "safe_count": safe_count,
                "unsafe_count": len(scan_results) - safe_count,
                "total_findings": total_findings,
                "total_malicious": total_malicious,
                "total_code_security": total_code_security,
            },
            "scans": individual_reports,
        }

        if output_path:
            validated_path = _validate_output_path(output_path)
            with open(validated_path, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=2)

        return report

    def _generate_summary(self, findings: list[SecurityFinding]) -> dict[str, Any]:
        """Generate findings summary."""
        severity_counts = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
        }
        section_counts: dict[str, int] = {
            "malicious": 0,
            "code_security": 0,
        }
        
        rules_triggered = set()
        
        for finding in findings:
            severity_counts[finding.severity] = severity_counts.get(finding.severity, 0) + 1
            section = finding.section or "code_security"
            section_counts[section] = section_counts.get(section, 0) + 1
            rules_triggered.add(finding.rule_id)
        
        return {
            "total_findings": len(findings),
            "severity_counts": severity_counts,
            "section_counts": section_counts,
            "unique_rules": len(rules_triggered),
            "rules_triggered": list(rules_triggered),
        }
    
    def _generate_components_summary(self, plugin: ParsedPlugin) -> dict[str, Any]:
        """Generate components summary."""
        type_counts: dict[str, int] = {}
        
        for component in plugin.components:
            type_counts[component.type] = type_counts.get(component.type, 0) + 1
        
        return {
            "total": len(plugin.components),
            "by_type": type_counts,
        }
    
    def _finding_to_dict(self, finding: SecurityFinding) -> dict[str, Any]:
        """Convert finding to dictionary."""
        result: dict[str, Any] = {
            "severity": finding.severity,
            "section": finding.section,
            "category": finding.category,
            "rule_id": finding.rule_id,
            "rule_name": finding.rule_name,
            "message": redact_secrets(finding.message),
            "component": {
                "type": finding.component_type,
                "name": finding.component_name,
                "path": finding.component_path,
            },
            "location": {
                "line": finding.line,
                "column": finding.column,
            } if finding.line else None,
            "snippet": redact_secrets(finding.snippet),
            "recommendation": finding.recommendation,
        }
        return result

