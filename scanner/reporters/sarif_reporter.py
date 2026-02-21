"""
SARIF Reporter - Outputs scan results in SARIF format for CI/CD integration.

SARIF (Static Analysis Results Interchange Format) is supported by:
- GitHub Advanced Security
- GitLab Security Dashboard  
- Azure DevOps
- Many other security tools
"""

import json
from datetime import datetime
from typing import Any

from scanner.core.plugin_parser import ParsedPlugin
from scanner.core.skill_analyzer import SecurityFinding
from scanner.reporters.json_reporter import _validate_output_path
from scanner.utils.redaction import redact_secrets


class SARIFReporter:
    """Generates SARIF reports from scan results."""
    
    SARIF_VERSION = "2.1.0"
    SCHEMA_URI = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
    
    SEVERITY_TO_LEVEL = {
        "critical": "error",
        "high": "error",
        "medium": "warning",
        "low": "note",
    }
    
    SEVERITY_TO_SCORE = {
        "critical": 9.0,
        "high": 7.0,
        "medium": 5.0,
        "low": 3.0,
    }
    
    def __init__(self):
        """Initialize the SARIF reporter."""
        pass
    
    def generate(
        self,
        plugin: ParsedPlugin,
        findings: list[SecurityFinding],
        output_path: str | None = None
    ) -> dict[str, Any]:
        """Generate a SARIF report."""
        # Collect unique rules
        rules = self._collect_rules(findings)
        
        # Build results
        results = [self._finding_to_result(f, rules) for f in findings]
        
        sarif = {
            "$schema": self.SCHEMA_URI,
            "version": self.SARIF_VERSION,
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "Claude Plugin Security Scanner",
                            "version": "1.0.0",
                            "informationUri": "https://github.com/your-org/skills-scanner",
                            "rules": list(rules.values()),
                        }
                    },
                    "results": results,
                    "invocations": [
                        {
                            "executionSuccessful": True,
                            "endTimeUtc": datetime.utcnow().isoformat() + "Z",
                        }
                    ],
                    "artifacts": self._build_artifacts(plugin),
                }
            ],
        }
        
        if output_path:
            # Validate output path before writing
            validated_path = _validate_output_path(output_path)
            with open(validated_path, "w", encoding="utf-8") as f:
                json.dump(sarif, f, indent=2)
        
        return sarif
    
    def _collect_rules(self, findings: list[SecurityFinding]) -> dict[str, dict]:
        """Collect unique rules from findings."""
        rules: dict[str, dict] = {}
        
        for finding in findings:
            if finding.rule_id not in rules:
                rules[finding.rule_id] = {
                    "id": finding.rule_id,
                    "name": finding.rule_name,
                    "shortDescription": {
                        "text": finding.rule_name,
                    },
                    "fullDescription": {
                        "text": finding.recommendation or finding.rule_name,
                    },
                    "defaultConfiguration": {
                        "level": self.SEVERITY_TO_LEVEL.get(finding.severity, "warning"),
                    },
                    "properties": {
                        "security-severity": str(self.SEVERITY_TO_SCORE.get(finding.severity, 5.0)),
                        "tags": ["security", f"severity:{finding.severity}", f"section:{finding.section}"],
                    },
                }
        
        return rules
    
    def _finding_to_result(
        self,
        finding: SecurityFinding,
        rules: dict[str, dict]
    ) -> dict[str, Any]:
        """Convert a finding to a SARIF result."""
        result: dict[str, Any] = {
            "ruleId": finding.rule_id,
            "ruleIndex": list(rules.keys()).index(finding.rule_id),
            "level": self.SEVERITY_TO_LEVEL.get(finding.severity, "warning"),
            "message": {
                "text": redact_secrets(finding.message),
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": finding.component_path,
                        },
                        "region": {
                            "startLine": finding.line or 1,
                            "startColumn": finding.column or 1,
                        } if finding.line else {},
                    },
                    "logicalLocations": [
                        {
                            "name": finding.component_name,
                            "kind": finding.component_type,
                        }
                    ],
                }
            ],
        }
        
        # Add code snippet if available
        if finding.snippet:
            result["locations"][0]["physicalLocation"]["contextRegion"] = {
                "snippet": {
                    "text": redact_secrets(finding.snippet),
                }
            }
        
        # Add fix recommendation
        if finding.recommendation:
            result["fixes"] = [
                {
                    "description": {
                        "text": finding.recommendation,
                    }
                }
            ]
        
        # Add section and category as properties
        result["properties"] = {
            "section": finding.section,
        }
        if finding.category:
            result["properties"]["category"] = finding.category
        
        return result
    
    def _build_artifacts(self, plugin: ParsedPlugin) -> list[dict]:
        """Build artifacts list from plugin components."""
        artifacts = []
        seen_paths = set()
        
        for component in plugin.components:
            if component.path not in seen_paths:
                seen_paths.add(component.path)
                artifacts.append({
                    "location": {
                        "uri": component.path,
                    },
                    "roles": [self._component_type_to_role(component.type)],
                })
        
        return artifacts
    
    def _component_type_to_role(self, component_type: str) -> str:
        """Map component type to SARIF artifact role."""
        role_map = {
            "skill": "analysisTarget",
            "command": "analysisTarget",
            "hook": "configuration",
            "mcp": "configuration",
            "lsp": "configuration",
            "agent": "analysisTarget",
            "script": "analysisTarget",
            "resource": "analysisTarget",
        }
        return role_map.get(component_type, "analysisTarget")

