"""
Graph Exporter - Exports plugin structure as React Flow compatible JSON.

Generates nodes and edges for visualization in the React Flow graph.
"""

import json
from dataclasses import dataclass
from typing import Any

from scanner.core.plugin_parser import ParsedPlugin, PluginComponent
from scanner.core.skill_analyzer import SecurityFinding
from scanner.reporters.json_reporter import _validate_output_path
from scanner.utils.redaction import redact_secrets


@dataclass
class GraphNode:
    """Represents a node in the visualization graph."""
    
    id: str
    type: str
    label: str
    path: str
    position: dict
    data: dict


@dataclass
class GraphEdge:
    """Represents an edge in the visualization graph."""
    
    id: str
    source: str
    target: str
    type: str = "default"
    data: dict | None = None


class GraphExporter:
    """Exports plugin structure for React Flow visualization."""
    
    # Node type colors (for reference in frontend)
    NODE_COLORS = {
        "plugin": "#64748b",    # Slate
        "skill": "#6366f1",     # Indigo
        "command": "#8b5cf6",   # Violet
        "hook": "#f59e0b",      # Amber
        "mcp": "#06b6d4",       # Cyan
        "lsp": "#14b8a6",       # Teal
        "agent": "#10b981",     # Emerald
        "script": "#f43f5e",    # Rose
        "resource": "#6b7280",  # Gray
    }
    
    # Layout configuration - optimized for cleaner visualization
    LAYOUT_CONFIG = {
        "node_width": 160,
        "node_height": 80,
        "horizontal_spacing": 200,
        "vertical_spacing": 140,
        "root_x": 500,
        "root_y": 50,
    }
    
    def __init__(self):
        """Initialize the graph exporter."""
        self.nodes: list[dict] = []
        self.edges: list[dict] = []
    
    def export(
        self,
        plugin: ParsedPlugin,
        findings: list[SecurityFinding],
        output_path: str | None = None,
        verdict: str = "safe",
    ) -> dict[str, Any]:
        """Export plugin as React Flow graph data."""
        self.nodes = []
        self.edges = []
        
        # Create findings lookup by component
        findings_by_component = self._group_findings(findings)
        
        # Create root plugin node (pass all findings for aggregate counts)
        root_node = self._create_plugin_node(plugin, findings_by_component, findings)
        self.nodes.append(root_node)
        
        # Create component nodes by type
        component_groups = self._group_components(plugin.components)
        
        y_offset = self.LAYOUT_CONFIG["root_y"] + self.LAYOUT_CONFIG["vertical_spacing"]
        
        for type_name, components in component_groups.items():
            self._create_component_nodes(
                components,
                type_name,
                findings_by_component,
                y_offset
            )
            y_offset += self.LAYOUT_CONFIG["vertical_spacing"]
        
        # Create edges from root to first-level components
        self._create_edges(plugin, component_groups)

        malicious_count = sum(1 for f in findings if f.section == "malicious")
        
        # Build output structure
        result = {
            "plugin": {
                "name": plugin.manifest.name,
                "version": plugin.manifest.version,
                "path": plugin.path,
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
            "nodes": self.nodes,
            "edges": self.edges,
            "summary": self._create_summary(plugin, findings),
            "nodeTypes": list(self.NODE_COLORS.keys()),
            "severityColors": {
                "critical": "#ef4444",
                "high": "#f97316",
                "medium": "#eab308",
                "low": "#6b7280",
                "clean": "#22c55e",
            },
        }
        
        if output_path:
            validated_path = _validate_output_path(output_path)
            with open(validated_path, "w", encoding="utf-8") as f:
                json.dump(result, f, indent=2)
        
        return result

    def export_multi(
        self,
        scan_results: list[dict],
        output_path: str | None = None,
    ) -> dict[str, Any]:
        """
        Export multiple scan results as a combined multi-scan JSON.

        Each entry in *scan_results* is a dict with keys:
            plugin (ParsedPlugin), findings (list[SecurityFinding]),
            verdict (str), target_type (str).
        """
        individual_exports: list[dict] = []
        total_findings = 0
        total_malicious = 0
        total_code_security = 0
        safe_count = 0

        for sr in scan_results:
            single = self.export(sr["plugin"], sr["findings"], verdict=sr["verdict"])
            single["scanType"] = sr.get("target_type", "plugin")
            individual_exports.append(single)

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

        result: dict[str, Any] = {
            "multi_scan": True,
            "aggregate": {
                "total_scans": len(scan_results),
                "safe_count": safe_count,
                "unsafe_count": len(scan_results) - safe_count,
                "total_findings": total_findings,
                "total_malicious": total_malicious,
                "total_code_security": total_code_security,
            },
            "scans": individual_exports,
        }

        if output_path:
            validated_path = _validate_output_path(output_path)
            with open(validated_path, "w", encoding="utf-8") as f:
                json.dump(result, f, indent=2)

        return result
    
    def _group_findings(
        self,
        findings: list[SecurityFinding]
    ) -> dict[str, list[SecurityFinding]]:
        """Group findings by component path."""
        grouped: dict[str, list[SecurityFinding]] = {}
        
        for finding in findings:
            key = f"{finding.component_type}:{finding.component_name}"
            if key not in grouped:
                grouped[key] = []
            grouped[key].append(finding)
        
        return grouped
    
    def _group_components(
        self,
        components: list[PluginComponent]
    ) -> dict[str, list[PluginComponent]]:
        """Group components by type."""
        grouped: dict[str, list[PluginComponent]] = {}
        
        for component in components:
            if component.type not in grouped:
                grouped[component.type] = []
            grouped[component.type].append(component)
        
        return grouped
    
    def _create_plugin_node(
        self,
        plugin: ParsedPlugin,
        findings_by_component: dict[str, list[SecurityFinding]],
        all_findings: list[SecurityFinding],
    ) -> dict:
        """Create the root plugin node with aggregate counts from all findings."""
        plugin_findings = findings_by_component.get("manifest:plugin.json", [])
        
        # Root severity reflects the worst finding across the entire plugin
        severity = self._get_highest_severity(all_findings)
        
        total_malicious = sum(
            1 for f in all_findings if f.section == "malicious"
        )
        total_code_security = sum(
            1 for f in all_findings
            if (f.section or "code_security") == "code_security"
        )
        
        return {
            "id": "plugin-root",
            "type": "plugin",
            "position": {
                "x": self.LAYOUT_CONFIG["root_x"],
                "y": self.LAYOUT_CONFIG["root_y"],
            },
            "data": {
                "label": plugin.manifest.name,
                "version": plugin.manifest.version,
                "description": plugin.manifest.description,
                "path": plugin.path,
                "severity": severity,
                "findingsCount": len(plugin_findings),
                "findings": [self._finding_to_dict(f) for f in plugin_findings],
                "componentCounts": self._count_components(plugin.components),
                "totalFindings": len(all_findings),
                "totalMalicious": total_malicious,
                "totalCodeSecurity": total_code_security,
            },
        }
    
    def _create_component_nodes(
        self,
        components: list[PluginComponent],
        type_name: str,
        findings_by_component: dict[str, list[SecurityFinding]],
        base_y: int
    ) -> None:
        """Create nodes for a group of components."""
        num_components = len(components)
        
        # Calculate starting X to center the row
        total_width = (num_components - 1) * self.LAYOUT_CONFIG["horizontal_spacing"]
        start_x = self.LAYOUT_CONFIG["root_x"] - (total_width / 2)
        
        for i, component in enumerate(components):
            key = f"{component.type}:{component.name}"
            component_findings = findings_by_component.get(key, [])
            
            severity = self._get_highest_severity(component_findings)
            
            node = {
                "id": f"{type_name}-{component.name}",
                "type": type_name,
                "position": {
                    "x": start_x + (i * self.LAYOUT_CONFIG["horizontal_spacing"]),
                    "y": base_y,
                },
                "data": {
                    "label": component.name,
                    "path": component.path,
                    "componentType": component.type,
                    "severity": severity,
                    "findingsCount": len(component_findings),
                    "findings": [self._finding_to_dict(f) for f in component_findings],
                    "metadata": component.metadata,
                },
            }
            
            self.nodes.append(node)
    
    def _create_edges(
        self,
        plugin: ParsedPlugin,
        component_groups: dict[str, list[PluginComponent]]
    ) -> None:
        """Create edges between nodes."""
        # Connect root to all first-level components
        for type_name, components in component_groups.items():
            for component in components:
                target_id = f"{type_name}-{component.name}"
                
                # Get severity for edge coloring
                edge_data = {"severity": "clean"}
                for node in self.nodes:
                    if node["id"] == target_id:
                        edge_data["severity"] = node["data"].get("severity", "clean")
                        break
                
                self.edges.append({
                    "id": f"e-root-{target_id}",
                    "source": "plugin-root",
                    "target": target_id,
                    "type": "security",
                    "animated": edge_data["severity"] in ["critical", "high"],
                    "data": edge_data,
                })
        
        # Create inter-component edges based on relationships
        self._create_relationship_edges(plugin.components)
    
    def _create_relationship_edges(self, components: list[PluginComponent]) -> None:
        """Create edges based on component relationships."""
        # Connect hooks to their event targets
        for component in components:
            if component.type == "hook":
                event = component.metadata.get("event", "")
                hook_type = component.metadata.get("hook_type", "")
                
                # If hook references a script, connect to it
                command = component.metadata.get("command", "")
                if command:
                    for other in components:
                        if other.type == "script" and other.name in command:
                            self.edges.append({
                                "id": f"e-hook-{component.name}-script-{other.name}",
                                "source": f"hook-{component.name}",
                                "target": f"script-{other.name}",
                                "type": "dependency",
                                "data": {"relationship": "executes"},
                            })
            
            # Connect skills to their scripts
            if component.type == "skill":
                parent_skill = component.metadata.get("parent_skill")
                if parent_skill:
                    self.edges.append({
                        "id": f"e-skill-{parent_skill}-script-{component.name}",
                        "source": f"skill-{parent_skill}",
                        "target": f"script-{component.name}",
                        "type": "contains",
                        "data": {"relationship": "contains"},
                    })
    
    def _get_highest_severity(self, findings: list[SecurityFinding]) -> str:
        """Get the highest severity from a list of findings."""
        severity_order = ["critical", "high", "medium", "low"]
        
        for severity in severity_order:
            for finding in findings:
                if finding.severity == severity:
                    return severity
        
        return "clean"
    
    def _finding_to_dict(self, finding: SecurityFinding) -> dict:
        """Convert finding to dictionary for frontend (secrets redacted)."""
        return {
            "severity": finding.severity,
            "section": finding.section,
            "category": finding.category,
            "ruleId": finding.rule_id,
            "ruleName": finding.rule_name,
            "message": redact_secrets(finding.message),
            "line": finding.line,
            "snippet": redact_secrets(finding.snippet),
            "filePath": finding.component_path,
            "recommendation": finding.recommendation,
        }
    
    def _count_components(self, components: list[PluginComponent]) -> dict[str, int]:
        """Count components by type."""
        counts: dict[str, int] = {}
        for component in components:
            counts[component.type] = counts.get(component.type, 0) + 1
        return counts
    
    def _create_summary(
        self,
        plugin: ParsedPlugin,
        findings: list[SecurityFinding]
    ) -> dict:
        """Create summary statistics."""
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        section_counts: dict[str, int] = {"malicious": 0, "code_security": 0}
        
        for finding in findings:
            severity_counts[finding.severity] = severity_counts.get(finding.severity, 0) + 1
            section = finding.section or "code_security"
            section_counts[section] = section_counts.get(section, 0) + 1
        
        return {
            "totalFindings": len(findings),
            "critical": severity_counts["critical"],
            "high": severity_counts["high"],
            "medium": severity_counts["medium"],
            "low": severity_counts["low"],
            "malicious": section_counts["malicious"],
            "codeSecurity": section_counts["code_security"],
            "totalComponents": len(plugin.components),
            "componentTypes": self._count_components(plugin.components),
        }

