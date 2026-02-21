"""
CSV Reporter — Exports scan findings as a CSV file alongside every scan.

Generates a single CSV with one row per finding, suitable for import into
spreadsheets, SIEM tools, or data analysis pipelines.
"""

import csv
import io
import os
from datetime import datetime
from pathlib import Path
from typing import Optional

from scanner.core.plugin_parser import ParsedPlugin
from scanner.core.skill_analyzer import SecurityFinding
from scanner.reporters.json_reporter import _validate_output_path
from scanner.utils.redaction import redact_secrets

_CSV_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def _defuse_csv_cell(value: str) -> str:
    """Neutralize CSV formula injection by prefixing dangerous cells with a tab."""
    if value and value[0] in _CSV_FORMULA_PREFIXES:
        return "\t" + value
    return value


def _sanitize(text: Optional[str], max_length: int = 0, redact: bool = False) -> str:
    """Sanitize text for CSV: collapse whitespace, optionally truncate and redact secrets."""
    if text is None:
        return ""
    text = str(text).replace("\r\n", " ").replace("\n", " ").replace("\r", " ")
    text = " ".join(text.split())
    if redact:
        text = redact_secrets(text)
    if max_length and len(text) > max_length:
        text = text[: max_length - 3] + "..."
    return _defuse_csv_cell(text)


HEADERS = [
    "Severity",
    "Section",
    "Rule ID",
    "Rule Name",
    "Category",
    "Component Type",
    "Component Name",
    "Component Path",
    "Line",
    "Message",
    "Recommendation",
    "Snippet",
]


class CSVReporter:
    """Generates CSV reports from scan results."""

    def generate(
        self,
        plugin: ParsedPlugin,
        findings: list[SecurityFinding],
        output_path: Optional[str] = None,
    ) -> str:
        """
        Generate a CSV report.

        Args:
            plugin: Parsed plugin (used for deriving default filename).
            findings: List of security findings.
            output_path: Explicit CSV file path. If ``None``, the path is
                         derived from the plugin name in the current directory.

        Returns:
            The absolute path of the written CSV file.
        """
        # Determine output path
        if output_path:
            csv_path = _validate_output_path(output_path)
        else:
            safe_name = _sanitize(plugin.manifest.name).replace(" ", "-") or "scan"
            csv_path = Path(f"{safe_name}-findings.csv").resolve()

        # Build rows
        rows: list[list[str]] = []
        for f in findings:
            # Use the explicit category field if available, else derive from rule_id
            category = f.category or (f.rule_id.rsplit("-", 1)[0] if f.rule_id else "")
            rows.append([
                _defuse_csv_cell(f.severity),
                _defuse_csv_cell(f.section),
                _defuse_csv_cell(f.rule_id),
                _defuse_csv_cell(f.rule_name),
                _defuse_csv_cell(category),
                _defuse_csv_cell(f.component_type),
                _defuse_csv_cell(f.component_name),
                _defuse_csv_cell(f.component_path),
                str(f.line) if f.line else "",
                _sanitize(f.message, max_length=500, redact=True),
                _sanitize(f.recommendation, max_length=300),
                _sanitize(f.snippet, max_length=200, redact=True),
            ])

        # Sort by severity (critical first), then component, then rule
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        rows.sort(key=lambda r: (severity_order.get(r[0], 9), r[4], r[1]))

        # Write CSV
        with open(csv_path, "w", newline="", encoding="utf-8") as fh:
            writer = csv.writer(fh, quoting=csv.QUOTE_ALL)
            writer.writerow(HEADERS)
            writer.writerows(rows)

        return str(csv_path)

    def generate_multi(
        self,
        scan_results: list[dict],
        output_path: Optional[str] = None,
    ) -> str:
        """
        Generate a CSV report from multiple scan results.

        Adds a leading "Plugin/Skill" column so rows from different
        targets are distinguishable.
        """
        multi_headers = ["Plugin/Skill"] + HEADERS

        if output_path:
            csv_path = _validate_output_path(output_path)
        else:
            csv_path = Path("multi-scan-findings.csv").resolve()

        rows: list[list[str]] = []
        for sr in scan_results:
            plugin = sr["plugin"]
            name = _sanitize(plugin.manifest.name) or "unknown"
            for f in sr["findings"]:
                category = f.category or (f.rule_id.rsplit("-", 1)[0] if f.rule_id else "")
                rows.append([
                    _defuse_csv_cell(name),
                    _defuse_csv_cell(f.severity),
                    _defuse_csv_cell(f.section),
                    _defuse_csv_cell(f.rule_id),
                    _defuse_csv_cell(f.rule_name),
                    _defuse_csv_cell(category),
                    _defuse_csv_cell(f.component_type),
                    _defuse_csv_cell(f.component_name),
                    _defuse_csv_cell(f.component_path),
                    str(f.line) if f.line else "",
                    _sanitize(f.message, max_length=500, redact=True),
                    _sanitize(f.recommendation, max_length=300),
                    _sanitize(f.snippet, max_length=200, redact=True),
                ])

        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        rows.sort(key=lambda r: (r[0], severity_order.get(r[1], 9), r[5], r[2]))

        with open(csv_path, "w", newline="", encoding="utf-8") as fh:
            writer = csv.writer(fh, quoting=csv.QUOTE_ALL)
            writer.writerow(multi_headers)
            writer.writerows(rows)

        return str(csv_path)

    def generate_string(self, findings: list[SecurityFinding]) -> str:
        """
        Generate CSV content as an in-memory string (for stdout / pipes).
        """
        buf = io.StringIO()
        writer = csv.writer(buf, quoting=csv.QUOTE_ALL)
        writer.writerow(HEADERS)

        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        sorted_findings = sorted(
            findings,
            key=lambda f: (severity_order.get(f.severity, 9), f.component_type, f.rule_id),
        )

        for f in sorted_findings:
            category = f.category or (f.rule_id.rsplit("-", 1)[0] if f.rule_id else "")
            writer.writerow([
                _defuse_csv_cell(f.severity),
                _defuse_csv_cell(f.section),
                _defuse_csv_cell(f.rule_id),
                _defuse_csv_cell(f.rule_name),
                _defuse_csv_cell(category),
                _defuse_csv_cell(f.component_type),
                _defuse_csv_cell(f.component_name),
                _defuse_csv_cell(f.component_path),
                str(f.line) if f.line else "",
                _sanitize(f.message, max_length=500, redact=True),
                _sanitize(f.recommendation, max_length=300),
                _sanitize(f.snippet, max_length=200, redact=True),
            ])

        return buf.getvalue()
