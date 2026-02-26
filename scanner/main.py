"""
Claude Code Plugin Security Scanner - Main CLI Entry Point

Usage:
    python -m scanner <plugin_path> [options]
    python -m scanner --marketplace <url> [options]
    python -m scanner rules [--list|--stats|--category <name>]
"""

import argparse
import json
import os
import re
import sys
import traceback
from pathlib import Path
from typing import Optional

from scanner.core.plugin_parser import PluginParser, ParsedPlugin
from scanner.core.skill_analyzer import SkillAnalyzer, SecurityFinding
from scanner.core.hook_analyzer import HookAnalyzer
from scanner.core.mcp_analyzer import MCPAnalyzer
from scanner.core.lsp_analyzer import LSPAnalyzer
from scanner.core.script_analyzer import ScriptAnalyzer
from scanner.core.agent_analyzer import AgentCommandAnalyzer
from scanner.core.ast_analyzer import PythonASTAnalyzer
from scanner.core.dataflow_analyzer import DataflowAnalyzer
from scanner.core.alignment_analyzer import AlignmentAnalyzer
from scanner.core.meta_analyzer import MetaAnalyzer
from scanner.core.cross_skill_analyzer import CrossSkillAnalyzer
from scanner.config import ScanConfig, load_config
from scanner.rules import get_rule_loader, reload_rules
from scanner.reporters.json_reporter import JSONReporter
from scanner.reporters.sarif_reporter import SARIFReporter
from scanner.reporters.graph_exporter import GraphExporter
from scanner.reporters.csv_reporter import CSVReporter
from scanner.utils.git_utils import (
    clone_marketplace,
    discover_plugins_in_marketplace,
    cleanup_temp_dir,
    validate_git_url,
)


_SECRET_LIKE = re.compile(
    r"(sk-[A-Za-z0-9]{5})[A-Za-z0-9]{15,}"
    r"|(ghp_[A-Za-z0-9]{4})[A-Za-z0-9]{32,}"
    r"|(AKIA[A-Z0-9]{4})[A-Z0-9]{12,}"
    r"|(xox[bpas]-[A-Za-z0-9]{4})[A-Za-z0-9\-]{6,}",
)


def _sanitize_traceback(tb_str: str) -> str:
    """Redact sensitive information from traceback strings before printing."""
    home = os.path.expanduser("~")
    tb_str = tb_str.replace(home, "~")
    tb_str = _SECRET_LIKE.sub(lambda m: next(g for g in m.groups() if g) + "***", tb_str)
    return tb_str


class PluginScanner:
    """Main scanner class that orchestrates all security checks."""
    
    def __init__(self, verbose: bool = False, config: Optional[ScanConfig] = None):
        """Initialize the scanner with all analyzers.
        
        Args:
            verbose: Enable verbose output.
            config: Optional ScanConfig; uses defaults if not provided.
        """
        self.verbose = verbose
        self.config = config or ScanConfig()
        
        # Initialize rule loader
        self.rule_loader = get_rule_loader()
        
        # Apply rule-level config (disabled rules/categories, severity overrides)
        self._apply_rule_config()
        
        # Core analyzers (always available, controlled by config)
        self.skill_analyzer = SkillAnalyzer(self.rule_loader)
        self.hook_analyzer = HookAnalyzer(self.rule_loader)
        self.mcp_analyzer = MCPAnalyzer(self.rule_loader)
        self.lsp_analyzer = LSPAnalyzer(self.rule_loader)
        self.script_analyzer = ScriptAnalyzer(self.rule_loader)
        self.agent_command_analyzer = AgentCommandAnalyzer(self.rule_loader)
        
        # Advanced analyzers
        self.ast_analyzer = PythonASTAnalyzer()
        self.dataflow_analyzer = DataflowAnalyzer()
        self.alignment_analyzer = AlignmentAnalyzer()
        self.meta_analyzer = MetaAnalyzer(verbose=verbose)
        self.cross_skill_analyzer = CrossSkillAnalyzer(verbose=verbose)
        
        # Reporters
        self.json_reporter = JSONReporter()
        self.sarif_reporter = SARIFReporter()
        self.graph_exporter = GraphExporter()
        self.csv_reporter = CSVReporter()
        
        if self.verbose and self.rule_loader.errors:
            print(f"Warning: {len(self.rule_loader.errors)} rule loading errors:")
            for error in self.rule_loader.errors[:5]:
                print(f"  - {error}")
    
    def _apply_rule_config(self) -> None:
        """Apply config-level rule overrides to the rule loader."""
        # Disable specific rules
        for rule_id in self.config.rules.disabled_rules:
            rule = self.rule_loader.get_rule(rule_id)
            if rule:
                rule.enabled = False
        
        # Disable categories
        for category in self.config.rules.disabled_categories:
            for rule in self.rule_loader.get_rules_by_category(category):
                rule.enabled = False
        
        # Apply severity overrides
        for rule_id, new_severity in self.config.rules.severity_overrides.items():
            rule = self.rule_loader.get_rule(rule_id)
            if rule and new_severity in ("critical", "high", "medium", "low"):
                rule.severity = new_severity
    
    def scan_plugin(
        self, 
        plugin_path: str,
        skip_static_analysis: bool = False
    ) -> tuple[ParsedPlugin, list[SecurityFinding]]:
        """
        Scan a single plugin for security issues.
        
        Args:
            plugin_path: Path to plugin directory
            skip_static_analysis: If True, only parse plugin without running static rules
            
        Returns:
            Tuple of (parsed plugin, list of findings)
        """
        if self.verbose:
            print(f"Scanning plugin: {plugin_path}")
            if skip_static_analysis:
                print("  (Static analysis skipped - AI-only mode)")
        
        # Parse the plugin
        parser = PluginParser(plugin_path)
        plugin = parser.parse()
        
        if self.verbose:
            std = getattr(plugin, "standard_count", "?")
            deep = getattr(plugin, "deep_count", "?")
            total = len(plugin.components)
            if deep and deep != "?" and deep > 0:
                print(f"  Components discovered: {total} ({std} standard + {deep} deep discovery)")
            else:
                print(f"  Components discovered: {total}")
        
        findings: list[SecurityFinding] = []
        
        # Skip static analysis if requested (AI-only mode)
        if skip_static_analysis:
            return plugin, findings
        
        cfg = self.config
        
        # Analyze manifest with YAML rules
        if self.verbose:
            print("  Running manifest rules...")
        manifest_findings = self._analyze_manifest(plugin)
        findings.extend(manifest_findings)
        
        # Analyze each component
        for component in plugin.components:
            # Check if component type is enabled
            if not cfg.is_component_enabled(component.type):
                if self.verbose:
                    print(f"  Skipping {component.type}: {component.name} (disabled in config)")
                continue
            
            if self.verbose:
                print(f"  Analyzing {component.type}: {component.name}")
            
            # ── Skills, commands, and agents ──
            if component.type in ("skill", "command", "agent"):
                if cfg.is_analyzer_enabled("skill_analyzer"):
                    findings.extend(self.skill_analyzer.analyze(component))
                
                # Agent/command-specific checks
                if cfg.is_analyzer_enabled("agent_command_analyzer"):
                    if component.type in ("agent", "command"):
                        findings.extend(self.agent_command_analyzer.analyze(component))
                
                # Alignment verification
                if cfg.is_analyzer_enabled("alignment_analyzer"):
                    findings.extend(self.alignment_analyzer.analyze(component))
            
            # ── Hooks ──
            elif component.type == "hook":
                if cfg.is_analyzer_enabled("hook_analyzer"):
                    findings.extend(self.hook_analyzer.analyze(component))
            
            # ── MCP servers ──
            elif component.type == "mcp":
                if cfg.is_analyzer_enabled("mcp_analyzer"):
                    findings.extend(self.mcp_analyzer.analyze(component))
            
            # ── LSP servers ──
            elif component.type == "lsp":
                if cfg.is_analyzer_enabled("lsp_analyzer"):
                    findings.extend(self.lsp_analyzer.analyze(component))
            
            # ── Scripts ──
            elif component.type == "script":
                if cfg.is_analyzer_enabled("script_analyzer"):
                    findings.extend(self.script_analyzer.analyze(component))
                
                # AST analysis (Python only)
                if cfg.is_analyzer_enabled("ast_analyzer"):
                    findings.extend(self.ast_analyzer.analyze(component))
                
                # Dataflow analysis (Python only)
                if cfg.is_analyzer_enabled("dataflow_analyzer"):
                    findings.extend(self.dataflow_analyzer.analyze(component))
                
                # Alignment verification for scripts with descriptions
                if cfg.is_analyzer_enabled("alignment_analyzer"):
                    findings.extend(self.alignment_analyzer.analyze(component))
            
            # ── Resources ──
            elif component.type == "resource":
                # Scan resources with skill analyzer for generic pattern matching
                if cfg.is_analyzer_enabled("skill_analyzer"):
                    findings.extend(self.skill_analyzer.analyze(component))
        
        # ── Cross-skill analysis (plugin-wide) ──
        if cfg.is_analyzer_enabled("cross_skill_analyzer") and len(plugin.components) >= 2:
            if self.verbose:
                print("  Running cross-component analysis...")
            findings.extend(self.cross_skill_analyzer.analyze(plugin))
        
        # ── Meta-analyzer: deduplicate, filter FPs, adjust severity, prioritize ──
        if cfg.is_analyzer_enabled("meta_analyzer"):
            if self.verbose:
                print("  Running meta-analysis (dedup, FP filter, prioritize)...")
            findings = self.meta_analyzer.process(findings)
        
        return plugin, findings
    
    def _analyze_manifest(self, plugin: ParsedPlugin) -> list[SecurityFinding]:
        """Analyze plugin manifest using YAML rules."""
        findings = []
        
        # Use the raw manifest dict for scanning
        if plugin.manifest and plugin.manifest.raw:
            manifest_str = json.dumps(plugin.manifest.raw)
        else:
            return findings
        
        # Get manifest-related rules
        manifest_rules = self.rule_loader.get_rules_by_category("manifest-structure")
        manifest_rules.extend(self.rule_loader.get_rules_by_category("manifest-permissions"))
        manifest_rules.extend(self.rule_loader.get_rules_by_category("manifest-mcp"))
        manifest_rules.extend(self.rule_loader.get_rules_by_category("manifest-hooks"))
        manifest_rules.extend(self.rule_loader.get_rules_by_category("manifest-agents"))
        manifest_rules.extend(self.rule_loader.get_rules_by_category("manifest-resources"))
        
        # Deduplicate
        seen = set()
        unique_rules = []
        for rule in manifest_rules:
            if rule.id not in seen:
                seen.add(rule.id)
                unique_rules.append(rule)
        
        for rule in unique_rules:
            if not rule.enabled:
                continue
            
            matches = rule.match(manifest_str)
            for match in matches:
                matched_text = match.group()[:50] + "..." if len(match.group()) > 50 else match.group()
                
                findings.append(SecurityFinding(
                    severity=rule.severity,
                    rule_id=rule.id,
                    rule_name=rule.name,
                    message=f"{rule.description}: '{matched_text}'",
                    component_type="manifest",
                    component_name="plugin.json",
                    component_path=str(Path(plugin.path) / ".claude-plugin" / "plugin.json"),
                    recommendation=rule.recommendation,
                    references=rule.references if rule.references else None
                ))
        
        return findings
    
    def scan_marketplace(
        self, 
        url: str,
        skip_static_analysis: bool = False
    ) -> list[tuple[ParsedPlugin, list[SecurityFinding]]]:
        """
        Scan all plugins in a marketplace.
        
        Args:
            url: Git URL of marketplace
            skip_static_analysis: If True, only parse plugins without running static rules
            
        Returns:
            List of (plugin, findings) tuples
        """
        if self.verbose:
            print(f"Cloning marketplace: {url}")
        
        temp_dir = None
        results = []
        
        try:
            temp_dir = clone_marketplace(url)
            plugins = discover_plugins_in_marketplace(temp_dir)
            
            if self.verbose:
                print(f"Found {len(plugins)} plugins")
            
            for plugin_info in plugins:
                plugin_path = plugin_info.get("path")
                if plugin_path and Path(plugin_path).exists():
                    try:
                        result = self.scan_plugin(plugin_path, skip_static_analysis)
                        results.append(result)
                    except Exception as e:
                        if self.verbose:
                            print(f"Error scanning {plugin_info.get('name', 'unknown')}: {e}")
        
        finally:
            if temp_dir:
                cleanup_temp_dir(temp_dir)
        
        return results
    
    def generate_report(
        self,
        plugin: ParsedPlugin,
        findings: list[SecurityFinding],
        output_format: str = "json",
        output_path: Optional[str] = None,
        verdict: str = "safe",
    ) -> dict:
        """
        Generate a report in the specified format.
        
        Args:
            plugin: Parsed plugin
            findings: List of security findings
            output_format: Report format (json, sarif, graph)
            output_path: Optional output file path
            verdict: Safety verdict ("safe" or "not_safe")
            
        Returns:
            Report data as dictionary
        """
        if output_format == "json":
            return self.json_reporter.generate(plugin, findings, output_path, verdict=verdict)
        elif output_format == "sarif":
            return self.sarif_reporter.generate(plugin, findings, output_path)
        elif output_format == "graph":
            return self.graph_exporter.export(plugin, findings, output_path, verdict=verdict)
        else:
            raise ValueError(f"Unknown output format: {output_format}")

    def generate_multi_report(
        self,
        scan_results: list[dict],
        output_format: str = "json",
        output_path: Optional[str] = None,
    ) -> dict:
        """
        Generate a combined report wrapping multiple individual scan results.

        Each entry in *scan_results* is a dict with keys:
            plugin, findings, verdict, target_type
        """
        if output_format == "graph":
            return self.graph_exporter.export_multi(scan_results, output_path)
        elif output_format == "json":
            return self.json_reporter.generate_multi(scan_results, output_path)
        elif output_format == "sarif":
            # SARIF doesn't have multi-scan support yet; fall back to first scan
            if scan_results:
                sr = scan_results[0]
                return self.sarif_reporter.generate(
                    sr["plugin"], sr["findings"], output_path
                )
            return {}
        else:
            raise ValueError(f"Unknown output format: {output_format}")


def print_summary(findings: list[SecurityFinding]) -> None:
    """Print a summary of findings to stdout, grouped by section."""
    from scanner.rules.sections import SECTION_DISPLAY_NAMES, SECTION_ORDER

    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    section_counts: dict[str, int] = {"malicious": 0, "code_security": 0}
    
    for finding in findings:
        severity_counts[finding.severity] = severity_counts.get(finding.severity, 0) + 1
        section_counts[finding.section] = section_counts.get(finding.section, 0) + 1
    
    print("\n" + "=" * 60)
    print("SCAN SUMMARY")
    print("=" * 60)
    print(f"Total findings: {len(findings)}")
    print(f"  Critical: {severity_counts['critical']}")
    print(f"  High:     {severity_counts['high']}")
    print(f"  Medium:   {severity_counts['medium']}")
    print(f"  Low:      {severity_counts['low']}")
    print()
    for sec_key in SECTION_ORDER:
        display = SECTION_DISPLAY_NAMES.get(sec_key, sec_key)
        print(f"  {display}: {section_counts.get(sec_key, 0)}")
    print("=" * 60)
    
    # Print critical and high findings grouped by section
    critical_high = [f for f in findings if f.severity in ("critical", "high")]
    
    if critical_high:
        for sec_key in SECTION_ORDER:
            display = SECTION_DISPLAY_NAMES.get(sec_key, sec_key)
            section_findings = [f for f in critical_high if f.section == sec_key]
            if not section_findings:
                continue
            
            print(f"\n{display.upper()} ({len(section_findings)} critical/high):")
            print("-" * 60)
            
            for finding in section_findings:
                severity_marker = "🔴" if finding.severity == "critical" else "🟠"
                print(f"\n{severity_marker} [{finding.severity.upper()}] {finding.rule_name}")
                print(f"   Component: {finding.component_type}/{finding.component_name}")
                if finding.component_path:
                    print(f"   File: {finding.component_path}")
                if finding.line:
                    print(f"   Line: {finding.line}")
                print(f"   Message: {finding.message}")
                if finding.snippet:
                    print(f"   Code: {finding.snippet[:200]}")
                if finding.category:
                    print(f"   Category: {finding.category}")
                if finding.recommendation:
                    print(f"   Fix: {finding.recommendation}")


def handle_rules_cli() -> None:
    """Handle the 'rules' CLI subcommand."""
    parser = argparse.ArgumentParser(
        prog="scanner rules",
        description="Manage security rules"
    )
    parser.add_argument(
        "--list", "-l",
        action="store_true",
        dest="list_rules",
        help="List all loaded rules"
    )
    parser.add_argument(
        "--stats", "-s",
        action="store_true",
        help="Show rule statistics"
    )
    parser.add_argument(
        "--category", "-c",
        help="List rules in a specific category"
    )
    parser.add_argument(
        "--tag", "-t",
        help="List rules with a specific tag"
    )
    parser.add_argument(
        "--list-categories",
        action="store_true",
        help="List all available categories"
    )
    parser.add_argument(
        "--list-tags",
        action="store_true",
        help="List all available tags"
    )
    parser.add_argument(
        "--reload", "-r",
        action="store_true",
        help="Reload rules from disk"
    )
    parser.add_argument(
        "--export", "-e",
        metavar="FILE",
        help="Export all rules to JSON file (use '-' for stdout)"
    )
    
    # Skip 'rules' in argv
    args = parser.parse_args(sys.argv[2:])
    handle_rules_command(args)


def handle_rules_command(args) -> None:
    """Handle the 'rules' subcommand."""
    loader = get_rule_loader()
    
    if args.reload:
        reload_rules()
        print("Rules reloaded from disk.")
        loader = get_rule_loader()
    
    if args.stats:
        stats = loader.get_stats()
        print("\n" + "=" * 60)
        print("RULE STATISTICS")
        print("=" * 60)
        print(f"Total rules: {stats['total_rules']}")
        print(f"Enabled rules: {stats['enabled_rules']}")
        print(f"Rule sets: {stats['rulesets']}")
        print(f"Categories: {stats['categories']}")
        print(f"Loading errors: {stats['errors']}")
        
        print("\nBy Severity:")
        for severity, count in sorted(stats['rules_by_severity'].items()):
            print(f"  {severity}: {count}")
        
        print("\nBy Category:")
        for category, count in sorted(stats['rules_by_category'].items()):
            print(f"  {category}: {count}")
        return
    
    if args.category:
        rules = loader.get_rules_by_category(args.category)
        if not rules:
            print(f"No rules found in category: {args.category}")
            return
        
        print(f"\nRules in category '{args.category}':")
        print("-" * 60)
        for rule in rules:
            status = "✓" if rule.enabled else "✗"
            print(f"  [{status}] {rule.id}")
            print(f"      Name: {rule.name}")
            print(f"      Severity: {rule.severity}")
            print(f"      Description: {rule.description[:60]}...")
            print()
        return
    
    if args.tag:
        rules = loader.get_rules_by_tag(args.tag)
        if not rules:
            print(f"No rules found with tag: {args.tag}")
            return
        
        print(f"\nRules with tag '{args.tag}':")
        print("-" * 60)
        for rule in rules:
            status = "✓" if rule.enabled else "✗"
            print(f"  [{status}] {rule.id} ({rule.severity})")
        return
    
    if args.list_categories:
        categories = sorted(loader.get_categories())
        print("\nAvailable categories:")
        for cat in categories:
            count = len(loader.get_rules_by_category(cat))
            print(f"  {cat} ({count} rules)")
        return
    
    if args.list_tags:
        tags = sorted(loader.get_tags())
        print("\nAvailable tags:")
        for tag in tags:
            count = len(loader.get_rules_by_tag(tag))
            print(f"  {tag} ({count} rules)")
        return
    
    if args.export:
        data = loader.to_dict()
        output = json.dumps(data, indent=2)
        if args.export == "-":
            print(output)
        else:
            with open(args.export, "w") as f:
                f.write(output)
            print(f"Rules exported to: {args.export}")
        return
    
    # Default: list all rules
    rules = loader.get_all_rules(enabled_only=False)
    print(f"\nLoaded {len(rules)} rules from {len(loader.rulesets)} rule sets\n")
    
    for ruleset in loader.rulesets:
        print(f"📁 {ruleset.name} (v{ruleset.version})")
        print(f"   {ruleset.description}")
        print(f"   Rules: {len(ruleset.rules)}")
        print()


def run_ai_triage(
    findings: list[SecurityFinding],
    plugin: ParsedPlugin,
    provider: str,
    model: Optional[str],
    verbose: bool,
    quiet: bool,
    max_workers: int = 4,
    rate_limiter=None,
) -> Optional[list]:
    """
    Run AI-powered triaging on findings.
    
    Returns list of triaged findings or None on error.
    """
    import time
    
    try:
        from scanner.ai import AITriager, get_llm_provider, SUPPORTED_PROVIDERS
    except ImportError as e:
        if not quiet:
            print(f"\nAI triage requires LangChain. Install with:")
            print(f"  pip install langchain langchain-openai langchain-google-genai langchain-aws langchain-anthropic")
        return None
    
    # Get the actual model being used
    provider_config = SUPPORTED_PROVIDERS.get(provider)
    actual_model = model or (provider_config.default_model if provider_config else "unknown")
    
    if not quiet:
        print(f"\n{'='*60}")
        print("AI TRIAGE")
        print(f"{'='*60}")
        print(f"Provider: {provider}")
        print(f"Model: {actual_model}")
        print(f"Findings to triage: {len(findings)}")
        rpm_label = f"{rate_limiter.rpm}" if rate_limiter and rate_limiter.rpm > 0 else "unlimited"
        print(f"Workers: {max_workers} | RPM limit: {rpm_label}")
        print(f"{'='*60}")
    
    try:
        if not quiet:
            print(f"\n[1/3] Initializing {provider} LLM...")
        
        start_time = time.time()
        llm = get_llm_provider(provider, model)
        
        if not quiet:
            print(f"      LLM initialized successfully")
        
        triager = AITriager(
            llm,
            verbose=verbose,
            max_workers=max_workers,
            rate_limiter=rate_limiter,
        )
        
        # Build component contents map
        component_contents = {}
        for comp in plugin.components:
            if comp.content:
                component_contents[comp.name] = comp.content
        
        if not quiet:
            print(f"\n[2/3] Running AI triage on {len(findings)} findings...")
        
        # Triage findings
        triaged = triager.triage_findings(findings, component_contents)
        
        elapsed = time.time() - start_time
        
        if not quiet:
            print(f"      Triage complete in {elapsed:.1f}s")
            print(f"\n[3/3] Generating triage report...")
            print(triager.generate_triage_report(triaged))
        
        return triaged
        
    except ValueError as e:
        if not quiet:
            print(f"\n[ERROR] AI triage configuration error: {e}")
        return None
    except Exception as e:
        if verbose:
            print(f"\n[ERROR] AI triage failed:", file=sys.stderr)
            print(_sanitize_traceback(traceback.format_exc()), file=sys.stderr)
        elif not quiet:
            print(f"\n[ERROR] AI triage failed: {e}")
        return None


def run_ai_review(
    plugin: ParsedPlugin,
    provider: str,
    model: Optional[str],
    verbose: bool,
    quiet: bool,
    ai_only: bool = False,
    max_workers: int = 4,
    rate_limiter=None,
):
    """
    Run AI-powered security review on plugin.
    
    When ``ai_only`` is True, uses the per-component AIComponentScanner
    (one LLM call per component + cross-component analysis).
    Otherwise, uses the holistic AISecurityReviewer (single LLM call).
    
    Both paths enforce all 3 PromptGuard layers on every LLM call.
    
    Returns AIReviewResult or None on error.
    """
    import time
    
    try:
        from scanner.ai import (
            AISecurityReviewer,
            AIComponentScanner,
            get_llm_provider,
            SUPPORTED_PROVIDERS,
        )
    except ImportError as e:
        if not quiet:
            print(f"\nAI review requires LangChain. Install with:")
            print(f"  pip install langchain langchain-openai langchain-google-genai langchain-aws langchain-anthropic")
        return None
    
    # Get the actual model being used
    provider_config = SUPPORTED_PROVIDERS.get(provider)
    actual_model = model or (provider_config.default_model if provider_config else "unknown")
    
    mode_label = "PER-COMPONENT AI SCAN" if ai_only else "AI SECURITY REVIEW"
    
    if not quiet:
        print(f"\n{'='*60}")
        print(mode_label)
        print(f"{'='*60}")
        print(f"Provider: {provider}")
        print(f"Model: {actual_model}")
        print(f"Plugin: {plugin.manifest.name}")
        std = getattr(plugin, "standard_count", None)
        deep = getattr(plugin, "deep_count", None)
        total = len(plugin.components)
        if deep and deep > 0:
            print(f"Components to analyze: {total} ({std} standard + {deep} deep discovery)")
        else:
            print(f"Components to analyze: {total}")
        if ai_only:
            print(f"Mode: per-component (1 LLM call per component + cross-component)")
        rpm_label = f"{rate_limiter.rpm}" if rate_limiter and rate_limiter.rpm > 0 else "unlimited"
        print(f"Workers: {max_workers} | RPM limit: {rpm_label}")
        print(f"{'='*60}")
    
    try:
        if not quiet:
            print(f"\n[1/3] Initializing {provider} LLM...")
        
        start_time = time.time()
        llm = get_llm_provider(provider, model)
        
        if not quiet:
            print(f"      LLM initialized successfully")
            print(f"\n[2/3] Running AI security analysis...")
            if ai_only:
                print(f"      Scanning {len(plugin.components)} component(s) individually...", flush=True)
            else:
                print(f"      This may take 30-60 seconds depending on plugin size...")
        
        if ai_only:
            # Per-component scan with type-specific prompts
            scanner = AIComponentScanner(
                llm,
                verbose=verbose,
                max_workers=max_workers,
                rate_limiter=rate_limiter,
            )
            result = scanner.scan_plugin(plugin)
        else:
            # Holistic plugin review (existing behavior)
            reviewer = AISecurityReviewer(
                llm,
                verbose=verbose,
                rate_limiter=rate_limiter,
            )
            result = reviewer.review_plugin(plugin)
        
        elapsed = time.time() - start_time
        
        if not quiet:
            print(f"      Analysis complete in {elapsed:.1f}s")
            print(f"\n[3/3] Generating report...")
            if ai_only:
                scanner_for_report = AIComponentScanner(llm, verbose=False)
                print(scanner_for_report.generate_review_report(result))
            else:
                reviewer_for_report = AISecurityReviewer(llm, verbose=False)
                print(reviewer_for_report.generate_review_report(result))
        
        return result
        
    except ValueError as e:
        if not quiet:
            print(f"\n[ERROR] AI review configuration error: {e}")
        return None
    except Exception as e:
        if verbose:
            print(f"\n[ERROR] AI review failed:", file=sys.stderr)
            print(_sanitize_traceback(traceback.format_exc()), file=sys.stderr)
        elif not quiet:
            print(f"\n[ERROR] AI review failed: {e}")
        return None


def run_ai_review_triage(
    ai_review_result,
    plugin: ParsedPlugin,
    provider: str,
    model: Optional[str],
    verbose: bool,
    quiet: bool,
    threshold: float = 0.5,
    max_workers: int = 4,
    rate_limiter=None,
):
    """
    Run AI-powered triage on AI review findings to filter false positives.

    Returns a filtered list of SecurityIssue objects that passed triage,
    or None on error.
    """
    import time

    if not ai_review_result or not ai_review_result.issues:
        return None

    try:
        from scanner.ai import (
            AIReviewTriager,
            get_llm_provider,
        )
    except ImportError as e:
        if not quiet:
            print(f"\nAI review triage requires LangChain.")
        return None

    if not quiet:
        print(f"\n{'='*60}")
        print("AI REVIEW TRIAGE (second-opinion validation)")
        print(f"{'='*60}")
        print(f"Issues to validate: {len(ai_review_result.issues)}")
        print(f"Confidence threshold: {threshold:.0%}")
        print(f"{'='*60}")

    try:
        if not quiet:
            print(f"\n[1/2] Initializing triage LLM...")

        start_time = time.time()
        llm = get_llm_provider(provider, model)

        if not quiet:
            print(f"      LLM initialized")
            print(f"\n[2/2] Validating AI review findings...")

        triager = AIReviewTriager(
            llm,
            verbose=verbose,
            max_workers=max_workers,
            rate_limiter=rate_limiter,
        )
        triaged = triager.triage_issues(ai_review_result.issues, plugin)

        elapsed = time.time() - start_time

        if not quiet:
            print(f"      Triage complete in {elapsed:.1f}s")
            print(triager.generate_triage_report(triaged))

        # Filter: keep only true positives with evidence above the confidence threshold
        kept = [
            t.original
            for t in triaged
            if t.is_true_positive
            and t.confidence >= threshold
            and t.evidence
            and t.evidence.strip()
        ]

        # Update adjusted severities on the kept issues
        severity_map = {
            id(t.original): t.adjusted_severity
            for t in triaged
            if t.is_true_positive
            and t.confidence >= threshold
            and t.evidence
            and t.evidence.strip()
        }
        for issue in kept:
            adjusted = severity_map.get(id(issue))
            if adjusted:
                issue.severity = adjusted

        if not quiet:
            removed = len(ai_review_result.issues) - len(kept)
            print(
                f"\n      Kept {len(kept)} issue(s), "
                f"removed {removed} false positive(s)"
            )

        return kept

    except Exception as e:
        if verbose:
            print(f"\n[ERROR] AI review triage failed:", file=sys.stderr)
            print(_sanitize_traceback(traceback.format_exc()), file=sys.stderr)
        elif not quiet:
            print(f"\n[ERROR] AI review triage failed: {e}")
        return None


def _run_single_scan_pipeline(
    scanner: PluginScanner,
    plugin: ParsedPlugin,
    static_findings: list[SecurityFinding],
    ai_provider: str,
    ai_model: Optional[str],
    verbose: bool,
    quiet: bool,
    static: bool,
    ai_triage_threshold: float,
    workers: int,
    rate_limiter,
) -> tuple[list[SecurityFinding], str]:
    """
    Run the full AI review / triage / verdict pipeline for a single scan target.

    Returns (combined_findings, verdict) where verdict is "safe" or "not_safe".
    """
    combined_findings = list(static_findings)

    # ── AI component scan ──
    ai_review_result = run_ai_review(
        plugin,
        ai_provider,
        ai_model,
        verbose,
        quiet,
        ai_only=True,
        max_workers=workers,
        rate_limiter=rate_limiter,
    )

    # ── AI triage on AI review findings ──
    ai_issues_to_merge: list = []
    if ai_review_result and ai_review_result.issues:
        validated = run_ai_review_triage(
            ai_review_result,
            plugin,
            ai_provider,
            ai_model,
            verbose,
            quiet,
            threshold=ai_triage_threshold,
            max_workers=workers,
            rate_limiter=rate_limiter,
        )
        ai_issues_to_merge = validated if validated is not None else ai_review_result.issues

    for issue in ai_issues_to_merge:
        sev = issue.severity.lower()
        if sev not in ("critical", "high", "medium", "low"):
            sev = "medium"

        comp_type = "skill"
        comp_name = issue.component or "unknown"
        comp_path = ""
        for comp in plugin.components:
            if comp.name == comp_name or comp_name in (comp.name, comp.path or ""):
                comp_type = comp.type
                comp_path = comp.path or ""
                comp_name = comp.name
                break

        ai_finding = SecurityFinding(
            severity=sev,
            rule_id=f"ai-review-{issue.category}",
            rule_name=f"[AI] {issue.title}",
            message=issue.description,
            component_type=comp_type,
            component_name=comp_name,
            component_path=issue.file_path or comp_path,
            recommendation=issue.remediation,
            section=issue.section,
            category=issue.category,
            line=issue.line_number,
            snippet=issue.code_snippet,
        )
        combined_findings.append(ai_finding)

    if ai_issues_to_merge and not quiet:
        print(f"\n  Merged {len(ai_issues_to_merge)} AI review issue(s) into findings")

    # ── AI triage on static findings (optional) ──
    if static and combined_findings:
        only_static = [
            f for f in combined_findings
            if not f.rule_id.startswith("ai-review-")
        ]
        if only_static:
            ai_triage_results = run_ai_triage(
                only_static,
                plugin,
                ai_provider,
                ai_model,
                verbose,
                quiet,
                max_workers=workers,
                rate_limiter=rate_limiter,
            )

            if ai_triage_results:
                threshold = ai_triage_threshold
                before_count = len(only_static)
                kept_originals = set()
                for t in ai_triage_results:
                    has_evidence = bool(t.evidence and t.evidence.strip())
                    if t.is_true_positive and t.confidence >= threshold and has_evidence:
                        kept_originals.add(id(t.original))

                combined_findings = [
                    f for f in combined_findings
                    if f.rule_id.startswith("ai-review-") or id(f) in kept_originals
                ]
                removed = before_count - sum(
                    1 for f in combined_findings
                    if not f.rule_id.startswith("ai-review-")
                )
                if not quiet:
                    print(
                        f"\n  Static triage filter: removed {removed} of "
                        f"{before_count} static finding(s) "
                        f"(without evidence or below {threshold:.0%} threshold)"
                    )

    # ── Compute safety verdict ──
    malicious_count = sum(
        1 for f in combined_findings if f.section == "malicious"
    )
    verdict = "not_safe" if malicious_count > 0 else "safe"

    if not quiet:
        print(f"\n{'='*60}")
        if verdict == "safe":
            print("VERDICT: SAFE — No malicious findings detected")
        else:
            print(f"VERDICT: NOT SAFE — {malicious_count} malicious finding(s) detected")
        print(f"{'='*60}")

    return combined_findings, verdict


def _run_ci_pr_pipeline(args, scanner, config, rate_limiter) -> None:
    """Run the CI/PR scanning pipeline: detect changes, resolve targets, diff scan."""
    import time

    from scanner.ci.changed_files import get_changed_files
    from scanner.ci.target_resolver import resolve_targets_with_llm, resolve_targets_heuristic
    from scanner.ci.diff_scanner import DiffScanner
    from scanner.ci.pr_reporter import (
        generate_pr_comment,
        generate_pr_sarif,
        generate_pr_json,
        write_pr_comment,
        write_pr_findings_txt,
        write_pr_sarif,
        write_pr_json,
    )

    repo_root = str(Path(args.plugin_path or ".").resolve())
    start_time = time.time()

    if not args.quiet:
        print(f"\n{'='*60}")
        print("CI/PR SECURITY SCAN")
        print(f"{'='*60}")

    # ── Step 1: Get changed files ──
    if not args.quiet:
        print(f"\n[1/4] Fetching changed files...")

    try:
        changed_files = get_changed_files(
            repo_root,
            github_token=args.github_token,
            pr_number=args.pr_number,
            base_ref=args.base_ref,
            head_ref=args.head_ref,
        )
    except Exception as e:
        print(f"Error: Failed to get changed files: {e}", file=sys.stderr)
        sys.exit(1)

    if not changed_files:
        if not args.quiet:
            print("  No changed files detected. Nothing to scan.")
        sys.exit(0)

    if not args.quiet:
        print(f"  Found {len(changed_files)} changed file(s)")
        if args.verbose:
            for cf in changed_files:
                print(f"    [{cf.status.upper()}] {cf.path}")

    # ── Step 2: Resolve targets with LLM ──
    if not args.quiet:
        print(f"\n[2/4] Resolving affected skills/plugins...")

    try:
        from scanner.ai.providers import get_llm_provider
        llm = get_llm_provider(args.ai_provider, args.ai_model)

        affected_targets = resolve_targets_with_llm(
            changed_files, repo_root, llm,
            verbose=args.verbose,
            rate_limiter=rate_limiter,
        )
    except Exception as e:
        if args.verbose:
            print(f"  [WARNING] LLM resolution failed: {e}")
            print("  Falling back to heuristic resolution...")
        affected_targets = resolve_targets_heuristic(changed_files, repo_root)

    if not affected_targets:
        if not args.quiet:
            print("  No skills or plugins affected by this PR. Nothing to scan.")
        sys.exit(0)

    if not args.quiet:
        print(f"  Found {len(affected_targets)} affected target(s):")
        for i, t in enumerate(affected_targets, 1):
            print(f"    {i}. [{t.target_type}] {t.name} ({t.change_scenario})")
            if args.verbose and t.reasoning:
                print(f"       Reason: {t.reasoning}")

    # ── Step 3: Differential scan ──
    if not args.quiet:
        print(f"\n[3/4] Running differential security scan...")

    base_ref = args.base_ref or os.environ.get("GITHUB_BASE_REF", "")
    head_ref = args.head_ref or os.environ.get("GITHUB_SHA", "HEAD")

    if not base_ref:
        print("Error: --base-ref is required for differential scanning", file=sys.stderr)
        sys.exit(1)

    try:
        from scanner.ai.providers import get_llm_provider
        llm = get_llm_provider(args.ai_provider, args.ai_model)
    except Exception as e:
        print(f"Error: Failed to initialize LLM: {e}", file=sys.stderr)
        sys.exit(1)

    diff_scanner = DiffScanner(
        scanner=scanner,
        llm=llm,
        ai_provider=args.ai_provider,
        ai_model=args.ai_model,
        verbose=args.verbose,
        quiet=args.quiet,
        static=args.static,
        ai_triage_threshold=args.ai_triage_threshold,
        workers=args.workers,
        rate_limiter=rate_limiter,
    )

    pr_result = diff_scanner.scan_pr(
        affected_targets, base_ref, head_ref, repo_root,
    )

    # Attach repository and PR context for reports
    pr_result.summary.repository = os.environ.get("GITHUB_REPOSITORY", "")
    pr_result.summary.pr_number = getattr(args, "pr_number", None)
    pr_result.summary.base_ref = base_ref
    pr_result.summary.head_ref = head_ref

    # ── Step 4: Generate reports ──
    if not args.quiet:
        elapsed = time.time() - start_time
        print(f"\n[4/4] Generating reports... (scan took {elapsed:.1f}s)")

    s = pr_result.summary
    if not args.quiet:
        print(f"\n{'='*60}")
        print("CI SCAN RESULTS")
        print(f"{'='*60}")
        print(f"  Targets scanned: {s.total_targets_affected}")
        print(f"  New vulnerabilities: {s.new_count}")
        print(f"  Worsened vulnerabilities: {s.worsened_count}")
        print(f"  Resolved (fixed): {s.resolved_count}")
        print(f"  Unchanged: {s.unchanged_count}")
        print(f"  Risk delta: {s.overall_risk_delta}")
        print(f"  Verdict: {s.verdict.upper()}")
        print(f"{'='*60}")

    # Write PR comment
    if args.pr_comment_file:
        try:
            write_pr_comment(pr_result, args.pr_comment_file)
            if not args.quiet:
                print(f"\nPR comment written to: {args.pr_comment_file}")
        except Exception as e:
            if args.verbose:
                print(f"\n[WARNING] Failed to write PR comment: {e}")

    # Write output file (SARIF or JSON) and findings text artifact
    if args.output_file:
        try:
            out_path = Path(args.output_file)
            if args.output == "sarif":
                write_pr_sarif(pr_result, args.output_file)
            else:
                write_pr_json(pr_result, args.output_file)
            findings_txt_path = str(out_path.parent / "pr-scan-findings.txt")
            write_pr_findings_txt(pr_result, findings_txt_path)
            if not args.quiet:
                print(f"Report written to: {args.output_file}, {findings_txt_path}")
        except Exception as e:
            if args.verbose:
                print(f"\n[WARNING] Failed to write report: {e}")
    else:
        # Print to stdout
        if args.output == "sarif":
            report = generate_pr_sarif(pr_result)
        else:
            report = generate_pr_json(pr_result)

        if not args.quiet:
            print(f"\n{'='*60}")
            print("REPORT OUTPUT")
            print(f"{'='*60}")
        print(json.dumps(report, indent=2))

    # Exit code based on --fail-on or verdict
    if args.fail_on:
        severity_order = ["critical", "high", "medium", "low"]
        threshold_idx = severity_order.index(args.fail_on)

        for tr in pr_result.target_results:
            for impact_f in tr.new_findings + tr.worsened_findings:
                finding_idx = severity_order.index(impact_f.severity)
                if finding_idx <= threshold_idx:
                    if args.verbose:
                        print(f"\nFailing: {impact_f.severity} finding: {impact_f.finding.rule_name}")
                    sys.exit(1)

    if s.verdict == "fail":
        sys.exit(1)

    sys.exit(0)


def main():
    """Main CLI entry point."""
    # Check if first arg is 'rules' subcommand
    if len(sys.argv) > 1 and sys.argv[1] == "rules":
        return handle_rules_cli()
    
    parser = argparse.ArgumentParser(
        description="Claude Code Plugin Security Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan a local plugin (AI scan is the default)
  python -m scanner /path/to/plugin --ai-provider openai

  # Scan with Gemini
  python -m scanner /path/to/plugin --ai-provider gemini

  # Scan with Claude via Bedrock
  python -m scanner /path/to/plugin --ai-provider bedrock

  # Also run static rule-based analysis alongside AI
  python -m scanner /path/to/plugin --static --ai-provider openai

  # Discover and scan all plugins/skills in a repo
  python -m scanner /path/to/repo --discover --ai-provider openai

  # Scan a marketplace
  python -m scanner --marketplace https://github.com/org/plugins --ai-provider openai

  # Output as SARIF for CI/CD
  python -m scanner /path/to/plugin --output sarif --output-file results.sarif

  # Generate visualization data
  python -m scanner /path/to/plugin --output graph --output-file graph.json

  # List all rules
  python -m scanner rules --list

  # Show rules by category
  python -m scanner rules --category prompt-injection

  # Export rules to JSON
  python -m scanner rules --export rules.json

Environment variables for AI providers:
  OPENAI_API_KEY        - OpenAI API key
  AZURE_OPENAI_API_KEY  - Azure OpenAI API key
  GOOGLE_API_KEY        - Google Gemini API key
  AWS_ACCESS_KEY_ID     - AWS credentials for Bedrock
  ANTHROPIC_API_KEY     - Anthropic API key
        """
    )
    
    # Main scanning arguments
    parser.add_argument(
        "plugin_path",
        nargs="?",
        help="Path to plugin directory to scan"
    )
    
    parser.add_argument(
        "--marketplace", "-m",
        help="Git URL of marketplace to scan"
    )
    
    parser.add_argument(
        "--output", "-o",
        choices=["json", "sarif", "graph"],
        default="json",
        help="Output format (default: json)"
    )
    
    parser.add_argument(
        "--output-file", "-f",
        help="Output file path (prints to stdout if not specified)"
    )
    
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose output"
    )
    
    parser.add_argument(
        "--quiet", "-q",
        action="store_true",
        help="Suppress summary output"
    )
    
    parser.add_argument(
        "--fail-on",
        choices=["critical", "high", "medium", "low"],
        default=None,
        help="Exit with non-zero code if findings of this severity or higher exist"
    )
    
    # Analysis options
    parser.add_argument(
        "--static",
        action="store_true",
        help="Also run static rule-based analysis (AI scan is the default)"
    )
    
    parser.add_argument(
        "--ai-provider",
        choices=["openai", "azure", "gemini", "bedrock", "anthropic", "xai"],
        default=None,
        help="AI provider to use (default: from config.yaml, or openai)"
    )
    
    parser.add_argument(
        "--ai-model",
        help="AI model to use (uses provider default if not specified)"
    )
    
    parser.add_argument(
        "--workers", "-w",
        type=int,
        default=4,
        help="Max parallel LLM calls for AI scanning (default: 4)"
    )
    
    parser.add_argument(
        "--rpm",
        type=int,
        default=0,
        help=(
            "Max LLM requests per minute. 0 = unlimited (default). "
            "Typical limits: Gemini free=15, OpenAI Tier1=500"
        )
    )
    
    parser.add_argument(
        "--ai-triage-threshold",
        type=float,
        default=0.5,
        help=(
            "Minimum confidence to keep a triaged finding (0.0-1.0, default: 0.5). "
            "Findings below this threshold are filtered out during AI triage."
        )
    )
    
    # Configuration options
    parser.add_argument(
        "--config",
        help="Path to config.yaml file (auto-discovers if not specified)"
    )
    
    parser.add_argument(
        "--mode",
        choices=["strict", "balanced", "permissive"],
        default=None,
        help="Scan mode: strict (audit), balanced (default), permissive (quick)"
    )
    
    parser.add_argument(
        "--discover",
        action="store_true",
        default=False,
        help="Recursively discover all plugins and skills in the given directory and scan each one",
    )
    
    # CI/PR scanning mode
    parser.add_argument(
        "--ci-pr",
        action="store_true",
        default=False,
        help="CI mode: scan only skills/plugins affected by PR changes",
    )
    parser.add_argument(
        "--base-ref",
        default=None,
        help="Base git ref for comparison (default: auto-detect from GITHUB_BASE_REF)",
    )
    parser.add_argument(
        "--head-ref",
        default=None,
        help="Head git ref for comparison (default: current HEAD)",
    )
    parser.add_argument(
        "--github-token",
        default=None,
        help="GitHub token for API access (default: GITHUB_TOKEN env var)",
    )
    parser.add_argument(
        "--pr-number",
        type=int,
        default=None,
        help="PR number to scan (default: auto-detect from CI environment)",
    )
    parser.add_argument(
        "--pr-comment-file",
        default=None,
        help="Write PR comment markdown to this file",
    )
    
    args = parser.parse_args()
    
    # Validate arguments for scan
    if not args.plugin_path and not args.marketplace and not args.ci_pr:
        parser.error("Either plugin_path, --marketplace, or --ci-pr is required")
    
    # Load configuration
    cli_overrides = {}
    if args.mode:
        cli_overrides["scan_mode"] = args.mode
    if args.verbose:
        cli_overrides.setdefault("output", {})["verbose"] = True
    
    config = load_config(
        config_path=args.config,
        cli_overrides=cli_overrides if cli_overrides else None,
    )

    # Resolve effective AI provider and model:
    # Priority: CLI arg > config.yaml ai section > built-in default
    args.ai_provider = args.ai_provider or config.ai.provider or "openai"
    args.ai_model = args.ai_model or config.ai.model

    if args.verbose:
        print(f"Scan mode: {config.scan_mode}")
    
    scanner = PluginScanner(verbose=args.verbose, config=config)
    
    try:
        from scanner.ai.providers import RateLimiter
        rate_limiter = RateLimiter(rpm=args.rpm)

        # ── CI/PR mode: scan only affected skills/plugins ──
        if args.ci_pr:
            _run_ci_pr_pipeline(args, scanner, config, rate_limiter)
            return

        # ── Discover mode: scan multiple plugins/skills ──
        if args.discover:
            from scanner.utils.discovery import discover_targets

            plugin_path = Path(args.plugin_path)
            if not plugin_path.exists():
                print(f"Error: Path does not exist: {args.plugin_path}", file=sys.stderr)
                sys.exit(1)

            targets = discover_targets(str(plugin_path))
            if not targets:
                print("No plugins or skills discovered in the given path", file=sys.stderr)
                sys.exit(1)

            if not args.quiet:
                print(f"\n{'='*60}")
                print(f"DISCOVERY: Found {len(targets)} target(s)")
                print(f"{'='*60}")
                for i, t in enumerate(targets, 1):
                    print(f"  {i}. [{t.target_type}] {t.name} — {t.path}")
                print()

            scan_results: list[dict] = []
            for idx, target in enumerate(targets, 1):
                if not args.quiet:
                    print(f"\n{'#'*60}")
                    print(f"# SCANNING {idx}/{len(targets)}: {target.name} ({target.target_type})")
                    print(f"{'#'*60}")

                try:
                    plugin, findings = scanner.scan_plugin(
                        target.path,
                        skip_static_analysis=not args.static,
                    )
                    if not args.quiet and args.static:
                        print_summary(findings)

                    combined_findings, verdict = _run_single_scan_pipeline(
                        scanner=scanner,
                        plugin=plugin,
                        static_findings=findings,
                        ai_provider=args.ai_provider,
                        ai_model=args.ai_model,
                        verbose=args.verbose,
                        quiet=args.quiet,
                        static=args.static,
                        ai_triage_threshold=args.ai_triage_threshold,
                        workers=args.workers,
                        rate_limiter=rate_limiter,
                    )

                    scan_results.append({
                        "plugin": plugin,
                        "findings": combined_findings,
                        "verdict": verdict,
                        "target_type": target.target_type,
                    })
                except Exception as e:
                    if args.verbose:
                        print(_sanitize_traceback(traceback.format_exc()), file=sys.stderr)
                    elif not args.quiet:
                        print(f"\n  [ERROR] Failed to scan {target.name}: {e}")

            if not scan_results:
                print("All scans failed", file=sys.stderr)
                sys.exit(1)

            # ── Multi-scan report ──
            report = scanner.generate_multi_report(
                scan_results,
                args.output,
                args.output_file,
            )

            # CSV for multi-scan
            all_csv_findings: list[SecurityFinding] = []
            for sr in scan_results:
                all_csv_findings.extend(sr["findings"])
            if all_csv_findings:
                if args.output_file:
                    primary = Path(args.output_file)
                    csv_path = str(primary.with_suffix(".csv"))
                else:
                    csv_path = None
                try:
                    csv_file = scanner.csv_reporter.generate_multi(
                        scan_results, csv_path
                    )
                    if not args.quiet:
                        print(f"\nCSV report saved to: {csv_file}")
                except Exception as e:
                    if args.verbose:
                        print(f"\n[WARNING] CSV generation failed: {e}")

            if not args.output_file:
                if not args.quiet:
                    print("\n" + "=" * 60)
                    print("REPORT OUTPUT")
                    print("=" * 60)
                print(json.dumps(report, indent=2))

            # fail-on check across all scans
            if args.fail_on:
                severity_order = ["critical", "high", "medium", "low"]
                threshold_idx = severity_order.index(args.fail_on)
                for sr in scan_results:
                    for finding in sr["findings"]:
                        finding_idx = severity_order.index(finding.severity)
                        if finding_idx <= threshold_idx:
                            if args.verbose:
                                print(f"\nFailing due to {finding.severity} finding: {finding.rule_name}")
                            sys.exit(1)

            sys.exit(0)

        # ── Single-target mode (original behavior) ──
        if args.marketplace:
            if not validate_git_url(args.marketplace):
                print(f"Error: Invalid marketplace URL: {args.marketplace}", file=sys.stderr)
                sys.exit(1)
            
            results = scanner.scan_marketplace(
                args.marketplace,
                skip_static_analysis=not args.static,
            )
            
            all_findings: list[SecurityFinding] = []
            for plugin, findings in results:
                all_findings.extend(findings)
            
            if not args.quiet and args.static:
                print_summary(all_findings)
            
            if results:
                plugin, findings = results[0]
                combined_findings = all_findings
            else:
                print("No plugins found in marketplace", file=sys.stderr)
                sys.exit(1)
        else:
            plugin_path = Path(args.plugin_path)
            
            if not plugin_path.exists():
                print(f"Error: Plugin path does not exist: {args.plugin_path}", file=sys.stderr)
                sys.exit(1)
            
            plugin, findings = scanner.scan_plugin(
                str(plugin_path),
                skip_static_analysis=not args.static,
            )
            combined_findings = findings
            
            if not args.quiet and args.static:
                print_summary(findings)

        # Run the AI review / triage / verdict pipeline
        combined_findings, verdict = _run_single_scan_pipeline(
            scanner=scanner,
            plugin=plugin,
            static_findings=combined_findings,
            ai_provider=args.ai_provider,
            ai_model=args.ai_model,
            verbose=args.verbose,
            quiet=args.quiet,
            static=args.static,
            ai_triage_threshold=args.ai_triage_threshold,
            workers=args.workers,
            rate_limiter=rate_limiter,
        )

        report = scanner.generate_report(
            plugin,
            combined_findings,
            args.output,
            args.output_file,
            verdict=verdict,
        )
        
        if combined_findings:
            if args.output_file:
                primary = Path(args.output_file)
                csv_path = str(primary.with_suffix(".csv"))
            else:
                csv_path = None
            
            try:
                csv_file = scanner.csv_reporter.generate(
                    plugin, combined_findings, csv_path
                )
                if not args.quiet:
                    print(f"\nCSV report saved to: {csv_file}")
            except Exception as e:
                if args.verbose:
                    print(f"\n[WARNING] CSV generation failed: {e}")
        
        if not args.output_file:
            if not args.quiet:
                print("\n" + "=" * 60)
                print("REPORT OUTPUT")
                print("=" * 60)
            print(json.dumps(report, indent=2))
        
        if args.fail_on:
            severity_order = ["critical", "high", "medium", "low"]
            threshold_idx = severity_order.index(args.fail_on)
            
            for finding in combined_findings:
                finding_idx = severity_order.index(finding.severity)
                if finding_idx <= threshold_idx:
                    if args.verbose:
                        print(f"\nFailing due to {finding.severity} finding: {finding.rule_name}")
                    sys.exit(1)
        
        sys.exit(0)
    
    except ValueError as e:
        print(f"Validation error: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        error_msg = str(e)
        if not args.verbose:
            print("Error: An error occurred during scanning. Use --verbose for details.", file=sys.stderr)
        else:
            print(f"Error: {error_msg}", file=sys.stderr)
            print(_sanitize_traceback(traceback.format_exc()), file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
