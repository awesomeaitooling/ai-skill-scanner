"""
Cross-Skill Analyzer — Detects coordinated attack patterns across components.

Checks:
- Data relay chains (skill A writes, skill B reads and sends)
- Shared external URLs across components
- Complementary hook triggers (one hook enables another's attack)
- Coordinated privilege escalation
- Shared secrets / tokens across components
"""

import re
from typing import List, Dict, Set, Tuple, Optional
from collections import defaultdict

from .plugin_parser import PluginComponent, ParsedPlugin
from .skill_analyzer import SecurityFinding


class CrossSkillAnalyzer:
    """Analyzes relationships between components for coordinated attacks."""

    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.findings: List[SecurityFinding] = []

    def analyze(self, plugin: ParsedPlugin) -> List[SecurityFinding]:
        """Analyze all plugin components for cross-component attack patterns."""
        self.findings = []
        components = plugin.components

        if len(components) < 2:
            return self.findings

        if self.verbose:
            print(f"    Cross-skill analysis: {len(components)} components")

        # Extract data from all components
        url_map = self._extract_urls(components)
        file_ops_map = self._extract_file_operations(components)
        env_var_map = self._extract_env_vars(components)
        hook_events = self._extract_hook_events(components)

        # Run cross-component checks
        self._check_shared_urls(url_map, components)
        self._check_data_relay(file_ops_map, components)
        self._check_shared_env_vars(env_var_map, components)
        self._check_hook_chains(hook_events, components)
        self._check_write_read_chains(components)

        if self.verbose:
            print(f"    Cross-skill findings: {len(self.findings)}")

        return self.findings

    # ---------------------------------------------------------------
    # Extraction
    # ---------------------------------------------------------------
    def _extract_urls(
        self, components: List[PluginComponent]
    ) -> Dict[str, List[str]]:
        """Extract external URLs referenced by each component."""
        url_pattern = re.compile(r"https?://[^\s\"'`)\]]+", re.IGNORECASE)
        url_map: Dict[str, List[str]] = {}

        for comp in components:
            content = comp.content or ""
            urls = url_pattern.findall(content)
            if urls:
                url_map[comp.name] = urls

        return url_map

    def _extract_file_operations(
        self, components: List[PluginComponent]
    ) -> Dict[str, Dict[str, List[str]]]:
        """Extract file read/write operations from components."""
        ops_map: Dict[str, Dict[str, List[str]]] = {}

        read_patterns = [
            r"open\s*\([^)]*[\"']r[\"']",
            r"\.read\s*\(",
            r"pathlib\.\w+\([^)]+\)\.read_text",
            r"read\s+(?:file|from|content)",
        ]
        write_patterns = [
            r"open\s*\([^)]*[\"'][wa][\"']",
            r"\.write\s*\(",
            r"pathlib\.\w+\([^)]+\)\.write_text",
            r"write\s+(?:to|file|output)",
        ]

        for comp in components:
            content = comp.content or ""
            reads = []
            writes = []

            for pat in read_patterns:
                if re.search(pat, content, re.IGNORECASE):
                    reads.append(pat)
            for pat in write_patterns:
                if re.search(pat, content, re.IGNORECASE):
                    writes.append(pat)

            if reads or writes:
                ops_map[comp.name] = {"reads": reads, "writes": writes}

        return ops_map

    def _extract_env_vars(
        self, components: List[PluginComponent]
    ) -> Dict[str, Set[str]]:
        """Extract environment variable references from components."""
        env_pattern = re.compile(
            r"(?:os\.environ\.get|os\.getenv|process\.env)\s*\(\s*[\"']([^\"']+)[\"']",
            re.IGNORECASE,
        )
        env_map: Dict[str, Set[str]] = {}

        for comp in components:
            content = comp.content or ""
            vars_found = set(env_pattern.findall(content))
            # Also check for $ENV_VAR patterns in bash/markdown
            shell_vars = set(re.findall(r"\$\{?([A-Z_][A-Z0-9_]+)\}?", content))
            vars_found.update(shell_vars)
            if vars_found:
                env_map[comp.name] = vars_found

        return env_map

    def _extract_hook_events(
        self, components: List[PluginComponent]
    ) -> Dict[str, Dict]:
        """Extract hook event configurations."""
        hook_map: Dict[str, Dict] = {}

        for comp in components:
            if comp.type != "hook":
                continue
            event = comp.metadata.get("event", "")
            pattern = comp.metadata.get("pattern", "")
            hook_map[comp.name] = {
                "event": event,
                "pattern": pattern,
                "metadata": comp.metadata,
            }

        return hook_map

    # ---------------------------------------------------------------
    # Cross-component checks
    # ---------------------------------------------------------------
    def _check_shared_urls(
        self, url_map: Dict[str, List[str]], components: List[PluginComponent]
    ) -> None:
        """Check for suspicious shared URLs across components."""
        # Build URL -> components index
        url_to_comps: Dict[str, List[str]] = defaultdict(list)
        for comp_name, urls in url_map.items():
            for url in urls:
                # Normalize URL
                base_url = url.split("?")[0].rstrip("/")
                url_to_comps[base_url].append(comp_name)

        # Flag URLs shared across 2+ components
        for url, comp_names in url_to_comps.items():
            if len(set(comp_names)) >= 2:
                # Skip common benign URLs
                if any(domain in url for domain in [
                    "github.com", "npmjs.com", "pypi.org", "owasp.org",
                    "docs.", "documentation", "example.com", "localhost"
                ]):
                    continue

                self.findings.append(SecurityFinding(
                    severity="medium",
                    rule_id="cross-shared-url",
                    rule_name="Shared External URL Across Components",
                    message=(
                        f"URL '{url[:80]}' is referenced by multiple components: "
                        f"{', '.join(set(comp_names))}. This could indicate coordinated external communication."
                    ),
                    component_type="plugin",
                    component_name=comp_names[0],
                    component_path="",
                    recommendation="Review whether multiple components need access to the same external URL",
                ))

    def _check_data_relay(
        self,
        file_ops_map: Dict[str, Dict[str, List[str]]],
        components: List[PluginComponent],
    ) -> None:
        """Check for data relay chains (comp A writes, comp B reads+sends)."""
        writers = [name for name, ops in file_ops_map.items() if ops.get("writes")]
        readers = [name for name, ops in file_ops_map.items() if ops.get("reads")]

        if not writers or not readers:
            return

        # Check if any reader also has network access
        for comp in components:
            if comp.name not in readers:
                continue
            content = comp.content or ""
            has_network = bool(re.search(
                r"(?:requests\.|urllib|httpx|fetch|curl|wget|socket)",
                content, re.IGNORECASE
            ))

            if has_network:
                writing_comps = [w for w in writers if w != comp.name]
                if writing_comps:
                    self.findings.append(SecurityFinding(
                        severity="high",
                        rule_id="cross-data-relay",
                        rule_name="Cross-Component Data Relay Chain",
                        message=(
                            f"Potential data relay: {', '.join(writing_comps)} write(s) files, "
                            f"while '{comp.name}' reads files AND has network access. "
                            "Data written by one component may be exfiltrated by another."
                        ),
                        component_type=comp.type,
                        component_name=comp.name,
                        component_path=comp.path,
                        recommendation="Review the data flow between components; ensure no sensitive data is relayed externally",
                    ))

    def _check_shared_env_vars(
        self,
        env_map: Dict[str, Set[str]],
        components: List[PluginComponent],
    ) -> None:
        """Check for shared sensitive env vars across components."""
        sensitive_patterns = {"key", "secret", "token", "password", "credential", "auth"}

        # Build var -> components index
        var_to_comps: Dict[str, List[str]] = defaultdict(list)
        for comp_name, vars_set in env_map.items():
            for var in vars_set:
                var_to_comps[var].append(comp_name)

        for var, comp_names in var_to_comps.items():
            if len(set(comp_names)) < 2:
                continue
            var_lower = var.lower()
            if any(p in var_lower for p in sensitive_patterns):
                self.findings.append(SecurityFinding(
                    severity="medium",
                    rule_id="cross-shared-secret",
                    rule_name="Shared Sensitive Environment Variable",
                    message=(
                        f"Sensitive env var '{var}' is accessed by multiple components: "
                        f"{', '.join(set(comp_names))}. Compromise of one component leaks the credential to others."
                    ),
                    component_type="plugin",
                    component_name=comp_names[0],
                    component_path="",
                    recommendation="Use component-specific credentials; minimize shared secret access",
                ))

    def _check_hook_chains(
        self,
        hook_events: Dict[str, Dict],
        components: List[PluginComponent],
    ) -> None:
        """Check for complementary hook triggers that could enable attack chains."""
        if len(hook_events) < 2:
            return

        # Check if multiple hooks target the same event
        event_hooks: Dict[str, List[str]] = defaultdict(list)
        for hook_name, info in hook_events.items():
            event = info.get("event", "")
            if event:
                event_hooks[event].append(hook_name)

        for event, hooks in event_hooks.items():
            if len(hooks) >= 2:
                self.findings.append(SecurityFinding(
                    severity="medium",
                    rule_id="cross-competing-hooks",
                    rule_name="Multiple Hooks on Same Event",
                    message=(
                        f"Multiple hooks ({', '.join(hooks)}) trigger on the same event '{event}'. "
                        "They may interfere with each other or create unintended behavior chains."
                    ),
                    component_type="hook",
                    component_name=hooks[0],
                    component_path="",
                    recommendation="Review hook execution order and potential interactions",
                ))

    def _check_write_read_chains(self, components: List[PluginComponent]) -> None:
        """Check for components that write to shared temp/data directories."""
        # Shared directory patterns
        shared_dirs = ["/tmp/", "/var/tmp/", "~/.cache/", "~/.local/share/"]

        writers: Dict[str, List[str]] = defaultdict(list)  # dir -> comp names
        readers: Dict[str, List[str]] = defaultdict(list)

        for comp in components:
            content = comp.content or ""
            for d in shared_dirs:
                if d in content:
                    if re.search(r"(?:write|open.*[\"']w|>)", content, re.IGNORECASE):
                        writers[d].append(comp.name)
                    if re.search(r"(?:read|open.*[\"']r|<|cat\s)", content, re.IGNORECASE):
                        readers[d].append(comp.name)

        for d in shared_dirs:
            w = set(writers.get(d, []))
            r = set(readers.get(d, []))
            overlap = w & r
            cross = w - r  # writers that don't read (someone else reads)
            cross_readers = r - w  # readers that don't write

            if cross and cross_readers:
                self.findings.append(SecurityFinding(
                    severity="medium",
                    rule_id="cross-shared-directory",
                    rule_name="Shared Directory Access Pattern",
                    message=(
                        f"Components {', '.join(cross)} write to '{d}' while "
                        f"{', '.join(cross_readers)} read from it. "
                        "This shared directory pattern could enable data relay."
                    ),
                    component_type="plugin",
                    component_name=list(cross)[0],
                    component_path="",
                    recommendation="Use isolated directories per component; avoid shared temp paths",
                ))
