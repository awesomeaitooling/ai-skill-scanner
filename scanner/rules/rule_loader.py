"""
YAML Rule Loader

Loads security rules from YAML files and provides an API for querying them.
"""

import re
import yaml
from pathlib import Path
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Pattern, Set, Any


@dataclass
class SecurityRule:
    """Represents a single security rule loaded from YAML."""
    
    id: str
    name: str
    description: str
    severity: str  # critical, high, medium, low
    category: str
    pattern: str
    compiled_pattern: Pattern
    recommendation: str
    pattern_flags: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    enabled: bool = True
    false_positive_note: Optional[str] = None
    # New fields for scoping and false-positive reduction
    file_types: List[str] = field(default_factory=list)  # e.g. ["python", "bash", "markdown"]
    components: List[str] = field(default_factory=list)   # e.g. ["skill", "script", "hook"]
    exclude_patterns: List[str] = field(default_factory=list)
    _compiled_excludes: List[Pattern] = field(default_factory=list, repr=False)
    
    def match(self, content: str) -> List[re.Match]:
        """Find all matches of this rule in the content, filtering out exclude patterns."""
        if not self.enabled:
            return []
        raw_matches = list(self.compiled_pattern.finditer(content))
        if not self._compiled_excludes:
            return raw_matches
        # Filter out matches that hit an exclude pattern
        filtered = []
        for m in raw_matches:
            matched_text = m.group()
            excluded = False
            for exc in self._compiled_excludes:
                if exc.search(matched_text):
                    excluded = True
                    break
            if not excluded:
                filtered.append(m)
        return filtered
    
    def applies_to_file_type(self, file_type: str) -> bool:
        """Check if this rule applies to a given file type. Empty list means all types."""
        if not self.file_types:
            return True
        return file_type.lower() in [ft.lower() for ft in self.file_types]
    
    def applies_to_component(self, component_type: str) -> bool:
        """Check if this rule applies to a given component type. Empty list means all."""
        if not self.components:
            return True
        return component_type.lower() in [ct.lower() for ct in self.components]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert rule to dictionary for serialization."""
        result = {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "severity": self.severity,
            "category": self.category,
            "pattern": self.pattern,
            "recommendation": self.recommendation,
            "references": self.references,
            "tags": self.tags,
            "enabled": self.enabled,
        }
        if self.file_types:
            result["file_types"] = self.file_types
        if self.components:
            result["components"] = self.components
        if self.exclude_patterns:
            result["exclude_patterns"] = self.exclude_patterns
        return result


@dataclass
class RuleSet:
    """Represents a set of rules loaded from a YAML file."""
    
    name: str
    description: str
    version: str
    author: str
    category: str
    rules: List[SecurityRule] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert ruleset to dictionary for serialization."""
        return {
            "name": self.name,
            "description": self.description,
            "version": self.version,
            "author": self.author,
            "category": self.category,
            "rules": [r.to_dict() for r in self.rules],
        }


class RuleLoader:
    """Loads and manages security rules from YAML files."""
    
    # Mapping of string flags to re module constants
    FLAG_MAP = {
        "IGNORECASE": re.IGNORECASE,
        "MULTILINE": re.MULTILINE,
        "DOTALL": re.DOTALL,
    }
    
    # Valid severity levels
    SEVERITY_LEVELS = {"critical", "high", "medium", "low"}
    
    # Maximum pattern length to prevent ReDoS
    MAX_PATTERN_LENGTH = 1000
    
    def __init__(self, rules_dir: Optional[Path] = None):
        """
        Initialize the rule loader.
        
        Args:
            rules_dir: Directory containing YAML rule files. 
                      Defaults to scanner/rules/yaml/
        """
        if rules_dir is None:
            rules_dir = Path(__file__).parent / "yaml"
        
        self.rules_dir = Path(rules_dir)
        self.rulesets: List[RuleSet] = []
        self.rules_by_id: Dict[str, SecurityRule] = {}
        self.rules_by_category: Dict[str, List[SecurityRule]] = {}
        self.rules_by_severity: Dict[str, List[SecurityRule]] = {}
        self.rules_by_tag: Dict[str, List[SecurityRule]] = {}
        self.errors: List[str] = []
        
        self._loaded = False
    
    def load_all(self) -> "RuleLoader":
        """Load all YAML rule files from the rules directory."""
        if not self.rules_dir.exists():
            self.errors.append(f"Rules directory not found: {self.rules_dir}")
            return self
        
        yaml_files = list(self.rules_dir.glob("*.yaml")) + list(self.rules_dir.glob("*.yml"))
        
        for yaml_file in yaml_files:
            # Skip schema documentation file
            if yaml_file.name == "schema.yaml":
                continue
            self._load_file(yaml_file)
        
        self._loaded = True
        return self
    
    def load_file(self, filepath: Path) -> "RuleLoader":
        """Load a single YAML rule file."""
        self._load_file(Path(filepath))
        return self
    
    def _load_file(self, filepath: Path) -> None:
        """Internal method to load and parse a YAML rule file."""
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                content = yaml.safe_load(f)
            
            if not content:
                self.errors.append(f"Empty rule file: {filepath}")
                return
            
            ruleset = self._parse_ruleset(content, filepath)
            if ruleset:
                self.rulesets.append(ruleset)
                
                # Index rules for fast lookup
                for rule in ruleset.rules:
                    self._index_rule(rule)
                    
        except yaml.YAMLError as e:
            self.errors.append(f"YAML parsing error in {filepath}: {e}")
        except Exception as e:
            self.errors.append(f"Error loading {filepath}: {e}")
    
    def _parse_ruleset(self, content: Dict, filepath: Path) -> Optional[RuleSet]:
        """Parse a ruleset from YAML content."""
        metadata = content.get("metadata", {})
        
        ruleset = RuleSet(
            name=metadata.get("name", filepath.stem),
            description=metadata.get("description", ""),
            version=metadata.get("version", "1.0.0"),
            author=metadata.get("author", "Unknown"),
            category=metadata.get("category", "general"),
        )
        
        rules_data = content.get("rules", [])
        for rule_data in rules_data:
            rule = self._parse_rule(rule_data, filepath)
            if rule:
                ruleset.rules.append(rule)
        
        return ruleset
    
    def _parse_rule(self, rule_data: Dict, filepath: Path) -> Optional[SecurityRule]:
        """Parse a single rule from YAML data."""
        try:
            # Validate required fields
            required_fields = ["id", "name", "description", "severity", "category", "pattern", "recommendation"]
            for field in required_fields:
                if field not in rule_data:
                    self.errors.append(f"Missing required field '{field}' in rule from {filepath}")
                    return None
            
            # Validate severity
            severity = rule_data["severity"].lower()
            if severity not in self.SEVERITY_LEVELS:
                self.errors.append(f"Invalid severity '{severity}' in rule {rule_data['id']}")
                return None
            
            # Validate and compile pattern
            pattern = rule_data["pattern"]
            if len(pattern) > self.MAX_PATTERN_LENGTH:
                self.errors.append(f"Pattern too long in rule {rule_data['id']} (max {self.MAX_PATTERN_LENGTH})")
                return None
            
            # Parse flags
            flag_names = rule_data.get("pattern_flags", [])
            flags = 0
            for flag_name in flag_names:
                if flag_name in self.FLAG_MAP:
                    flags |= self.FLAG_MAP[flag_name]
                else:
                    self.errors.append(f"Unknown flag '{flag_name}' in rule {rule_data['id']}")
            
            # Compile pattern with timeout protection
            try:
                compiled = re.compile(pattern, flags)
            except re.error as e:
                self.errors.append(f"Invalid regex in rule {rule_data['id']}: {e}")
                return None
            
            # Parse and compile exclude patterns
            exclude_patterns = rule_data.get("exclude_patterns", [])
            compiled_excludes = []
            for exc_pat in exclude_patterns:
                try:
                    compiled_excludes.append(re.compile(exc_pat, re.IGNORECASE))
                except re.error as e:
                    self.errors.append(f"Invalid exclude pattern in rule {rule_data['id']}: {e}")
            
            return SecurityRule(
                id=rule_data["id"],
                name=rule_data["name"],
                description=rule_data["description"],
                severity=severity,
                category=rule_data["category"],
                pattern=pattern,
                compiled_pattern=compiled,
                recommendation=rule_data["recommendation"],
                pattern_flags=flag_names,
                references=rule_data.get("references", []),
                tags=rule_data.get("tags", []),
                enabled=rule_data.get("enabled", True),
                false_positive_note=rule_data.get("false_positive_note"),
                file_types=rule_data.get("file_types", []),
                components=rule_data.get("components", []),
                exclude_patterns=exclude_patterns,
                _compiled_excludes=compiled_excludes,
            )
            
        except Exception as e:
            self.errors.append(f"Error parsing rule from {filepath}: {e}")
            return None
    
    def _index_rule(self, rule: SecurityRule) -> None:
        """Index a rule for fast lookup."""
        # By ID
        if rule.id in self.rules_by_id:
            self.errors.append(f"Duplicate rule ID: {rule.id}")
        self.rules_by_id[rule.id] = rule
        
        # By category
        if rule.category not in self.rules_by_category:
            self.rules_by_category[rule.category] = []
        self.rules_by_category[rule.category].append(rule)
        
        # By severity
        if rule.severity not in self.rules_by_severity:
            self.rules_by_severity[rule.severity] = []
        self.rules_by_severity[rule.severity].append(rule)
        
        # By tags
        for tag in rule.tags:
            if tag not in self.rules_by_tag:
                self.rules_by_tag[tag] = []
            self.rules_by_tag[tag].append(rule)
    
    def get_rule(self, rule_id: str) -> Optional[SecurityRule]:
        """Get a rule by its ID."""
        return self.rules_by_id.get(rule_id)
    
    def get_rules_by_category(self, category: str) -> List[SecurityRule]:
        """Get all rules in a category."""
        return self.rules_by_category.get(category, [])
    
    def get_rules_by_severity(self, severity: str) -> List[SecurityRule]:
        """Get all rules with a specific severity."""
        return self.rules_by_severity.get(severity.lower(), [])
    
    def get_rules_by_tag(self, tag: str) -> List[SecurityRule]:
        """Get all rules with a specific tag."""
        return self.rules_by_tag.get(tag, [])
    
    def get_all_rules(self, enabled_only: bool = True) -> List[SecurityRule]:
        """Get all loaded rules."""
        rules = list(self.rules_by_id.values())
        if enabled_only:
            rules = [r for r in rules if r.enabled]
        return rules
    
    def get_categories(self) -> Set[str]:
        """Get all unique categories."""
        return set(self.rules_by_category.keys())
    
    def get_tags(self) -> Set[str]:
        """Get all unique tags."""
        return set(self.rules_by_tag.keys())
    
    def get_rules_for_component(
        self, categories: List[str], component_type: str, file_type: str = ""
    ) -> List[SecurityRule]:
        """Get deduplicated rules filtered by category, component type, and file type.
        
        Args:
            categories: Rule categories to include.
            component_type: The component type (e.g. "skill", "script", "hook").
            file_type: The file/language type (e.g. "python", "bash", "markdown").
        """
        rules = []
        for cat in categories:
            rules.extend(self.get_rules_by_category(cat))
        
        seen: set = set()
        filtered: List[SecurityRule] = []
        for rule in rules:
            if rule.id in seen or not rule.enabled:
                continue
            seen.add(rule.id)
            if not rule.applies_to_component(component_type):
                continue
            if file_type and not rule.applies_to_file_type(file_type):
                continue
            filtered.append(rule)
        return filtered
    
    def scan_content(
        self,
        content: str,
        categories: Optional[List[str]] = None,
        severities: Optional[List[str]] = None,
        tags: Optional[List[str]] = None,
    ) -> List[Dict[str, Any]]:
        """
        Scan content against loaded rules.
        
        Args:
            content: Content to scan
            categories: Filter by categories (None = all)
            severities: Filter by severities (None = all)
            tags: Filter by tags (None = all)
            
        Returns:
            List of finding dictionaries
        """
        if not self._loaded:
            self.load_all()
        
        findings = []
        rules = self.get_all_rules(enabled_only=True)
        
        # Filter rules
        if categories:
            rules = [r for r in rules if r.category in categories]
        if severities:
            severities_lower = [s.lower() for s in severities]
            rules = [r for r in rules if r.severity in severities_lower]
        if tags:
            rules = [r for r in rules if any(t in r.tags for t in tags)]
        
        # Scan with each rule
        for rule in rules:
            matches = rule.match(content)
            for match in matches:
                # Get line number
                line_num = content[:match.start()].count('\n') + 1
                
                findings.append({
                    "rule_id": rule.id,
                    "rule_name": rule.name,
                    "description": rule.description,
                    "severity": rule.severity,
                    "category": rule.category,
                    "recommendation": rule.recommendation,
                    "references": rule.references,
                    "match": match.group()[:100],  # Truncate long matches
                    "line": line_num,
                    "start": match.start(),
                    "end": match.end(),
                })
        
        return findings
    
    def disable_rule(self, rule_id: str) -> bool:
        """Disable a rule by ID."""
        rule = self.rules_by_id.get(rule_id)
        if rule:
            rule.enabled = False
            return True
        return False
    
    def enable_rule(self, rule_id: str) -> bool:
        """Enable a rule by ID."""
        rule = self.rules_by_id.get(rule_id)
        if rule:
            rule.enabled = True
            return True
        return False
    
    def get_stats(self) -> Dict[str, Any]:
        """Get statistics about loaded rules."""
        return {
            "total_rules": len(self.rules_by_id),
            "enabled_rules": len([r for r in self.rules_by_id.values() if r.enabled]),
            "rulesets": len(self.rulesets),
            "categories": len(self.rules_by_category),
            "rules_by_severity": {
                severity: len(rules)
                for severity, rules in self.rules_by_severity.items()
            },
            "rules_by_category": {
                category: len(rules)
                for category, rules in self.rules_by_category.items()
            },
            "errors": len(self.errors),
        }
    
    def to_dict(self) -> Dict[str, Any]:
        """Export all rules as a dictionary."""
        return {
            "rulesets": [rs.to_dict() for rs in self.rulesets],
            "stats": self.get_stats(),
            "errors": self.errors,
        }


# Singleton instance for global access
_global_loader: Optional[RuleLoader] = None


def get_rule_loader() -> RuleLoader:
    """Get the global rule loader instance."""
    global _global_loader
    if _global_loader is None:
        _global_loader = RuleLoader().load_all()
    return _global_loader


def reload_rules() -> RuleLoader:
    """Reload all rules from disk."""
    global _global_loader
    _global_loader = RuleLoader().load_all()
    return _global_loader

