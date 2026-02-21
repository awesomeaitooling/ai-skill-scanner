"""
Security Rules Module

This module provides YAML-based security rules for the plugin scanner.
Rules are defined in YAML files under the yaml/ directory and can be
easily extended without modifying Python code.

Usage:
    from scanner.rules import get_rule_loader, reload_rules

    # Get the global rule loader
    loader = get_rule_loader()
    
    # Get rules by category
    rules = loader.get_rules_by_category("prompt-injection")
    
    # Scan content
    findings = loader.scan_content(content, categories=["prompt-injection"])
    
    # Reload rules from disk
    reload_rules()
"""

from .rule_loader import (
    RuleLoader,
    SecurityRule,
    RuleSet,
    get_rule_loader,
    reload_rules,
)

__all__ = [
    "RuleLoader",
    "SecurityRule", 
    "RuleSet",
    "get_rule_loader",
    "reload_rules",
]
