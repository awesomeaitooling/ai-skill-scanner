"""Utility functions for the scanner."""

from .git_utils import clone_marketplace, fetch_plugin_from_git
from .discovery import DiscoveredTarget, discover_targets
from .redaction import redact_secrets

__all__ = [
    "clone_marketplace",
    "fetch_plugin_from_git",
    "DiscoveredTarget",
    "discover_targets",
    "redact_secrets",
]

