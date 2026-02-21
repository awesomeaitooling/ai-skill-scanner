"""Configuration management for the security scanner."""

from .scan_config import ScanConfig, load_config

__all__ = ["ScanConfig", "load_config"]
