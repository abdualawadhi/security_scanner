"""
Configuration Management Module
Low-Code Platform Security Scanner

Centralized configuration system for professional security scanning operations.

Author: Bachelor Thesis Project - Low-Code Platforms Security Analysis
"""

from .settings import ScannerConfig, SecurityStandards
from .constants import (
    SEVERITY_LEVELS,
    CONFIDENCE_LEVELS,
    VULNERABILITY_CATEGORIES,
    HTTP_SECURITY_HEADERS,
    PLATFORM_TYPES,
)

__all__ = [
    "ScannerConfig",
    "SecurityStandards",
    "SEVERITY_LEVELS",
    "CONFIDENCE_LEVELS",
    "VULNERABILITY_CATEGORIES",
    "HTTP_SECURITY_HEADERS",
    "PLATFORM_TYPES",
]
