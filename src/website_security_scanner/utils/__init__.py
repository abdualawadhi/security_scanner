"""
Utility Modules
Low-Code Platform Security Scanner

Professional utility functions for security scanning operations.

Author: Bachelor Thesis Project - Low-Code Platforms Security Analysis
"""

from .logger import setup_scanner_logger, get_logger, ScannerLogger
from .utils import (
    normalize_url,
    is_valid_url,
    extract_domain,
    calculate_security_score,
)

__all__ = [
    "setup_scanner_logger",
    "get_logger",
    "ScannerLogger",
    "normalize_url",
    "is_valid_url",
    "extract_domain",
    "calculate_security_score",
]
