"""
Custom Exception Classes
Low-Code Platform Security Scanner

Professional exception hierarchy for robust error handling.

Author: Bachelor Thesis Project - Low-Code Platforms Security Analysis
"""

from .scanner_exceptions import (
    ScannerError,
    ScannerConfigurationError,
    ScannerNetworkError,
    ScannerTimeoutError,
    ScannerAuthenticationError,
    AnalysisError,
    PlatformDetectionError,
    ReportGenerationError,
    ValidationError,
)

__all__ = [
    "ScannerError",
    "ScannerConfigurationError",
    "ScannerNetworkError",
    "ScannerTimeoutError",
    "ScannerAuthenticationError",
    "AnalysisError",
    "PlatformDetectionError",
    "ReportGenerationError",
    "ValidationError",
]
