"""
Vulnerability Verification Module

This module provides active verification capabilities for detected vulnerabilities.
It attempts to confirm vulnerabilities through controlled testing while maintaining
safety and ethical boundaries.
"""

from .vulnerability_verifier import VulnerabilityVerifier
from .verification_tests import (
    verify_xss,
    verify_sql_injection,
    verify_command_injection,
    verify_path_traversal,
    verify_ssrf,
    verify_open_redirect,
)
from .evidence_verifier import EvidenceVerifier, verify_vulnerabilities

__all__ = [
    'VulnerabilityVerifier',
    'verify_xss',
    'verify_sql_injection',
    'verify_command_injection',
    'verify_path_traversal',
    'verify_ssrf',
    'verify_open_redirect',
    'EvidenceVerifier',
    'verify_vulnerabilities',
]
