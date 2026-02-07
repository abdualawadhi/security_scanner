#!/usr/bin/env python3
"""
Evidence Verification Module

Thin wrapper around the live evidence verification utility so external
imports can use website_security_scanner.verifier.evidence_verifier.
"""

from ..utils.evidence_verifier import EvidenceVerifier, verify_vulnerabilities

__all__ = ["EvidenceVerifier", "verify_vulnerabilities"]
