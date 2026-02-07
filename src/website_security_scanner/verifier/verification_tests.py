"""
Individual verification test functions for various vulnerability types.

These functions provide granular testing capabilities that can be used
standalone or through the VulnerabilityVerifier class.
"""

from typing import Dict, Any, Optional
import requests


def verify_xss(url: str, parameter: str, session: Optional[requests.Session] = None) -> Dict[str, Any]:
    """
    Standalone XSS verification test.
    
    Args:
        url: Target URL
        parameter: Parameter to test
        session: Optional requests session
        
    Returns:
        Verification result dictionary
    """
    from .vulnerability_verifier import VulnerabilityVerifier
    verifier = VulnerabilityVerifier(session)
    return verifier.verify_xss({
        'url': url,
        'parameter': parameter,
        'type': 'xss'
    })


def verify_sql_injection(url: str, parameter: str, session: Optional[requests.Session] = None) -> Dict[str, Any]:
    """Standalone SQL injection verification test."""
    from .vulnerability_verifier import VulnerabilityVerifier
    verifier = VulnerabilityVerifier(session)
    return verifier.verify_sql_injection({
        'url': url,
        'parameter': parameter,
        'type': 'sql injection'
    })


def verify_command_injection(url: str, parameter: str, session: Optional[requests.Session] = None) -> Dict[str, Any]:
    """Standalone command injection verification test."""
    from .vulnerability_verifier import VulnerabilityVerifier
    verifier = VulnerabilityVerifier(session)
    return verifier.verify_command_injection({
        'url': url,
        'parameter': parameter,
        'type': 'command injection'
    })


def verify_path_traversal(url: str, parameter: str, session: Optional[requests.Session] = None) -> Dict[str, Any]:
    """Standalone path traversal verification test."""
    from .vulnerability_verifier import VulnerabilityVerifier
    verifier = VulnerabilityVerifier(session)
    return verifier.verify_path_traversal({
        'url': url,
        'parameter': parameter,
        'type': 'path traversal'
    })


def verify_ssrf(url: str, parameter: str, session: Optional[requests.Session] = None) -> Dict[str, Any]:
    """Standalone SSRF verification test."""
    from .vulnerability_verifier import VulnerabilityVerifier
    verifier = VulnerabilityVerifier(session)
    return verifier.verify_ssrf({
        'url': url,
        'parameter': parameter,
        'type': 'ssrf'
    })


def verify_open_redirect(url: str, parameter: str, session: Optional[requests.Session] = None) -> Dict[str, Any]:
    """Standalone open redirect verification test."""
    from .vulnerability_verifier import VulnerabilityVerifier
    verifier = VulnerabilityVerifier(session)
    return verifier.verify_open_redirect({
        'url': url,
        'parameter': parameter,
        'type': 'open redirect'
    })
