#!/usr/bin/env python3
"""
Base Security Analyzer
Low-Code Platform Security Scanner

Enhanced base class for all security analyzers with professional-grade features
including enriched vulnerability reporting, HTTP context recording, and
comprehensive security analysis capabilities.

Author: Bachelor Thesis Project - Low-Code Platforms Security Analysis
"""

from datetime import datetime
from typing import Any, Dict, List, Optional, Union
import logging

import requests
from bs4 import BeautifulSoup

from ..exceptions import AnalysisError
from ..utils.logger import get_logger
from ..utils.vulnerability_verifier import VulnerabilityVerifier


class BaseAnalyzer:
    """
    Professional base class for all security analyzers.
    
    This class provides comprehensive vulnerability management, HTTP context recording,
    and enriched reporting capabilities that are consistent across all platform analyzers.
    
    All platform-specific analyzers should inherit from this class to ensure
    consistent professional-grade reporting and analysis capabilities.
    """

    def __init__(self, session: requests.Session):
        """
        Initialize base analyzer with session and enriched reporting capabilities.
        
        Args:
            session: Configured requests session for HTTP operations
        """
        self.session = session
        self.vulnerabilities: List[Dict[str, Any]] = []
        self.findings: Dict[str, Any] = {}
        
        # HTTP context tracking for enriched vulnerability reporting
        self._last_request: Optional[requests.PreparedRequest] = None
        self._last_response: Optional[requests.Response] = None
        
        # Logger for professional error handling and debugging
        self.logger = get_logger(self.__class__.__name__)

    def analyze(
        self, url: str, response: requests.Response, soup: BeautifulSoup
    ) -> Dict[str, Any]:
        """
        Base analyze method to be overridden by subclasses.
        
        Args:
            url: Target URL being analyzed
            response: HTTP response from target
            soup: Parsed BeautifulSoup object
            
        Returns:
            Dictionary containing analysis results
            
        Raises:
            NotImplementedError: If subclass doesn't implement this method
        """
        raise NotImplementedError("Subclasses must implement analyze method")

    def _record_http_context(self, url: str, response: requests.Response):
        """
        Store the primary HTTP request/response for enriched vulnerability reporting.
        
        This method captures the HTTP context that will be included in vulnerability
        reports to provide complete Request/Response pairs for professional reporting.
        
        Args:
            url: URL being analyzed
            response: HTTP response object
        """
        self._last_response = response
        try:
            self._last_request = response.request
        except Exception as e:
            self.logger.debug(f"Could not extract request from response: {e}")
            self._last_request = None

    def _build_http_instance(
        self, evidence_list: Optional[List[Any]] = None
    ) -> Dict[str, Any]:
        """
        Build HTTP instance dictionary for vulnerability reporting.
        
        Creates a structured HTTP instance containing request/response headers
        and evidence highlighting. Bodies are intentionally omitted to focus on
        protocol context while reducing report size and avoiding data leakage.
        
        Args:
            evidence_list: List of evidence items to highlight in the report
            
        Returns:
            Dictionary containing HTTP instance data
        """
        req_txt = ""
        resp_txt = ""
        
        if self._last_request is not None:
            try:
                method = getattr(self._last_request, "method", "GET")
                path = getattr(self._last_request, "path_url", "") or getattr(
                    self._last_request, "url", ""
                )
                headers = "\n".join(
                    f"{k}: {v}"
                    for k, v in getattr(self._last_request, "headers", {}).items()
                )
                req_txt = f"{method} {path} HTTP/1.1\n{headers}"
            except Exception as e:
                self.logger.debug(f"Error building request text: {e}")
                req_txt = ""
        
        if self._last_response is not None:
            try:
                status = self._last_response.status_code
                reason = getattr(self._last_response, "reason", "")
                headers = "\n".join(
                    f"{k}: {v}" for k, v in self._last_response.headers.items()
                )
                resp_txt = f"HTTP/1.1 {status} {reason}\n{headers}"
            except Exception as e:
                self.logger.debug(f"Error building response text: {e}")
                resp_txt = ""
        
        url = ""
        if self._last_request:
            url = getattr(self._last_request, "url", "")
        elif self._last_response:
            url = getattr(self._last_response, "url", "")
        
        return {
            "url": url,
            "request": req_txt,
            "response": resp_txt,
            "evidence": evidence_list or [],
        }

    def add_vulnerability(
        self,
        vuln_type: str,
        severity: str,
        description: str,
        evidence: str = "",
        recommendation: str = "",
        confidence: str = "Firm",
        category: str = "General",
        owasp: str = "N/A",
        cwe: Optional[List[str]] = None,
    ):
        """
        Add a vulnerability to the findings with detailed metadata.
        
        This is the standard method for reporting vulnerabilities. For enhanced
        reporting with background, impact, and references, use add_enriched_vulnerability.
        
        Args:
            vuln_type: Type/name of the vulnerability
            severity: Severity level (Critical, High, Medium, Low, Info)
            description: Detailed description of the vulnerability
            evidence: Evidence supporting the vulnerability finding
            recommendation: Remediation recommendations
            confidence: Confidence level (Certain, Firm, Tentative)
            category: Vulnerability category
            owasp: OWASP classification
            cwe: List of relevant CWE identifiers
        """
        vulnerability = {
            "type": vuln_type,
            "severity": severity,
            "description": description,
            "evidence": evidence,
            "recommendation": recommendation,
            "confidence": confidence,
            "category": category,
            "owasp": owasp,
            "cwe": cwe or [],
            "timestamp": self._get_timestamp(),
        }
        self.vulnerabilities.append(vulnerability)
        
        # Log vulnerability discovery
        self.logger.warning(
            f"Vulnerability found: {vuln_type} ({severity})",
            extra={
                "extra_data": {
                    "type": vuln_type,
                    "severity": severity,
                    "confidence": confidence,
                }
            }
        )

    def add_enriched_vulnerability(
        self,
        vuln_type: str,
        severity: str,
        description: str,
        evidence: Union[str, Dict, List] = "",
        recommendation: str = "",
        confidence: str = "Firm",
        category: str = "General",
        owasp: str = "N/A",
        cwe: Optional[List[str]] = None,
        background: str = "",
        impact: str = "",
        references: Optional[List[str]] = None,
    ):
        """
        Add enriched vulnerability with comprehensive metadata and HTTP context.
        
        This method extends the standard vulnerability reporting with additional
        professional-grade metadata including background information, impact analysis,
        references, and HTTP request/response pairs for Burp-style reporting.
        
        Args:
            vuln_type: Type/name of the vulnerability
            severity: Severity level (Critical, High, Medium, Low, Info)
            description: Detailed description of the vulnerability
            evidence: Evidence supporting the finding (string, dict, or list)
            recommendation: Remediation recommendations
            confidence: Confidence level (Certain, Firm, Tentative)
            category: Vulnerability category
            owasp: OWASP classification
            cwe: List of relevant CWE identifiers
            background: Background information about the vulnerability type
            impact: Detailed impact analysis
            references: List of reference URLs for more information
        """
        # Handle evidence parameter - can be string, dict, or list
        if isinstance(evidence, (dict, list)):
            evidence_list = evidence if isinstance(evidence, list) else [evidence]
            evidence_str = str(evidence)
        else:
            evidence_list = [evidence] if evidence else []
            evidence_str = evidence
        
        # Call standard add_vulnerability to ensure consistent base behavior
        self.add_vulnerability(
            vuln_type,
            severity,
            description,
            evidence_str,
            recommendation,
            confidence,
            category,
            owasp,
            cwe,
        )
        
        # Enhance the last added vulnerability with enriched metadata
        vuln = self.vulnerabilities[-1]
        vuln["background"] = background or ""
        vuln["impact"] = impact or ""
        vuln["references"] = references or []
        
        # Add HTTP instance for professional Burp-style reporting
        if self._last_response is not None:
            vuln["instances"] = [self._build_http_instance(evidence_list=evidence_list)]

    def _get_timestamp(self) -> str:
        """
        Get current timestamp for vulnerability logging.
        
        Returns:
            ISO format timestamp string
        """
        return datetime.now().isoformat()

    def check_security_headers(self, response: requests.Response) -> Dict[str, Any]:
        """
        Analyze security headers in the HTTP response.
        
        Evaluates the presence and configuration of critical security headers
        that protect against common web vulnerabilities.
        
        Args:
            response: HTTP response to analyze
            
        Returns:
            Dictionary containing header analysis results and security score
        """
        headers = response.headers
        security_headers = {
            "X-Frame-Options": headers.get("X-Frame-Options", "Missing"),
            "X-Content-Type-Options": headers.get("X-Content-Type-Options", "Missing"),
            "X-XSS-Protection": headers.get("X-XSS-Protection", "Missing"),
            "Strict-Transport-Security": headers.get(
                "Strict-Transport-Security", "Missing"
            ),
            "Content-Security-Policy": headers.get(
                "Content-Security-Policy", "Missing"
            ),
            "Referrer-Policy": headers.get("Referrer-Policy", "Missing"),
            "Permissions-Policy": headers.get("Permissions-Policy", "Missing"),
            "X-Permitted-Cross-Domain-Policies": headers.get(
                "X-Permitted-Cross-Domain-Policies", "Missing"
            ),
        }

        # Calculate security score
        present_headers = sum(1 for v in security_headers.values() if v != "Missing")
        security_headers["security_score"] = f"{present_headers}/8"

        return security_headers

    def analyze_ssl_tls(self, url: str) -> Dict[str, Any]:
        """
        Analyze SSL/TLS configuration of the target.
        
        Performs comprehensive SSL/TLS analysis including certificate validation,
        cipher suite evaluation, and protocol version checking.
        
        Args:
            url: Target URL to analyze
            
        Returns:
            Dictionary containing SSL/TLS analysis results
        """
        import ssl
        import socket
        from urllib.parse import urlparse

        parsed_url = urlparse(url)
        hostname = parsed_url.hostname

        if not hostname:
            return {"error": "Invalid URL for SSL analysis"}

        try:
            context = ssl.create_default_context()
            with socket.create_connection((hostname, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    version = ssock.version()

                    return {
                        "version": version,
                        "cipher": cipher,
                        "certificate_subject": cert.get("subject", []),
                        "certificate_issuer": cert.get("issuer", []),
                        "certificate_expiry": cert.get("notAfter", "Unknown"),
                        "certificate_san": cert.get("subjectAltName", []),
                    }
        except Exception as e:
            self.logger.debug(f"SSL analysis failed for {url}: {e}")
            return {"error": str(e)}

    def get_results(self) -> Dict[str, Any]:
        """
        Get comprehensive analysis results.
        
        Returns:
            Dictionary containing all vulnerabilities, findings, and metrics
        """
        return {
            "vulnerabilities": self.vulnerabilities,
            "findings": self.findings,
            "vulnerability_count": len(self.vulnerabilities),
            "severity_breakdown": self._get_severity_breakdown(),
        }

    def _get_severity_breakdown(self) -> Dict[str, int]:
        """
        Calculate breakdown of vulnerabilities by severity level.
        
        Returns:
            Dictionary mapping severity levels to counts
        """
        breakdown = {
            "Critical": 0,
            "High": 0,
            "Medium": 0,
            "Low": 0,
            "Info": 0,
            "Information": 0,
        }
        
        for vuln in self.vulnerabilities:
            severity = vuln.get("severity", "Info")
            if severity in breakdown:
                breakdown[severity] += 1
        
        return breakdown

    def verify_vulnerabilities(self, url: str) -> Dict[str, Any]:
        """
        Actively verify detected vulnerabilities using safe payload testing.
        
        This method integrates with the VulnerabilityVerifier to confirm that
        detected vulnerabilities are actually exploitable. It performs safe
        exploitation attempts and updates confidence levels based on verification results.
        
        Args:
            url: Target URL being analyzed
            
        Returns:
            Dictionary containing verification summary statistics
        """
        if not self.vulnerabilities:
            self.logger.info("No vulnerabilities to verify")
            return {
                "total_vulnerabilities": 0,
                "verified_vulnerabilities": 0,
                "high_confidence_verifications": 0,
                "verification_rate": 0.0
            }
        
        # Initialize vulnerability verifier
        verifier = VulnerabilityVerifier(self.session)
        
        # Get the last response if available for verification context
        response = self._last_response if self._last_response else None
        
        verified_count = 0
        high_confidence_count = 0
        
        self.logger.info(f"Starting active verification for {len(self.vulnerabilities)} vulnerabilities")
        
        for i, vuln in enumerate(self.vulnerabilities):
            vuln_type = vuln.get('type', '')
            
            # Skip verification for certain vulnerability types that don't benefit from active testing
            skip_types = [
                'Missing Security Header',
                'SSL/TLS Issue',
                'Information Disclosure',
                'Cookie Security',
                'Session Token in URL'
            ]
            
            if any(skip_type in vuln_type for skip_type in skip_types):
                # Mark as pattern match only
                vuln['verification'] = {
                    'verified': False,
                    'confidence': 'medium',
                    'method': 'pattern_match_only',
                    'note': 'This vulnerability type is verified via static analysis only'
                }
                continue
            
            # Perform active verification for exploitable vulnerabilities
            try:
                if response:
                    verified_vuln = verifier.verify_vulnerability(vuln, url, response)
                else:
                    # If no response available, mark as unable to verify
                    verified_vuln = vuln.copy()
                    verified_vuln['verification'] = {
                        'verified': False,
                        'confidence': 'low',
                        'method': 'no_context',
                        'note': 'No HTTP response available for verification'
                    }
                
                # Update vulnerability with verification results
                self.vulnerabilities[i] = verified_vuln
                
                # Track verification statistics
                verification = verified_vuln.get('verification', {})
                if verification.get('verified', False):
                    verified_count += 1
                    high_confidence_count += 1
                    
                    # Update confidence level to Certain for verified vulnerabilities
                    self.vulnerabilities[i]['confidence'] = 'Certain'
                    self.logger.info(f"✓ Verified: {vuln_type}")
                else:
                    confidence = verification.get('confidence', 'low')
                    if confidence == 'high':
                        high_confidence_count += 1
                    self.logger.debug(f"✗ Unverified: {vuln_type} (confidence: {confidence})")
                
            except Exception as e:
                self.logger.error(f"Verification failed for {vuln_type}: {str(e)}")
                self.vulnerabilities[i]['verification'] = {
                    'verified': False,
                    'confidence': 'unknown',
                    'error': str(e),
                    'method': 'failed'
                }
        
        # Calculate verification statistics
        total_vulns = len(self.vulnerabilities)
        verification_rate = (verified_count / total_vulns * 100) if total_vulns > 0 else 0.0
        
        verification_summary = {
            'total_vulnerabilities': total_vulns,
            'verified_vulnerabilities': verified_count,
            'high_confidence_verifications': high_confidence_count,
            'verification_rate': round(verification_rate, 2)
        }
        
        self.logger.info(
            f"Verification complete: {verified_count}/{total_vulns} verified "
            f"({verification_rate:.2f}% verification rate)"
        )
        
        return verification_summary
