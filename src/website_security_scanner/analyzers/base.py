#!/usr/bin/env python3
"""
Base Security Analyzer
Low-Code Platform Security Scanner

Base class for all security analyzers with common functionality.

Author: Bachelor Thesis Project - Low-Code Platforms Security Analysis
"""

from typing import Any, Dict, List, Optional

import requests
from bs4 import BeautifulSoup


class BaseAnalyzer:
    """Base class for all security analyzers"""

    def __init__(self, session: requests.Session):
        self.session = session
        self.vulnerabilities = []
        self.findings = {}

    def analyze(
        self, url: str, response: requests.Response, soup: BeautifulSoup
    ) -> Dict[str, Any]:
        """Base analyze method to be overridden by subclasses"""
        raise NotImplementedError("Subclasses must implement analyze method")

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
        cwe: List[str] = None,
    ):
        """Add a vulnerability to the findings with detailed metadata for professional reporting"""
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

    def _get_timestamp(self) -> str:
        """Get current timestamp for vulnerability logging"""
        from datetime import datetime
        return datetime.now().isoformat()

    def check_security_headers(self, response: requests.Response) -> Dict[str, Any]:
        """Analyze security headers in the response"""
        headers = response.headers
        security_headers = {
            "X-Frame-Options": headers.get("X-Frame-Options", "Missing"),
            "X-Content-Type-Options": headers.get("X-Content-Type-Options", "Missing"),
            "X-XSS-Protection": headers.get("X-XSS-Protection", "Missing"),
            "Strict-Transport-Security": headers.get("Strict-Transport-Security", "Missing"),
            "Content-Security-Policy": headers.get("Content-Security-Policy", "Missing"),
            "Referrer-Policy": headers.get("Referrer-Policy", "Missing"),
            "Permissions-Policy": headers.get("Permissions-Policy", "Missing"),
            "X-Permitted-Cross-Domain-Policies": headers.get("X-Permitted-Cross-Domain-Policies", "Missing"),
        }

        # Calculate security score
        present_headers = sum(1 for v in security_headers.values() if v != "Missing")
        security_headers["security_score"] = f"{present_headers}/8"

        return security_headers

    def analyze_ssl_tls(self, url: str) -> Dict[str, Any]:
        """Analyze SSL/TLS configuration"""
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
            return {"error": str(e)}

    def get_results(self) -> Dict[str, Any]:
        """Get analysis results"""
        return {
            "vulnerabilities": self.vulnerabilities,
            "findings": self.findings,
            "vulnerability_count": len(self.vulnerabilities),
        }
