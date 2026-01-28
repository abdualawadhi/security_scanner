#!/usr/bin/env python3
"""
OutSystems Security Analyzer
Low-Code Platform Security Scanner

Specialized analyzer for OutSystems applications with platform-specific
vulnerability detection.

Author: Bachelor Thesis Project - Low-Code Platforms Security Analysis
"""

import re
from typing import Any, Dict, List

import requests
from bs4 import BeautifulSoup

from .base import BaseAnalyzer


class OutSystemsAnalyzer(BaseAnalyzer):
    """Specialized analyzer for OutSystems applications"""

    def __init__(self, session: requests.Session):
        super().__init__(session)
        self.rest_apis = []
        self.screen_actions = []
        self.entities = []

    def analyze(
        self, url: str, response: requests.Response, soup: BeautifulSoup
    ) -> Dict[str, Any]:
        """Comprehensive OutSystems security analysis"""

        js_content = self._extract_javascript(soup)
        html_content = str(soup)

        # Analyze REST APIs
        self._analyze_rest_apis(js_content)

        # Analyze screen actions
        self._analyze_screen_actions(js_content)

        # Check for entity exposure
        self._analyze_entities(js_content)

        # Check session management
        self._analyze_session_management(js_content)

        # Analyze role-based access
        self._analyze_roles(js_content)

        # Check for session tokens in URL
        self._check_session_tokens_in_url(url)

        # Check for secrets in JavaScript
        self._check_secrets_in_javascript(js_content, url)

        # Check cookie security
        self._check_cookie_security(response)

        # Check Content Security Policy
        self._check_csp_policy(response)

        # Check for clickjacking vulnerabilities
        self._check_clickjacking(response)

        # Check for information disclosure
        self._check_information_disclosure(js_content, html_content, response)

        # Check for reflected input (XSS)
        self._check_reflected_input(url, response, html_content)

        # Check for path-relative stylesheet import
        self._check_path_relative_stylesheets(soup)

        # Check for cacheable HTTPS responses
        self._check_cacheable_https(response, url)

        # Check for Base64 encoded data
        self._check_base64_data(url, html_content)

        return {
            "rest_apis": self.rest_apis,
            "screen_actions": self.screen_actions,
            "entities": self.entities,
            "vulnerabilities": self.vulnerabilities,
            "outsystems_specific_findings": self.findings,
        }

    def _extract_javascript(self, soup: BeautifulSoup) -> str:
        """Extract JavaScript content for analysis"""
        js_content = ""

        for script in soup.find_all("script"):
            if script.string:
                js_content += script.string + "\n"

        return js_content

    def _analyze_rest_apis(self, js_content: str):
        """Analyze OutSystems REST API exposure"""

        rest_patterns = [
            r'/rest/([^"\'?\s]+)',
            r'RestService_([^"\'?\s]+)',
            r'CallRestAPI\([^)]*["\']([^"\']+)["\']',
        ]

        for pattern in rest_patterns:
            matches = re.findall(pattern, js_content, re.IGNORECASE)
            for match in matches:
                self.rest_apis.append(match)

                # Check for sensitive API names
                if any(
                    sensitive in match.lower()
                    for sensitive in ["admin", "internal", "private", "secret"]
                ):
                    self.add_vulnerability(
                        "Sensitive REST API Exposure",
                        "High",
                        f"Potentially sensitive REST API exposed: {match}",
                        match,
                        "Review API permissions and authentication requirements",
                        category="API Security",
                        owasp="A01:2021 - Broken Access Control",
                        cwe=["CWE-284", "CWE-862"]
                    )

    def _analyze_screen_actions(self, js_content: str):
        """Analyze OutSystems screen actions"""

        action_patterns = [
            r'ScreenAction_([^"\'()\s]+)',
            r'OnClick["\']?\s*[:=]\s*["\']?([^"\';\s]+)',
            r'ServerAction_([^"\'()\s]+)',
        ]

        for pattern in action_patterns:
            matches = re.findall(pattern, js_content, re.IGNORECASE)
            for match in matches:
                self.screen_actions.append(match)

                # Check for privileged actions
                if any(
                    priv in match.lower()
                    for priv in ["delete", "admin", "elevate", "privilege"]
                ):
                    self.add_vulnerability(
                        "Privileged Action Exposure",
                        "Medium",
                        f"Privileged screen action found: {match}",
                        match,
                        "Ensure proper authorization checks for privileged actions",
                        category="Business Logic",
                        owasp="A01:2021 - Broken Access Control",
                        cwe=["CWE-284"]
                    )

    def _analyze_entities(self, js_content: str):
        """Check for OutSystems entity exposure"""

        entity_patterns = [
            r'Entity["\']?\s*[:=]\s*["\']([^"\']+)',
            r'GetEntity\([^)]*["\']([^"\']+)',
            r"entity_([a-zA-Z0-9_]+)",
        ]

        for pattern in entity_patterns:
            matches = re.findall(pattern, js_content, re.IGNORECASE)
            for match in matches:
                self.entities.append(match)

                # Check for sensitive entity names
                if any(
                    sensitive in match.lower()
                    for sensitive in ["user", "account", "payment", "personal"]
                ):
                    self.add_vulnerability(
                        "Sensitive Entity Exposure",
                        "Medium",
                        f"Sensitive entity structure exposed: {match}",
                        match,
                        "Review entity permissions and data access rules",
                        category="Data Exposure",
                        owasp="A04:2021 - Insecure Design",
                        cwe=["CWE-200"]
                    )

    def _analyze_session_management(self, js_content: str):
        """Analyze session management implementation"""

        session_patterns = [
            r'session[_-]?id["\']?\s*[:=]\s*["\']([^"\']+)',
            r"GetUserId\(\)",
            r'session["\']?\s*[:=]\s*["\']([^"\']+)',
        ]

        session_found = False
        for pattern in session_patterns:
            matches = re.findall(pattern, js_content, re.IGNORECASE)
            if matches:
                session_found = True
                break

        if not session_found:
            self.add_vulnerability(
                "Session Management Issues",
                "Medium",
                "No clear session management implementation found",
                "No session patterns detected",
                "Implement secure session management with proper timeout and validation",
                category="Session Management",
                owasp="A07:2021 - Identification and Authentication Failures",
                cwe=["CWE-287", "CWE-307"]
            )

    def _analyze_roles(self, js_content: str):
        """Analyze role-based access control"""

        role_patterns = [
            r'CheckRole\([^)]*["\']([^"\']+)',
            r'UserHasRole\([^)]*["\']([^"\']+)',
            r'role["\']?\s*[:=]\s*["\']([^"\']+)',
        ]

        roles_found = 0
        for pattern in role_patterns:
            matches = re.findall(pattern, js_content, re.IGNORECASE)
            roles_found += len(matches)

        if roles_found == 0:
            self.add_vulnerability(
                "Missing Role-Based Access Control",
                "High",
                "No role-based access control implementation detected",
                "No role patterns found",
                "Implement comprehensive role-based access control",
                category="Access Control",
                owasp="A01:2021 - Broken Access Control",
                cwe=["CWE-284"]
            )

    def _check_session_tokens_in_url(self, url: str):
        """Check for session tokens in URL"""
        if re.search(r'[?&](session|token|sid)=', url, re.IGNORECASE):
            self.add_vulnerability(
                "Session Token in URL",
                "Medium",
                "Session token found in URL",
                url,
                "Use secure cookies for session management",
                category="Session Management",
                owasp="A07:2021 - Identification and Authentication Failures",
                cwe=["CWE-384"]
            )

    def _check_secrets_in_javascript(self, js_content: str, url: str):
        """Check for secrets in JavaScript"""
        secret_patterns = [
            r'["\']([A-Za-z0-9]{32,})["\']',  # Potential API keys
            r'password["\']?\s*[:=]\s*["\']([^"\']+)["\']',
            r'secret["\']?\s*[:=]\s*["\']([^"\']+)["\']',
        ]

        for pattern in secret_patterns:
            matches = re.findall(pattern, js_content, re.IGNORECASE)
            for match in matches:
                if len(match) > 10:  # Avoid false positives
                    self.add_vulnerability(
                        "Potential Secret in JavaScript",
                        "High",
                        f"Potential secret found in JavaScript: {match[:10]}...",
                        match[:20],
                        "Remove secrets from client-side code",
                        category="Secret Management",
                        owasp="A02:2021 - Cryptographic Failures",
                        cwe=["CWE-798"]
                    )

    def _check_cookie_security(self, response: requests.Response):
        """Check cookie security headers"""
        cookies = response.headers.get("Set-Cookie", "")
        if "Secure" not in cookies:
            self.add_vulnerability(
                "Insecure Cookie",
                "Medium",
                "Cookie lacks Secure flag",
                cookies[:50],
                "Set Secure flag for cookies",
                category="Session Management",
                owasp="A05:2021 - Security Misconfiguration",
                cwe=["CWE-614"]
            )

    def _check_csp_policy(self, response: requests.Response):
        """Check Content Security Policy"""
        csp = response.headers.get("Content-Security-Policy", "")
        if not csp:
            self.add_vulnerability(
                "Missing Content Security Policy",
                "Low",
                "No CSP header found",
                "",
                "Implement Content Security Policy",
                category="Security Headers",
                owasp="A05:2021 - Security Misconfiguration",
                cwe=["CWE-693"]
            )

    def _check_clickjacking(self, response: requests.Response):
        """Check for clickjacking protection"""
        xfo = response.headers.get("X-Frame-Options", "")
        if not xfo:
            self.add_vulnerability(
                "Missing Clickjacking Protection",
                "Low",
                "No X-Frame-Options header",
                "",
                "Implement X-Frame-Options header",
                category="Security Headers",
                owasp="A05:2021 - Security Misconfiguration",
                cwe=["CWE-693"]
            )

    def _check_information_disclosure(self, js_content: str, html_content: str, response: requests.Response):
        """Check for information disclosure"""
        error_patterns = [
            r'error[:\s]+["\']([^"\']+)["\']',
            r'exception[:\s]+["\']([^"\']+)["\']',
            r'stack\s*trace',
        ]

        for pattern in error_patterns:
            if re.search(pattern, js_content + html_content, re.IGNORECASE):
                self.add_vulnerability(
                    "Information Disclosure",
                    "Low",
                    "Potential error information exposed",
                    "",
                    "Review error handling and information disclosure",
                    category="Information Disclosure",
                    owasp="A09:2021 - Security Logging and Monitoring Failures",
                    cwe=["CWE-200"]
                )
                break

    def _check_reflected_input(self, url: str, response: requests.Response, html_content: str):
        """Check for reflected input (potential XSS)"""
        from urllib.parse import urlparse, parse_qs
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        for param, values in params.items():
            for value in values:
                if value in html_content:
                    self.add_vulnerability(
                        "Reflected Input (Potential XSS)",
                        "Medium",
                        f"Input parameter '{param}' is reflected in response",
                        f"{param}={value}",
                        "Implement output encoding and input validation",
                        category="Cross-Site Scripting",
                        owasp="A03:2021 - Injection",
                        cwe=["CWE-79"]
                    )

    def _check_path_relative_stylesheets(self, soup: BeautifulSoup):
        """Check for path-relative stylesheet imports"""
        link_tags = soup.find_all("link", rel="stylesheet")
        for link in link_tags:
            href = link.get("href", "")
            if href.startswith("/") and not href.startswith("//"):
                self.add_vulnerability(
                    "Path-Relative Stylesheet Import",
                    "Low",
                    f"Path-relative stylesheet: {href}",
                    href,
                    "Use absolute URLs for stylesheet imports",
                    category="Content Security Policy",
                    owasp="A05:2021 - Security Misconfiguration",
                    cwe=["CWE-939"]
                )

    def _check_cacheable_https(self, response: requests.Response, url: str):
        """Check for cacheable HTTPS responses"""
        cache_control = response.headers.get("Cache-Control", "")
        if "no-store" not in cache_control and url.startswith("https://"):
            self.add_vulnerability(
                "Cacheable HTTPS Response",
                "Low",
                "HTTPS response may be cached",
                cache_control,
                "Implement proper cache control for sensitive pages",
                category="Security Headers",
                owasp="A05:2021 - Security Misconfiguration",
                cwe=["CWE-525"]
            )

    def _check_base64_data(self, url: str, html_content: str):
        """Check for Base64 encoded data that might contain sensitive information"""
        import base64
        import re

        base64_pattern = r'["\']([A-Za-z0-9+/]{20,}={0,2})["\']'
        matches = re.findall(base64_pattern, html_content)
        
        for match in matches:
            try:
                decoded = base64.b64decode(match).decode('utf-8', errors='ignore')
                # Check if decoded content looks like sensitive data
                if any(keyword in decoded.lower() for keyword in ["password", "token", "key", "secret"]):
                    self.add_vulnerability(
                        "Sensitive Data in Base64",
                        "Medium",
                        f"Sensitive data found in Base64 encoded content",
                        match[:20],
                        "Avoid encoding sensitive data in Base64 in client-side code",
                        category="Data Exposure",
                        owasp="A04:2021 - Insecure Design",
                        cwe=["CWE-200"]
                    )
            except Exception:
                pass  # Skip if not valid Base64
