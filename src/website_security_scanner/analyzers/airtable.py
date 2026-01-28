#!/usr/bin/env python3
"""
Airtable Security Analyzer
Low-Code Platform Security Scanner

Specialized analyzer for Airtable applications with platform-specific
vulnerability detection.

Author: Bachelor Thesis Project - Low-Code Platforms Security Analysis
"""

import re
import base64
from typing import Any, Dict, List
from urllib.parse import urlparse, parse_qs

import requests
from bs4 import BeautifulSoup

from .base import BaseAnalyzer


class AirtableAnalyzer(BaseAnalyzer):
    """Specialized analyzer for Airtable applications"""

    def __init__(self, session: requests.Session):
        super().__init__(session)
        self.base_ids = []
        self.api_keys = []
        self.table_schemas = []
        self.permission_models = []

    def analyze(
        self, url: str, response: requests.Response, soup: BeautifulSoup
    ) -> Dict[str, Any]:
        """Comprehensive Airtable security analysis"""

        js_content = self._extract_javascript(soup)
        html_content = str(soup)

        # Analyze Base ID exposure
        self._analyze_base_ids(js_content, html_content)

        # Check for API key exposure
        self._analyze_api_keys(js_content, html_content)

        # Analyze table structure
        self._analyze_table_structure(js_content)

        # Check permission model
        self._analyze_permissions(js_content)

        # Check data access controls
        self._analyze_data_access(js_content)

        # Generic security checks
        self._check_session_tokens_in_url(url)
        self._check_secrets_in_javascript(js_content, url)
        self._check_cookie_security(response)
        self._check_csp_policy(response)
        self._check_clickjacking(response)
        self._check_information_disclosure(js_content, html_content, response)
        self._check_reflected_input(url, response, html_content)
        self._check_cacheable_https(response, url)
        self._check_open_redirection(js_content)
        self._check_ajax_header_manipulation(js_content)
        self._check_hsts(response)
        self._check_content_type_options(response)
        self._check_vulnerable_dependencies(js_content)

        return {
            "base_ids": self.base_ids,
            "api_keys": self.api_keys,
            "table_schemas": self.table_schemas,
            "permission_models": self.permission_models,
            "vulnerabilities": self.vulnerabilities,
            "airtable_specific_findings": self.findings,
        }

    def _extract_javascript(self, soup: BeautifulSoup) -> str:
        """Extract JavaScript content for analysis"""
        js_content = ""

        for script in soup.find_all("script"):
            if script.string:
                js_content += script.string + "\n"

        return js_content

    def _analyze_base_ids(self, js_content: str, html_content: str):
        """Analyze Airtable Base ID exposure"""

        # Airtable Base ID patterns (17 characters starting with app)
        base_id_patterns = [
            r'app[A-Za-z0-9]{15}',
            r'base["\']?\s*[:=]\s*["\'](app[A-Za-z0-9]{15})["\']',
            r'airtable\.com/([a-zA-Z0-9]{17})',
        ]

        content = js_content + html_content
        for pattern in base_id_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                if match not in self.base_ids:
                    self.base_ids.append(match)
                    
                    self.add_vulnerability(
                        "Airtable Base ID Exposure",
                        "Medium",
                        f"Airtable Base ID exposed: {match}",
                        match,
                        "Review Base ID usage and implement proper access controls",
                        category="Data Exposure",
                        owasp="A04:2021 - Insecure Design",
                        cwe=["CWE-200"]
                    )

    def _analyze_api_keys(self, js_content: str, html_content: str):
        """Check for Airtable API key exposure"""

        # Airtable API key patterns (starts with key)
        api_key_patterns = [
            r'key[A-Za-z0-9]{14,}',
            r'api[_-]?key["\']?\s*[:=]\s*["\'](key[A-Za-z0-9]{14,})["\']',
            r'authorization["\']?\s*[:=]\s*["\']Bearer\s+(key[A-Za-z0-9]{14,})["\']',
        ]

        content = js_content + html_content
        for pattern in api_key_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                if match not in self.api_keys:
                    self.api_keys.append(match)
                    
                    self.add_vulnerability(
                        "Airtable API Key Exposure",
                        "Critical",
                        f"Airtable API key exposed: {match[:10]}...",
                        match[:20],
                        "Immediately revoke exposed API key and use server-side proxy",
                        category="Secret Management",
                        owasp="A02:2021 - Cryptographic Failures",
                        cwe=["CWE-798", "CWE-319"]
                    )

    def _analyze_table_structure(self, js_content: str):
        """Analyze Airtable table structure exposure"""

        # Table name and field patterns
        table_patterns = [
            r'table["\']?\s*[:=]\s*["\']([^"\']+)["\']',
            r'fields["\']?\s*[:=]\s*\[([^\]]+)\]',
            r'records["\']?\s*[:=]\s*\[([^\]]+)\]',
        ]

        for pattern in table_patterns:
            matches = re.findall(pattern, js_content, re.IGNORECASE)
            for match in matches:
                if isinstance(match, tuple):
                    match = ' '.join(match)
                
                if match not in self.table_schemas:
                    self.table_schemas.append(match)
                    
                    # Check for sensitive field names
                    if any(sensitive in match.lower() for sensitive in ["email", "password", "phone", "ssn", "credit"]):
                        self.add_vulnerability(
                            "Sensitive Table Field Exposure",
                            "Medium",
                            f"Sensitive table structure exposed: {match}",
                            match,
                            "Review field permissions and data access rules",
                            category="Data Exposure",
                            owasp="A04:2021 - Insecure Design",
                            cwe=["CWE-200"]
                        )

    def _analyze_permissions(self, js_content: str):
        """Analyze permission model implementation"""

        # Permission-related patterns
        permission_patterns = [
            r'share["\']?\s*[:=]\s*["\']([^"\']+)["\']',
            r'permission["\']?\s*[:=]\s*["\']([^"\']+)["\']',
            r'access["\']?\s*[:=]\s*["\']([^"\']+)["\']',
            r'collaborator["\']?\s*[:=]\s*["\']([^"\']+)["\']',
        ]

        permissions_found = []
        for pattern in permission_patterns:
            matches = re.findall(pattern, js_content, re.IGNORECASE)
            for match in matches:
                if match not in permissions_found:
                    permissions_found.append(match)
                    self.permission_models.append(match)

        # Check for public access
        if any(perm.lower() in ["public", "anyone", "all"] for perm in permissions_found):
            self.add_vulnerability(
                "Public Access Configuration",
                "High",
                "Airtable base appears to have public access",
                "Public access patterns detected",
                "Review sharing settings and implement proper access controls",
                category="Access Control",
                owasp="A01:2021 - Broken Access Control",
                cwe=["CWE-284"]
            )

    def _analyze_data_access(self, js_content: str):
        """Analyze data access patterns"""

        # Data access patterns
        access_patterns = [
            r'select\([^)]*\)',
            r'query\([^)]*\)',
            r'filter\([^)]*\)',
            r'sort\([^)]*\)',
        ]

        for pattern in access_patterns:
            matches = re.findall(pattern, js_content, re.IGNORECASE)
            for match in matches:
                # Check for potentially unsafe queries
                if any(unsafe in match.lower() for unsafe in ["*", "all", "true"]):
                    self.add_vulnerability(
                        "Unsafe Data Access Pattern",
                        "Medium",
                        f"Potentially unsafe data access: {match}",
                        match,
                        "Review data access patterns and implement proper filtering",
                        category="Data Exposure",
                        owasp="A04:2021 - Insecure Design",
                        cwe=["CWE-89"]
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

    def _check_open_redirection(self, js_content: str):
        """Check for open redirection vulnerabilities"""
        redirect_patterns = [
            r'location\.href\s*=\s*["\']([^"\']+)["\']',
            r'window\.open\s*\(\s*["\']([^"\']+)["\']',
            r'redirect\s*[:=]\s*["\']([^"\']+)["\']',
        ]

        for pattern in redirect_patterns:
            matches = re.findall(pattern, js_content, re.IGNORECASE)
            for match in matches:
                if "http" in match and not match.startswith(("http://", "https://")):
                    self.add_vulnerability(
                        "Open Redirection",
                        "Medium",
                        f"Potential open redirection: {match}",
                        match,
                        "Validate and whitelist redirect URLs",
                        category="Server-Side Request Forgery",
                        owasp="A10:2021 - Server-Side Request Forgery",
                        cwe=["CWE-601"]
                    )

    def _check_ajax_header_manipulation(self, js_content: str):
        """Check for AJAX header manipulation"""
        ajax_patterns = [
            r'XMLHttpRequest',
            r'fetch\s*\(',
            r'\.ajax\s*\(',
        ]

        for pattern in ajax_patterns:
            if re.search(pattern, js_content, re.IGNORECASE):
                # Check for proper headers
                if "X-Requested-With" not in js_content:
                    self.add_vulnerability(
                        "Missing AJAX Security Headers",
                        "Low",
                        "AJAX requests may lack security headers",
                        "",
                        "Implement proper AJAX security headers",
                        category="Cross-Site Scripting",
                        owasp="A05:2021 - Security Misconfiguration",
                        cwe=["CWE-1007"]
                    )
                break

    def _check_hsts(self, response: requests.Response):
        """Check HSTS implementation"""
        hsts = response.headers.get("Strict-Transport-Security", "")
        if not hsts:
            self.add_vulnerability(
                "Missing HSTS Header",
                "Low",
                "No HSTS header found",
                "",
                "Implement HTTP Strict Transport Security",
                category="Security Headers",
                owasp="A05:2021 - Security Misconfiguration",
                cwe=["CWE-523"]
            )

    def _check_content_type_options(self, response: requests.Response):
        """Check X-Content-Type-Options"""
        xcto = response.headers.get("X-Content-Type-Options", "")
        if xcto != "nosniff":
            self.add_vulnerability(
                "Missing X-Content-Type-Options",
                "Low",
                "X-Content-Type-Options header missing or incorrect",
                xcto,
                "Set X-Content-Type-Options: nosniff",
                category="Security Headers",
                owasp="A05:2021 - Security Misconfiguration",
                cwe=["CWE-173"]
            )

    def _check_vulnerable_dependencies(self, js_content: str):
        """Check for potentially vulnerable dependencies"""
        library_patterns = [
            r'jquery[-.]?(\d+\.[\d\.]+)',
            r'bootstrap[-.]?(\d+\.[\d\.]+)',
            r'angular[-.]?(\d+\.[\d\.]+)',
        ]

        for pattern in library_patterns:
            matches = re.findall(pattern, js_content, re.IGNORECASE)
            for version in matches:
                # This is a simplified check - in practice, you'd use a vulnerability database
                if version.startswith(("1.", "2.", "3.")):  # Older versions
                    self.add_vulnerability(
                        "Potentially Vulnerable Dependency",
                        "Low",
                        f"Old library version detected: {version}",
                        version,
                        "Update to latest stable version",
                        category="Vulnerable Components",
                        owasp="A06:2021 - Vulnerable and Outdated Components",
                        cwe=["CWE-937"]
                    )
