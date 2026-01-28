#!/usr/bin/env python3
"""
Bubble.io Security Analyzer
Low-Code Platform Security Scanner

Specialized analyzer for Bubble.io applications with platform-specific
vulnerability detection.

Author: Bachelor Thesis Project - Low-Code Platforms Security Analysis
"""

import re
from typing import Any, Dict, List
from urllib.parse import urljoin

import requests
from bs4 import BeautifulSoup

from .base import BaseAnalyzer
from .advanced_checks import AdvancedChecksMixin


class BubbleAnalyzer(AdvancedChecksMixin, BaseAnalyzer):
    """Specialized analyzer for Bubble.io applications"""

    def __init__(self, session: requests.Session):
        super().__init__(session)
        self.api_endpoints = []
        self.workflow_patterns = []
        self.database_schemas = []
        self.privacy_rules = []

    def analyze(
        self, url: str, response: requests.Response, soup: BeautifulSoup
    ) -> Dict[str, Any]:
        """Comprehensive Bubble.io security analysis"""

        # Extract JavaScript content for analysis
        js_content = self._extract_javascript(soup)
        html_content = str(soup)

        # Analyze API endpoints
        self._analyze_api_endpoints(js_content)

        # Check for workflow exposure
        self._analyze_workflows(js_content)

        # Check for database schema exposure
        self._analyze_database_exposure(js_content)

        # Check for privacy rules implementation
        self._analyze_privacy_rules(js_content)

        # Check for authentication vulnerabilities
        self._analyze_authentication(url, response, soup)

        # Check for client-side data exposure
        self._analyze_client_side_data(js_content)

        # Analyze form security
        self._analyze_forms(soup)

        # Perform generic security checks
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
        self._check_linkfinder(js_content)
        self._check_hsts(response)
        self._check_content_type_options(response)
        self._check_vulnerable_dependencies(js_content)
        self._check_robots_txt(url)

        # NEW ENHANCED CHECKS - Bubble missing vulnerabilities
        self._check_http2_support(url)
        self._check_cookie_domain_scoping(response, url)
        self._check_cloud_resources(js_content + "\n" + html_content)
        self._check_secret_input_header_reflection(url)

        return {
            "api_endpoints": self.api_endpoints,
            "workflow_patterns": self.workflow_patterns,
            "database_schemas": self.database_schemas,
            "privacy_rules": self.privacy_rules,
            "vulnerabilities": self.vulnerabilities,
            "bubble_specific_findings": self.findings,
        }

    def _extract_javascript(self, soup: BeautifulSoup) -> str:
        """Extract all JavaScript content from the page"""
        js_content = ""

        # Extract inline scripts
        for script in soup.find_all("script"):
            if script.string:
                js_content += script.string + "\n"

        # Extract external scripts (attempt to fetch)
        for script in soup.find_all("script", src=True):
            try:
                script_url = urljoin(soup.base.get("href", ""), script["src"])
                script_response = self.session.get(script_url, timeout=5)
                if script_response.status_code == 200:
                    js_content += script_response.text + "\n"
            except Exception:
                pass  # Skip if unable to fetch external script

        return js_content

    def _analyze_api_endpoints(self, js_content: str):
        """Analyze Bubble API endpoints for security issues"""

        # Bubble API patterns
        api_patterns = [
            r'api/1\.1/wf/([^"\']+)',  # Workflow APIs
            r'api/1\.1/obj/([^"\']+)',  # Object APIs
            r'version-test/api/([^"\']+)',  # Version test APIs
        ]

        for pattern in api_patterns:
            matches = re.findall(pattern, js_content, re.IGNORECASE)
            for match in matches:
                self.api_endpoints.append(match)
                
                # Check for sensitive API names
                if any(sensitive in match.lower() for sensitive in ["admin", "delete", "user", "private"]):
                    self.add_vulnerability(
                        "Sensitive Bubble API Endpoint",
                        "High",
                        f"Sensitive API endpoint exposed: {match}",
                        match,
                        "Review API permissions and implement proper access controls",
                        category="API Security",
                        owasp="A01:2021 - Broken Access Control",
                        cwe=["CWE-284", "CWE-862"]
                    )

    def _analyze_workflows(self, js_content: str):
        """Analyze Bubble workflow patterns for security issues"""

        workflow_patterns = [
            r'workflow[^"\']*["\']([^"\']+)["\']',
            r'do[^"\']*["\']([^"\']+)["\']',
            r'run[^"\']*["\']([^"\']+)["\']',
        ]

        for pattern in workflow_patterns:
            matches = re.findall(pattern, js_content, re.IGNORECASE)
            for match in matches:
                self.workflow_patterns.append(match)

                # Check for sensitive workflow names
                if any(sensitive in match.lower() for sensitive in ["delete", "admin", "payment", "email"]):
                    self.add_vulnerability(
                        "Sensitive Workflow Exposure",
                        "Medium",
                        f"Sensitive workflow exposed: {match}",
                        match,
                        "Implement proper privacy rules for sensitive workflows",
                        category="Business Logic",
                        owasp="A01:2021 - Broken Access Control",
                        cwe=["CWE-284"]
                    )

    def _analyze_database_exposure(self, js_content: str):
        """Check for database schema exposure"""

        schema_patterns = [
            r'thing[^"\']*["\']([^"\']+)["\']',
            r'data[^"\']*["\']([^"\']+)["\']',
            r'field[^"\']*["\']([^"\']+)["\']',
        ]

        for pattern in schema_patterns:
            matches = re.findall(pattern, js_content, re.IGNORECASE)
            for match in matches:
                self.database_schemas.append(match)

                # Check for sensitive field names
                if any(sensitive in match.lower() for sensitive in ["password", "email", "phone", "address"]):
                    self.add_vulnerability(
                        "Database Schema Exposure",
                        "Medium",
                        f"Sensitive database field exposed: {match}",
                        match,
                        "Review privacy rules and data exposure settings",
                        category="Data Exposure",
                        owasp="A04:2021 - Insecure Design",
                        cwe=["CWE-200"]
                    )

    def _analyze_privacy_rules(self, js_content: str):
        """Analyze privacy rules implementation"""

        # Look for privacy rule patterns
        privacy_patterns = [
            r'privacy[^"\']*["\']([^"\']+)["\']',
            r'rule[^"\']*["\']([^"\']+)["\']',
            r'access[^"\']*["\']([^"\']+)["\']',
        ]

        privacy_found = False
        for pattern in privacy_patterns:
            if re.search(pattern, js_content, re.IGNORECASE):
                privacy_found = True
                break

        if not privacy_found:
            self.add_vulnerability(
                "Missing Privacy Rules",
                "High",
                "No privacy rules implementation detected",
                "No privacy patterns found in JavaScript",
                "Implement comprehensive privacy rules for all data access",
                category="Access Control",
                owasp="A01:2021 - Broken Access Control",
                cwe=["CWE-284"]
            )

    def _analyze_authentication(self, url: str, response: requests.Response, soup: BeautifulSoup):
        """Analyze authentication implementation"""

        # Check for authentication indicators
        auth_indicators = [
            r'current_user',
            r'user_id',
            r'logged_in',
            r'authentication',
        ]

        js_content = self._extract_javascript(soup)
        auth_found = any(re.search(indicator, js_content, re.IGNORECASE) for indicator in auth_indicators)

        if not auth_found:
            self.add_vulnerability(
                "Authentication Issues",
                "High",
                "No clear authentication implementation found",
                "No authentication patterns detected",
                "Implement proper user authentication and session management",
                category="Authentication",
                owasp="A07:2021 - Identification and Authentication Failures",
                cwe=["CWE-287", "CWE-307"]
            )

    def _analyze_client_side_data(self, js_content: str):
        """Check for client-side data exposure"""

        # Look for sensitive data patterns
        sensitive_patterns = [
            r'["\']([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})["\']',  # Emails
            r'["\'](\d{3}-?\d{3}-?\d{4})["\']',  # Phone numbers
            r'["\'](\d{4}[-\s]?){3}\d{4}["\']',  # Credit card patterns
        ]

        for pattern in sensitive_patterns:
            matches = re.findall(pattern, js_content)
            for match in matches:
                self.add_vulnerability(
                    "Client-side Data Exposure",
                    "High",
                    f"Sensitive data exposed in client-side code: {match[:10]}...",
                    match[:20],
                    "Remove sensitive data from client-side code",
                    category="Data Exposure",
                    owasp="A04:2021 - Insecure Design",
                    cwe=["CWE-200"]
                )

    def _analyze_forms(self, soup: BeautifulSoup):
        """Analyze form security"""

        forms = soup.find_all("form")
        for form in forms:
            # Check for CSRF protection
            csrf_input = form.find("input", {"name": re.compile(r"csrf", re.IGNORECASE)})
            if not csrf_input:
                self.add_vulnerability(
                    "Missing CSRF Protection",
                    "Medium",
                    "Form lacks CSRF protection",
                    str(form)[:100],
                    "Implement CSRF tokens for all forms",
                    category="Cross-Site Scripting",
                    owasp="A03:2021 - Injection",
                    cwe=["CWE-352"]
                )

    # Generic security check methods (would be implemented in base class or mixins)
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
        # Look for stack traces, error messages, etc.
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
        # Simple check for reflected parameters
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

    def _check_linkfinder(self, js_content: str):
        """Check for exposed links and endpoints"""
        url_patterns = [
            r'["\']https?://[^"\']+["\']',
            r'["\']/[^"\']*["\']',
        ]

        for pattern in url_patterns:
            matches = re.findall(pattern, js_content)
            for match in matches:
                # Check for sensitive endpoints
                if any(sensitive in match.lower() for sensitive in ["admin", "api", "config", "debug"]):
                    self.add_vulnerability(
                        "Exposed Sensitive Endpoint",
                        "Low",
                        f"Potentially sensitive endpoint exposed: {match}",
                        match,
                        "Review exposed endpoints and implement proper access controls",
                        category="Information Disclosure",
                        owasp="A01:2021 - Broken Access Control",
                        cwe=["CWE-200"]
                    )

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

    def _check_robots_txt(self, url: str):
        """Check robots.txt for information disclosure"""
        from urllib.parse import urljoin
        try:
            robots_url = urljoin(url, "/robots.txt")
            response = self.session.get(robots_url, timeout=5)
            if response.status_code == 200:
                content = response.text
                # Look for sensitive entries
                if any(sensitive in content.lower() for sensitive in ["admin", "private", "secret"]):
                    self.add_vulnerability(
                        "Sensitive Information in robots.txt",
                        "Low",
                        "robots.txt contains sensitive information",
                        content[:100],
                        "Review robots.txt content",
                        category="Information Disclosure",
                        owasp="A09:2021 - Security Logging and Monitoring Failures",
                        cwe=["CWE-200"]
                    )
        except Exception:
            pass
