#!/usr/bin/env python3
"""
Bubble.io Security Analyzer
Low-Code Platform Security Scanner

Specialized analyzer for Bubble.io applications with platform-specific
vulnerability detection and comprehensive traditional web vulnerability
scanning (XSS, SQLi, CSRF, Open Redirect, etc.).

Author: Bachelor Thesis Project - Low-Code Platforms Security Analysis
"""

import re
import socket
import ssl
from datetime import datetime
from typing import Any, Dict, List
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup

from .base import BaseAnalyzer
from .advanced_checks import AdvancedChecksMixin
from .common_web_checks import CommonWebChecksMixin
from .verification_metadata_mixin import VerificationMetadataMixin
from .vulnerability_detection import (
    XSSDetector,
    SQLInjectionDetector,
    CSRFDetector,
    OpenRedirectDetector,
)
from .enhanced_checks import EnhancedSecurityChecks
from ..utils.evidence_builder import EvidenceBuilder


class BubbleAnalyzer(CommonWebChecksMixin, AdvancedChecksMixin, VerificationMetadataMixin, BaseAnalyzer):
    """
    Specialized analyzer for Bubble.io applications.
    
    Provides comprehensive security analysis for Bubble.io low-code applications,
    detecting workflow exposures, database schema leaks, authentication issues,
    and privacy rule misconfigurations.
    """

    def __init__(self, session: requests.Session):
        """
        Initialize Bubble analyzer.
        
        Args:
            session: Configured requests session for HTTP operations
        """
        super().__init__(session)
        self.api_endpoints: List[str] = []
        self.workflow_patterns: List[Dict[str, Any]] = []
        self.database_schemas: List[Dict[str, Any]] = []
        self.privacy_rules: List[Dict[str, Any]] = []
        
        # Initialize vulnerability detectors
        self.xss_detector = XSSDetector(session)
        self.sqli_detector = SQLInjectionDetector(session)
        self.csrf_detector = CSRFDetector(session)
        self.redirect_detector = OpenRedirectDetector(session)
        
        # Initialize enhanced security checks
        self.enhanced_checks = EnhancedSecurityChecks(session)

    def analyze(
        self, url: str, response: requests.Response, soup: BeautifulSoup
    ) -> Dict[str, Any]:
        """
        Comprehensive Bubble.io security analysis.
        
        Args:
            url: Target URL being analyzed
            response: HTTP response from target
            soup: Parsed BeautifulSoup object
            
        Returns:
            Dictionary containing analysis results and vulnerabilities
        """
        
        # Record HTTP context for enriched vulnerability reporting
        self._record_http_context(url, response)

        # Extract JavaScript content for analysis
        js_content = self._extract_javascript(soup, url)
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
        self._check_hsts(response, url)
        self._check_content_type_options(response)
        self._check_vulnerable_dependencies(js_content)
        self._check_robots_txt(url)
        self._check_security_headers_informational(response)
        self._check_tls_certificate(url)
        self._check_stripe_public_keys(js_content, url)
        self._check_http2_support(url)
        self._check_request_url_override(url)
        self._check_cookie_domain_scoping(response, url)
        self._check_secret_uncached_url_input(url, response)
        self._check_dom_data_manipulation(js_content)
        self._check_cloud_resources(js_content + "\n" + html_content)
        self._check_secret_input_header_reflection(url)

        # COMPREHENSIVE VULNERABILITY DETECTION (Traditional Web Vulnerabilities)
        # Cross-Site Scripting (XSS) Detection - CRITICAL for Bubble (48 XSS instances in Burp)
        xss_vulns = self.xss_detector.detect_reflected_xss(url, response, html_content)
        for vuln in xss_vulns:
            evidence = f"Parameter: {vuln['parameter']}, Context: {vuln['context']}"
            self.add_enriched_vulnerability(
                vuln['type'],
                vuln['severity'],
                f"{vuln['type']} detected in parameter '{vuln['parameter']}'",
                evidence,
                "Implement output encoding, input validation, and Content Security Policy",
                category="Cross-Site Scripting",
                owasp="A03:2021 - Injection",
                cwe=["CWE-79"],
                background="Cross-Site Scripting (XSS) occurs when untrusted data is included in web pages without proper validation or escaping, allowing attackers to execute malicious scripts in victims' browsers.",
                impact="XSS can lead to session hijacking, defacement, malware distribution, data theft, and credential harvesting. Attackers can impersonate users, perform actions on their behalf, and steal sensitive data.",
                references=[
                    "https://owasp.org/www-community/attacks/xss/",
                    "https://cwe.mitre.org/data/definitions/79.html",
                    "https://portswigger.net/web-security/cross-site-scripting"
                ],
                parameter=vuln.get('parameter', ''),
                url=vuln.get('url', url),
                http_response=vuln.get('response')
            )

        # DOM-based XSS Detection
        dom_xss_vulns = self.xss_detector.detect_dom_xss(url, js_content)
        for vuln in dom_xss_vulns:
            evidence = f"Source: {vuln['source']}, Sink: {vuln['sink']}"
            self.add_enriched_vulnerability(
                vuln['type'],
                vuln['severity'],
                f"{vuln['type']} detected via DOM manipulation",
                evidence,
                "Avoid using dangerous DOM sinks with user-controlled data; use safe DOM APIs and validate input",
                category="Cross-Site Scripting",
                owasp="A03:2021 - Injection",
                cwe=["CWE-79"],
                background="DOM-based XSS vulnerabilities occur when the DOM is modified in an unsafe way using untrusted data from sources like location.hash or document.URL.",
                impact="DOM-based XSS is particularly dangerous as it bypasses server-side protections. Attackers can execute arbitrary JavaScript in the victim's browser context.",
                references=[
                    "https://owasp.org/www-community/attacks/DOM_Based_XSS",
                    "https://portswigger.net/web-security/cross-site-scripting/dom-based"
                ],
                parameter=vuln.get('parameter', ''),
                url=vuln.get('url', url),
                http_response=vuln.get('response')
            )

        # SQL Injection Detection
        sqli_vulns = self.sqli_detector.detect_sql_injection(url, response)
        for vuln in sqli_vulns:
            if vuln['type'] == 'SQL Injection':
                evidence = f"Parameter: {vuln.get('parameter', 'unknown')}"
                self.add_enriched_vulnerability(
                    vuln['type'],
                    vuln['severity'],
                    f"{vuln['type']} vulnerability detected in parameter '{vuln.get('parameter', 'unknown')}'",
                    evidence,
                    "Use parameterized queries, prepared statements, and input validation. Never concatenate user input into SQL queries.",
                    category="Injection",
                    owasp="A03:2021 - Injection",
                    cwe=["CWE-89"],
                    background="SQL Injection occurs when untrusted user input is included in SQL queries without proper sanitization, allowing attackers to manipulate database queries.",
                    impact="SQL injection can lead to data breaches, data loss, authentication bypass, privilege escalation, and in severe cases, complete server compromise.",
                    references=[
                        "https://owasp.org/www-community/attacks/SQL_Injection",
                        "https://cwe.mitre.org/data/definitions/89.html",
                        "https://portswigger.net/web-security/sql-injection"
                    ],
                    parameter=vuln.get('parameter', ''),
                    url=vuln.get('url', url),
                    http_response=vuln.get('response')
                )
            elif vuln['type'] == 'SQL Error Disclosure':
                self.add_enriched_vulnerability(
                    vuln['type'],
                    vuln['severity'],
                    "Database error messages are being disclosed to users",
                    "SQL error patterns found in response",
                    "Configure database error handling to display generic messages to users. Log detailed errors server-side.",
                    category="Information Disclosure",
                    owasp="A05:2021 - Security Misconfiguration",
                    cwe=["CWE-209"],
                    background="SQL error messages can reveal database structure, table names, column names, and implementation details to attackers.",
                    impact="SQL error disclosure assists attackers in crafting more precise SQL injection attacks and understanding the database schema.",
                    references=[
                        "https://cwe.mitre.org/data/definitions/209.html",
                        "https://owasp.org/www-project-web-security-testing-guide/"
                    ],
                    url=vuln.get('url', url),
                    http_response=vuln.get('response')
                )

        # CSRF Detection
        csrf_vulns = self.csrf_detector.detect_csrf(url, response, soup)
        for vuln in csrf_vulns:
            if vuln['type'] == 'Cross-Site Request Forgery (CSRF)':
                evidence = f"Form: {vuln['form_method']} {vuln['form_action']}, Missing: {vuln['missing_protection']}"
                self.add_enriched_vulnerability(
                    vuln['type'],
                    vuln['severity'],
                    f"{vuln['type']} vulnerability in form {vuln['form_index']}",
                    evidence,
                    "Implement anti-CSRF tokens in all state-changing forms. Verify SameSite cookie attributes. Use CSRF protection headers.",
                    category="Cross-Site Request Forgery",
                    owasp="A01:2021 - Broken Access Control",
                    cwe=["CWE-352"],
                    background="CSRF attacks force authenticated users to execute unwanted actions on a web application without their consent.",
                    impact="CSRF can lead to unauthorized transactions, password changes, email modifications, data deletion, and privilege escalation.",
                    references=[
                        "https://owasp.org/www-community/attacks/csrf",
                        "https://cwe.mitre.org/data/definitions/352.html",
                        "https://portswigger.net/web-security/csrf"
                    ],
                    url=vuln.get('url', url),
                    http_response=vuln.get('response')
                )
            elif vuln['type'] == 'Weak CSRF Protection':
                evidence = f"Form: {vuln['form_method']} {vuln['form_action']}, Issue: {vuln['issue']}"
                self.add_enriched_vulnerability(
                    vuln['type'],
                    vuln['severity'],
                    f"{vuln['type']} in form {vuln['form_index']}",
                    evidence,
                    "Implement SameSite=Strict or SameSite=Lax cookies. Use double-submit cookie pattern or custom CSRF tokens.",
                    category="Cross-Site Request Forgery",
                    owasp="A01:2021 - Broken Access Control",
                    cwe=["CWE-352"],
                    background="Weak CSRF protection may not prevent all CSRF attack vectors, especially in cross-origin scenarios.",
                    impact="Weak CSRF protection can still allow attackers to perform unauthorized actions on behalf of authenticated users, compromising data integrity.",
                    references=[
                        "https://owasp.org/www-community/attacks/csrf",
                        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie/SameSite"
                    ],
                    url=vuln.get('url', url),
                    http_response=vuln.get('response')
                )
            elif vuln['type'] == 'API CSRF Vulnerability':
                evidence = f"Method: {vuln['method']}, Issue: {vuln['issue']}"
                self.add_enriched_vulnerability(
                    vuln['type'],
                    vuln['severity'],
                    f"{vuln['type']} in API endpoint",
                    evidence,
                    "Implement CSRF tokens, verify Origin/Referer headers, or use custom headers like X-Requested-With for state-changing API calls.",
                    category="Cross-Site Request Forgery",
                    owasp="A01:2021 - Broken Access Control",
                    cwe=["CWE-352"],
                    background="API endpoints may be vulnerable to CSRF if they don't implement proper CSRF protection mechanisms.",
                    impact="API CSRF vulnerabilities can lead to unauthorized API calls, data modification, and privilege escalation. This is critical for Bubble's API endpoints.",
                    references=[
                        "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html"
                    ],
                    url=vuln.get('url', url),
                    http_response=vuln.get('response')
                )

        # Open Redirect Detection - CRITICAL for Bubble (102 instances in Burp)
        redirect_vulns = self.redirect_detector.detect_open_redirect(url, response, soup)
        for vuln in redirect_vulns:
            if vuln['type'] == 'Open Redirect':
                evidence = f"Parameter: {vuln['parameter']}"
                self.add_enriched_vulnerability(
                    vuln['type'],
                    vuln['severity'],
                    f"{vuln['type']} vulnerability detected in parameter '{vuln['parameter']}'",
                    evidence,
                    "Validate and whitelist redirect URLs. Use relative URLs where possible. Avoid using user input for redirect destinations.",
                    category="URL Redirection",
                    owasp="A01:2021 - Broken Access Control",
                    cwe=["CWE-601"],
                    background="Open redirect vulnerabilities occur when an application accepts user-controllable input that specifies a redirect URL without proper validation.",
                    impact="Attackers can redirect users to phishing sites, malware distribution, or malicious content, bypassing URL filtering and trust indicators. This is particularly dangerous for applications with authentication flows.",
                    references=[
                        "https://cwe.mitre.org/data/definitions/601.html",
                        "https://owasp.org/www-project-web-security-testing-guide/"
                    ],
                    parameter=vuln.get('parameter', ''),
                    url=vuln.get('url', url),
                    http_response=vuln.get('response')
                )
            elif vuln['type'] == 'Open Redirect via Meta Refresh':
                self.add_enriched_vulnerability(
                    vuln['type'],
                    vuln['severity'],
                    "Open redirect via meta refresh tag detected",
                    "Meta refresh with user-controlled URL parameter",
                    "Validate redirect URLs before using them in meta refresh tags. Use server-side redirects with proper validation.",
                    category="URL Redirection",
                    owasp="A01:2021 - Broken Access Control",
                    cwe=["CWE-601"],
                    background="Meta refresh tags can be abused for open redirect attacks if they incorporate user-controlled input.",
                    impact="Similar to standard open redirects, this can be used for phishing and malware distribution, exploiting user trust.",
                    references=[
                        "https://cwe.mitre.org/data/definitions/601.html"
                    ],
                    url=vuln.get('url', url),
                    http_response=vuln.get('response')
                )
            elif vuln['type'] == 'Potential Open Redirect via JavaScript':
                self.add_enriched_vulnerability(
                    vuln['type'],
                    vuln['severity'],
                    "Potential open redirect via JavaScript detected",
                    "JavaScript redirect code with user input",
                    "Review JavaScript redirect code to ensure URLs are validated and sanitized before use.",
                    category="URL Redirection",
                    owasp="A01:2021 - Broken Access Control",
                    cwe=["CWE-601"],
                    background="JavaScript-based redirects can be exploited for phishing if they incorporate user-controlled input without validation.",
                    impact="Attackers can craft malicious URLs that redirect victims to phishing sites or malicious content, exploiting user trust.",
                    references=[
                        "https://cwe.mitre.org/data/definitions/601.html"
                    ],
                    url=vuln.get('url', url),
                    http_response=vuln.get('response')
                )

        return {
            "api_endpoints": self.api_endpoints,
            "workflow_patterns": self.workflow_patterns,
            "database_schemas": self.database_schemas,
            "privacy_rules": self.privacy_rules,
            "vulnerabilities": self.vulnerabilities,
            "bubble_specific_findings": self.findings,
        }

    def _extract_javascript(self, soup: BeautifulSoup, base_url: str) -> str:
        """Extract all JavaScript content from the page"""
        js_content = ""

        # Extract inline scripts
        for script in soup.find_all("script"):
            if script.string:
                js_content += script.string + "\n"

        # Extract external scripts (bounded by scan profile)
        for _, content, _ in self._fetch_external_javascript(
            soup, base_url, limit=self.max_external_js_assets
        ):
            if content:
                js_content += content + "\n"

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
                    api_evidence = EvidenceBuilder.regex_pattern(
                        rf"(?i){re.escape(match)}",
                        f"Sensitive API endpoint: {match}"
                    )
                    self.add_enriched_vulnerability(
                        "Sensitive Bubble API Endpoint",
                        "High",
                        f"Sensitive API endpoint exposed: {match}",
                        api_evidence,
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
                    workflow_evidence = EvidenceBuilder.regex_pattern(
                        rf"(?i){re.escape(match)}",
                        f"Sensitive workflow pattern: {match}"
                    )
                    self.add_enriched_vulnerability(
                        "Sensitive Workflow Exposure",
                        "Medium",
                        f"Sensitive workflow exposed: {match}",
                        workflow_evidence,
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
                    self.add_enriched_vulnerability(
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
            privacy_evidence = EvidenceBuilder.exact_match(
                "Privacy rule patterns not found in JavaScript",
                "Missing privacy rules implementation"
            )
            self.add_enriched_vulnerability(
                "Missing Privacy Rules",
                "High",
                "No privacy rules implementation detected",
                privacy_evidence,
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

        js_content = self._extract_javascript(soup, url)
        auth_found = any(re.search(indicator, js_content, re.IGNORECASE) for indicator in auth_indicators)

        if not auth_found:
            self.add_enriched_vulnerability(
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
                self.add_enriched_vulnerability(
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
                self.add_enriched_vulnerability(
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
            self.add_enriched_vulnerability(
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
            {
                "pattern": r'(?i)(?:api[_-]?key|apikey|access[_-]?token|auth[_-]?token|client_secret|secret|password|passwd)\s*[:=]\s*["\']([^"\']{8,})["\']',
                "description": "Hardcoded credential/token",
                "group": 1,
            },
        ]

        placeholder_values = {
            "changeme",
            "change-me",
            "replace_me",
            "replace-me",
            "example",
            "sample",
            "test",
            "dummy",
            "your_api_key",
            "your-api-key",
            "yourapikey",
            "your_token",
            "your-token",
            "yourpassword",
        }

        for entry in secret_patterns:
            for match in re.finditer(entry["pattern"], js_content):
                value = match.group(entry["group"]).strip()
                value_lower = value.lower()

                if value_lower in placeholder_values:
                    continue

                if re.fullmatch(r"[xX*]{6,}", value):
                    continue

                self.add_enriched_vulnerability(
                    "Potential Secret in JavaScript",
                    "High",
                    f"{entry['description']} found in JavaScript: {value[:10]}...",
                    value[:20],
                    "Remove secrets from client-side code",
                    category="Secret Management",
                    owasp="A02:2021 - Cryptographic Failures",
                    cwe=["CWE-798"],
                    parameter=value,
                    url=url,
                )

    def _check_cookie_security(self, response: requests.Response):
        """Check cookie security headers"""
        cookies = self._get_set_cookie_headers(response)

        for cookie in cookies:
            cookie_name = cookie.split("=", 1)[0] if "=" in cookie else "Unknown"
            cookie_lower = cookie.lower()

            if "secure" not in cookie_lower:
                self.add_enriched_vulnerability(
                    "Insecure Cookie (Missing Secure Flag)",
                    "Medium",
                    f"Cookie '{cookie_name}' lacks Secure flag",
                    cookie[:100],
                    "Set the 'Secure' flag for all cookies to ensure they are only transmitted over HTTPS.",
                    category="Session Management",
                    owasp="A05:2021 - Security Misconfiguration",
                    cwe=["CWE-614"]
                )

    def _check_stripe_public_keys(self, js_content: str, url: str):
        """Detect Stripe publishable keys in client-side code."""
        pattern = r"\bpk_(live|test)_[A-Za-z0-9]{16,}\b"
        for match in re.finditer(pattern, js_content):
            key = match.group(0)
            self.add_enriched_vulnerability(
                "Stripe Publishable Key Exposure",
                "Info",
                "Stripe publishable key found in client-side code.",
                f"Key pattern: {key[:16]}...",
                "Ensure only publishable keys are used client-side; never expose secret keys.",
                category="Information Disclosure",
                owasp="A05:2021 - Security Misconfiguration",
                cwe=["CWE-200"],
                url=url,
            )

            if "httponly" not in cookie_lower:
                self.add_enriched_vulnerability(
                    "Cookie without HttpOnly Flag",
                    "Low",
                    f"Cookie '{cookie_name}' lacks HttpOnly flag",
                    cookie[:100],
                    "Set the 'HttpOnly' flag for all cookies to prevent them from being accessed by client-side scripts.",
                    category="Session Management",
                    owasp="A05:2021 - Security Misconfiguration",
                    cwe=["CWE-1004"]
                )

            if "samesite" not in cookie_lower:
                self.add_enriched_vulnerability(
                    "Cookie without SameSite Attribute",
                    "Low",
                    f"Cookie '{cookie_name}' lacks SameSite attribute",
                    cookie[:100],
                    "Set the 'SameSite' attribute (Lax or Strict) for all cookies to protect against CSRF attacks.",
                    category="Session Management",
                    owasp="A01:2021 - Broken Access Control",
                    cwe=["CWE-1275"]
                )

    def _check_csp_policy(self, response: requests.Response):
        """Check Content Security Policy"""
        csp = response.headers.get("Content-Security-Policy", "")
        if not csp:
            self.add_enriched_vulnerability(
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
            self.add_enriched_vulnerability(
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
                self.add_enriched_vulnerability(
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
                    self.add_enriched_vulnerability(
                        "Reflected Input (Potential XSS)",
                        "Medium",
                        f"Input parameter '{param}' is reflected in response",
                        f"{param}={value}",
                        "Implement output encoding and input validation",
                        category="Cross-Site Scripting",
                        owasp="A03:2021 - Injection",
                        cwe=["CWE-79"],
                        parameter=param,
                        url=url
                    )

    def _check_cacheable_https(self, response: requests.Response, url: str):
        """Check for cacheable HTTPS responses"""
        if not url.lower().startswith("https://"):
            return

        cache_control = response.headers.get("Cache-Control", "")
        pragma = response.headers.get("Pragma", "")
        cache_control_lower = cache_control.lower()

        if any(directive in cache_control_lower for directive in ["no-store", "no-cache", "private"]):
            return

        if "no-cache" in pragma.lower():
            return

        request_headers = {}
        if getattr(response, "request", None) is not None:
            request_headers = getattr(response.request, "headers", {}) or {}

        sensitive_request = any(
            header in request_headers for header in ["Authorization", "Cookie"]
        )

        sensitive_cookie_names = ["session", "auth", "token", "sid", "jwt", "sso"]
        sensitive_cookie = False
        for cookie in self._get_set_cookie_headers(response):
            cookie_name = cookie.split("=", 1)[0].strip().lower()
            if any(name in cookie_name for name in sensitive_cookie_names):
                sensitive_cookie = True
                break

        if not sensitive_request and not sensitive_cookie:
            return

        self.add_enriched_vulnerability(
            "Cacheable HTTPS Response",
            "Low",
            "Potentially cacheable HTTPS response detected; manual verification is required to confirm sensitive content exposure.",
            f"Cache-Control={cache_control} Pragma={pragma}",
            "Apply Cache-Control: no-store (or private, no-cache) to sensitive/authenticated pages and confirm behavior via manual testing.",
            confidence="Tentative",
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
                    self.add_enriched_vulnerability(
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
                    self.add_enriched_vulnerability(
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
                    self.add_enriched_vulnerability(
                        "Exposed Sensitive Endpoint",
                        "Info",
                        f"Potentially sensitive endpoint exposed: {match}",
                        match,
                        "Review exposed endpoints and implement proper access controls",
                        confidence="Tentative",
                        category="Information Disclosure",
                        owasp="A01:2021 - Broken Access Control",
                        cwe=["CWE-200"]
                    )

    def _check_hsts(self, response: requests.Response, url: str = ""):
        """Check HSTS implementation"""
        if url and not url.lower().startswith("https://"):
            return
        if hasattr(self, "_is_html_response") and not self._is_html_response(response):
            return
        hsts = response.headers.get("Strict-Transport-Security", "")
        if not hsts:
            self.add_enriched_vulnerability(
                "Missing HSTS Header",
                "Low",
                "No HSTS header found",
                "",
                "Implement HTTP Strict Transport Security",
                confidence="Tentative",
                category="Security Headers",
                owasp="A05:2021 - Security Misconfiguration",
                cwe=["CWE-523"]
            )

    def _check_content_type_options(self, response: requests.Response):
        """Check X-Content-Type-Options"""
        if hasattr(self, "_is_html_response") and not self._is_html_response(response):
            return
        xcto = response.headers.get("X-Content-Type-Options", "")
        if xcto != "nosniff":
            self.add_enriched_vulnerability(
                "Missing X-Content-Type-Options",
                "Info",
                "X-Content-Type-Options header missing or incorrect",
                xcto,
                "Set X-Content-Type-Options: nosniff",
                confidence="Tentative",
                category="Security Headers",
                owasp="A05:2021 - Security Misconfiguration",
                cwe=["CWE-173"]
            )

    def _check_vulnerable_dependencies(self, js_content: str):
        """Check for potentially vulnerable dependencies"""
        library_patterns = [
            (r'jquery[-.]?(\d+\.[\d\.]+)', "jQuery"),
            (r'bootstrap[-.]?(\d+\.[\d\.]+)', "Bootstrap"),
            (r'angular[-.]?(\d+\.[\d\.]+)', "Angular"),
        ]

        for pattern, library in library_patterns:
            matches = re.findall(pattern, js_content, re.IGNORECASE)
            for version in matches:
                severity = "Low"
                vuln_type = "Potentially Vulnerable Dependency"
                description = f"Old {library} version detected: {version}"
                if library.lower() == "jquery":
                    severity = "Medium"
                    vuln_type = "Outdated jQuery Version"
                    description = f"Outdated jQuery version detected: {version}"

                if version.startswith(("1.", "2.", "3.")):
                    self.add_enriched_vulnerability(
                        vuln_type,
                        severity,
                        description,
                        version,
                        "Update to the latest stable version of the library and monitor for security patches.",
                        category="Vulnerable Components",
                        owasp="A06:2021 - Vulnerable and Outdated Components",
                        cwe=["CWE-1104"],
                        background="Outdated third-party JavaScript libraries can contain known vulnerabilities that attackers exploit for XSS, prototype pollution, or other client-side attacks.",
                        impact="Using vulnerable libraries can lead to client-side compromise, data exposure, and malware injection. Attackers often target outdated jQuery versions for DOM-based XSS.",
                        references=[
                            "https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/",
                            "https://cwe.mitre.org/data/definitions/1104.html"
                        ]
                    )

    def _check_robots_txt(self, url: str):
        """Check robots.txt for information disclosure"""
        from urllib.parse import urljoin
        try:
            if int(getattr(self, "scan_depth", 1) or 1) <= 1:
                return
            robots_url = urljoin(url, "/robots.txt")
            response = self.session.get(
                robots_url,
                timeout=self._get_timeout_seconds(5),
                verify=getattr(self, "verify_ssl", True),
            )
            if response.status_code == 200:
                content = response.text
                # Look for sensitive entries
                if any(sensitive in content.lower() for sensitive in ["admin", "private", "secret"]):
                    self.add_enriched_vulnerability(
                        "Sensitive Information in robots.txt",
                        "Low",
                        "robots.txt contains sensitive information",
                        content[:100],
                        "Review robots.txt content",
                        confidence="Tentative",
                        category="Information Disclosure",
                        owasp="A09:2021 - Security Logging and Monitoring Failures",
                        cwe=["CWE-200"],
                        http_response=response,
                    )
        except Exception:
            pass

    def _check_security_headers_informational(self, response: requests.Response):
        """Check for missing security headers (informational)."""
        headers_to_check = [
            ("X-Frame-Options", "Low"),
            ("X-Content-Type-Options", "Low"),
            ("Content-Security-Policy", "Low"),
            ("Referrer-Policy", "Low"),
            ("Permissions-Policy", "Info"),
            ("X-Permitted-Cross-Domain-Policies", "Info"),
        ]

        for header, severity in headers_to_check:
            if header not in response.headers:
                self.add_enriched_vulnerability(
                    f"Missing {header} Header",
                    severity,
                    f"The {header} security header is missing",
                    "",
                    f"Implement the {header} header to enhance security.",
                    category="Security Headers",
                    owasp="A05:2021 - Security Misconfiguration",
                    cwe=["CWE-16"],
                )

    def _check_tls_certificate(self, url: str):
        """Check TLS certificate validity and expiration."""
        parsed = urlparse(url)
        if parsed.scheme != "https" or not parsed.hostname:
            return

        hostname = parsed.hostname
        port = parsed.port or 443

        try:
            context = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=6) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    if not cert:
                        raise ValueError("No certificate data returned")

                    not_after = cert.get("notAfter")
                    if not not_after:
                        raise ValueError("Certificate expiry not found")

                    expires_at = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                    days_remaining = (expires_at - datetime.utcnow()).days

                    if days_remaining < 0:
                        self.add_enriched_vulnerability(
                            "TLS Certificate Issues",
                            "Medium",
                            "TLS certificate has expired.",
                            f"Expired on {expires_at.isoformat()} ({days_remaining} days)",
                            "Renew the TLS certificate and ensure automated rotation before expiration.",
                            category="TLS/SSL Configuration",
                            owasp="A02:2021 - Cryptographic Failures",
                            cwe=["CWE-295"],
                            background="Expired TLS certificates prevent clients from verifying the server identity, enabling man-in-the-middle attacks.",
                            impact="Users may be exposed to interception or be unable to establish secure connections.",
                            references=["https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure"],
                        )
                    elif days_remaining < 14:
                        self.add_enriched_vulnerability(
                            "TLS Certificate Issues",
                            "Medium",
                            "TLS certificate is nearing expiration.",
                            f"Expires on {expires_at.isoformat()} ({days_remaining} days)",
                            "Rotate the TLS certificate promptly to avoid service disruption.",
                            category="TLS/SSL Configuration",
                            owasp="A02:2021 - Cryptographic Failures",
                            cwe=["CWE-295"],
                        )
        except Exception as exc:
            self.add_enriched_vulnerability(
                "TLS Certificate Issues",
                "Medium",
                "TLS certificate problems detected.",
                str(exc),
                "Investigate TLS certificate configuration and ensure a valid, trusted certificate is installed.",
                category="TLS/SSL Configuration",
                owasp="A02:2021 - Cryptographic Failures",
                cwe=["CWE-295"],
            )

    def _check_dom_open_redirect(self, js_content: str, url: str):
        """Detect DOM-based open redirect patterns."""
        patterns = [
            r"location\.href\s*=\s*[^;]+",
            r"window\.location\s*=\s*[^;]+",
            r"location\.assign\s*\(",
            r"location\.replace\s*\(",
        ]
        sources = [
            r"location\.search",
            r"location\.hash",
            r"document\.referrer",
            r"document\.url",
            r"document\.location",
        ]

        source_hits = any(re.search(source, js_content, re.IGNORECASE) for source in sources)
        if not source_hits:
            return

        for pattern in patterns:
            if re.search(pattern, js_content, re.IGNORECASE):
                self.add_enriched_vulnerability(
                    "DOM-based Open Redirect",
                    "Medium",
                    "Client-side code performs redirects using user-controllable DOM sources.",
                    "DOM sources (location/search/referrer) combined with redirect sinks detected",
                    "Validate redirect destinations and avoid using user-controlled data for navigation.",
                    category="URL Redirection",
                    owasp="A01:2021 - Broken Access Control",
                    cwe=["CWE-601"],
                    background="DOM-based open redirects occur when client-side scripts use untrusted input to set window.location values.",
                    impact="Attackers can craft links that redirect users to phishing or malware sites.",
                    references=["https://portswigger.net/web-security/dom-based/open-redirection"],
                )
                break
