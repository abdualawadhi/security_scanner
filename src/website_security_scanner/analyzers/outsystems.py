#!/usr/bin/env python3
"""
OutSystems Security Analyzer
Low-Code Platform Security Scanner

Specialized analyzer for OutSystems applications with platform-specific
vulnerability detection and comprehensive traditional web vulnerability
scanning (XSS, SQLi, CSRF, Open Redirect, etc.).

Author: Bachelor Thesis Project - Low-Code Platforms Security Analysis
"""

import re
import secrets
from typing import Any, Dict, List
from urllib.parse import urlparse

import requests
from bs4 import BeautifulSoup

from .base import BaseAnalyzer
from .advanced_checks import AdvancedChecksMixin
from .vulnerability_detection import (
    XSSDetector,
    SQLInjectionDetector,
    CSRFDetector,
    OpenRedirectDetector,
)
from ..utils.evidence_builder import EvidenceBuilder


class OutSystemsAnalyzer(AdvancedChecksMixin, BaseAnalyzer):
    """
    Specialized analyzer for OutSystems applications.
    
    Provides comprehensive security analysis for OutSystems low-code applications,
    detecting REST API exposures, screen action vulnerabilities, entity leaks,
    and role-based access control misconfigurations.
    """

    def __init__(self, session: requests.Session):
        """
        Initialize OutSystems analyzer.
        
        Args:
            session: Configured requests session for HTTP operations
        """
        super().__init__(session)
        self.rest_apis: List[str] = []
        self.screen_actions: List[Dict[str, Any]] = []
        self.entities: List[Dict[str, Any]] = []
        
        # Initialize vulnerability detectors
        self.xss_detector = XSSDetector(session)
        self.sqli_detector = SQLInjectionDetector(session)
        self.csrf_detector = CSRFDetector(session)
        self.redirect_detector = OpenRedirectDetector(session)

    def analyze(
        self, url: str, response: requests.Response, soup: BeautifulSoup
    ) -> Dict[str, Any]:
        """
        Comprehensive OutSystems security analysis.
        
        Args:
            url: Target URL being analyzed
            response: HTTP response from target
            soup: Parsed BeautifulSoup object
            
        Returns:
            Dictionary containing analysis results and vulnerabilities
        """
        
        # Record HTTP context for enriched vulnerability reporting
        self._record_http_context(url, response)

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

        # Check for Host Header Injection
        self._check_host_header_injection(url)

        # Check for missing Content-Type
        self._check_missing_content_type(response)

        # Check for X-Content-Type-Options
        self._check_x_content_type_options(response)

        # Check for informational security headers
        self._check_security_headers_informational(response)

        # NEW DETECTIONS - Enhanced coverage
        # Check for HTTP/2 protocol support (Hidden HTTP/2)
        self._check_http2_support(url)

        # Check for request URL override
        self._check_request_url_override(url)

        # Check cookie domain scoping
        self._check_cookie_domain_scoping(response, url)

        # Check for cloud resource exposure
        self._check_cloud_resources(js_content)

        # Check for secret uncached URL input
        self._check_secret_uncached_url_input(url, response)

        # Check for DOM data manipulation
        self._check_dom_data_manipulation(js_content)

        # Advanced header analysis (Burp: Secret input: header)
        self._check_secret_input_header_reflection(url)

        # COMPREHENSIVE VULNERABILITY DETECTION (Traditional Web Vulnerabilities)
        # Cross-Site Scripting (XSS) Detection
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
                ]
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
                ]
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
                    impact="SQL injection can lead to data breach, data loss, authentication bypass, privilege escalation, and in severe cases, complete server compromise.",
                    references=[
                        "https://owasp.org/www-community/attacks/SQL_Injection",
                        "https://cwe.mitre.org/data/definitions/89.html",
                        "https://portswigger.net/web-security/sql-injection"
                    ]
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
                    ]
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
                    ]
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
                    impact="Weak CSRF protection can still allow attackers to perform unauthorized actions on behalf of authenticated users.",
                    references=[
                        "https://owasp.org/www-community/attacks/csrf",
                        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie/SameSite"
                    ]
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
                    impact="API CSRF vulnerabilities can lead to unauthorized API calls, data modification, and privilege escalation.",
                    references=[
                        "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html"
                    ]
                )

        # Open Redirect Detection
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
                    impact="Attackers can redirect users to phishing sites, malware distribution, or malicious content, bypassing URL filtering and trust indicators.",
                    references=[
                        "https://cwe.mitre.org/data/definitions/601.html",
                        "https://owasp.org/www-project-web-security-testing-guide/"
                    ]
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
                    impact="Similar to standard open redirects, this can be used for phishing and malware distribution.",
                    references=[
                        "https://cwe.mitre.org/data/definitions/601.html"
                    ]
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
                    impact="Attackers can craft malicious URLs that redirect victims to phishing sites or malicious content.",
                    references=[
                        "https://cwe.mitre.org/data/definitions/601.html"
                    ]
                )

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
                    api_evidence = EvidenceBuilder.regex_pattern(
                        rf"(?i){re.escape(match)}",
                        f"Sensitive REST API endpoint: {match}"
                    )
                    self.add_enriched_vulnerability(
                        "Sensitive REST API Exposure",
                        "High",
                        f"Potentially sensitive REST API exposed: {match}",
                        api_evidence,
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
                    action_evidence = EvidenceBuilder.regex_pattern(
                        rf"(?i){re.escape(match)}",
                        f"Privileged screen action: {match}"
                    )
                    self.add_enriched_vulnerability(
                        "Privileged Action Exposure",
                        "Medium",
                        f"Privileged screen action found: {match}",
                        action_evidence,
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
                    self.add_enriched_vulnerability(
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
            session_evidence = EvidenceBuilder.exact_match(
                "Session management patterns not found in JavaScript",
                "Missing session management implementation"
            )
            self.add_enriched_vulnerability(
                "Session Management Issues",
                "Medium",
                "No clear session management implementation found",
                session_evidence,
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
            self.add_enriched_vulnerability(
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
        session_params = [
            'session', 'token', 'sid', 'sessionid', 'session_id',
            'session_code', 'state', 'nonce', 'auth_token', 'code'
        ]
        
        found_params = []
        for param in session_params:
            if re.search(rf'[?&]{param}=', url, re.IGNORECASE):
                found_params.append(param)
                
        if found_params:
            self.add_enriched_vulnerability(
                "Session Token in URL",
                "Medium",
                f"Session-related token(s) found in URL: {', '.join(found_params)}",
                url,
                "Use secure cookies for session management and avoid passing tokens in URLs. Use POST bodies or Authorization headers instead.",
                category="Session Management",
                owasp="A07:2021 - Identification and Authentication Failures",
                cwe=["CWE-384", "CWE-598"],
                background="Sensitive information, such as session tokens, should not be passed in the URL. URLs can be logged by servers, proxies, and browser history, leading to token leakage.",
                impact="If session tokens are leaked, attackers can hijack user sessions and perform unauthorized actions on behalf of the user.",
                references=["https://owasp.org/www-community/vulnerabilities/Information_exposure_through_query_strings_in_url"]
            )

    def _check_secrets_in_javascript(self, js_content: str, url: str):
        """Check for secrets in JavaScript"""
        secret_patterns = [
            (r'["\']([A-Za-z0-9]{32,})["\']', "Potential API key/token"),
            (r'(?i)password["\']?\s*[:=]\s*["\']([^"\']+)["\']', "Hardcoded password"),
            (r'(?i)secret["\']?\s*[:=]\s*["\']([^"\']+)["\']', "Hardcoded secret"),
            (r'(?i)apikey["\']?\s*[:=]\s*["\']([^"\']+)["\']', "Hardcoded API key"),
            (r'(?i)FailShowPassword\s*:\s*["\']([^"\']+)["\']', "OutSystems specific secret"),
            (r'OSUI-API-[0-9]{5}', "OutSystems UI API Key pattern")
        ]

        for pattern, desc in secret_patterns:
            matches = re.findall(pattern, js_content)
            for match in matches:
                # Basic entropy/length check to reduce false positives
                if len(match) > 5:
                    self.add_enriched_vulnerability(
                        "Potential Secret in JavaScript",
                        "High",
                        f"{desc} found in JavaScript: {match[:10]}...",
                        f"Pattern: {desc}, Match: {match[:20]}",
                        "Remove all hardcoded secrets, API keys, and passwords from client-side JavaScript. Use server-side configuration or secure vault services.",
                        category="Secret Management",
                        owasp="A02:2021 - Cryptographic Failures",
                        cwe=["CWE-798"],
                        background="Hardcoding secrets in client-side code makes them visible to anyone who can access the application. This is a common source of credential leakage.",
                        impact="Exposed secrets can lead to unauthorized access to APIs, databases, and third-party services, potentially resulting in data breaches.",
                        references=["https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure"]
                    )

    def _check_cookie_security(self, response: requests.Response):
        """Check cookie security headers"""
        cookies = self._get_set_cookie_headers(response)
        
        for cookie in cookies:
            cookie_name = cookie.split('=')[0] if '=' in cookie else "Unknown"
            
            if "Secure" not in cookie:
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
                
            if "HttpOnly" not in cookie:
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
                
            if "SameSite" not in cookie:
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
        patterns = [
            (r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', "Email address"),
            (r'\b(?:10|127|172\.(?:1[6-9]|2[0-9]|3[0-1])|192\.168)\..*?\b', "Private IP address"),
            (r'(?i)error[:\s]+["\']([^"\']+)["\']', "Error message"),
            (r'(?i)exception[:\s]+["\']([^"\']+)["\']', "Exception message"),
            (r'(?i)stack\s*trace', "Stack trace"),
            (r'OutSystemsUI', "OutSystems UI version info")
        ]

        for pattern, desc in patterns:
            matches = re.findall(pattern, js_content + html_content)
            if matches:
                self.add_enriched_vulnerability(
                    "Information Disclosure",
                    "Info",
                    f"Potential {desc} disclosure found in client-side content",
                    f"Found {len(matches)} instance(s) of {desc}",
                    "Review the disclosed information to ensure it doesn't reveal sensitive details about the application or infrastructure.",
                    category="Information Disclosure",
                    owasp="A09:2021 - Security Logging and Monitoring Failures",
                    cwe=["CWE-200"]
                )

    def _check_security_headers_informational(self, response: requests.Response):
        """Check for security headers with Informational severity as per Burp report"""
        headers_to_check = [
            ("Referrer-Policy", "Low"),
            ("Permissions-Policy", "Info"),
            ("X-Permitted-Cross-Domain-Policies", "Info")
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
                    cwe=["CWE-16"]
                )

    def _check_reflected_input(self, url: str, response: requests.Response, html_content: str):
        """Check for reflected input (potential XSS)"""
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
                        cwe=["CWE-79"]
                    )

    def _check_path_relative_stylesheets(self, soup: BeautifulSoup):
        """Check for path-relative stylesheet imports"""
        link_tags = soup.find_all("link", rel="stylesheet")
        for link in link_tags:
            href = link.get("href", "")
            if href.startswith("/") and not href.startswith("//"):
                self.add_enriched_vulnerability(
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
            self.add_enriched_vulnerability(
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
                    self.add_enriched_vulnerability(
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

    def _check_host_header_injection(self, url: str):
        """Active check for Host Header Injection"""
        parsed = urlparse(url)
        if not parsed.hostname:
            return

        test_host = f"evil-{secrets.token_hex(4)}.com"
        headers = {
            'Host': test_host,
            'X-Forwarded-Host': test_host,
            'X-Forwarded-For': '1.2.3.4',
            'Forwarded': f'for=1.2.3.4;host={test_host};proto=https'
        }

        try:
            # Test X-Forwarded-Host injection
            resp = self.session.get(url, headers={'X-Forwarded-Host': test_host}, timeout=5, allow_redirects=False)
            if test_host in resp.text or test_host in resp.headers.get('Location', ''):
                self.add_enriched_vulnerability(
                    "Host Header Injection (X-Forwarded-Host)",
                    "Medium",
                    "Application reflects X-Forwarded-Host header, potentially allowing cache poisoning or password reset poisoning",
                    f"X-Forwarded-Host: {test_host} reflected in response",
                    "Configure the web server to only trust the Host header and ignore or sanitize X-Forwarded-Host headers. Validate the Host header against a whitelist of allowed domains.",
                    category="Injection",
                    owasp="A03:2021 - Injection",
                    cwe=["CWE-644"],
                    background="Host header injection occurs when an application incorrectly handles the Host header or related headers like X-Forwarded-Host. Attackers can use this to manipulate links generated by the application.",
                    impact="Can lead to web cache poisoning, password reset poisoning, and redirection to malicious sites.",
                    references=["https://portswigger.net/web-security/host-header-injection"]
                )
        except Exception:
            pass

    def _check_missing_content_type(self, response: requests.Response):
        """Check for missing Content-Type header"""
        if 'Content-Type' not in response.headers:
            self.add_enriched_vulnerability(
                "Missing Content-Type Header",
                "Medium",
                "The response does not contain a Content-Type header",
                "",
                "Ensure all responses include an appropriate Content-Type header to prevent MIME-type sniffing attacks.",
                category="Security Headers",
                owasp="A05:2021 - Security Misconfiguration",
                cwe=["CWE-436"]
            )

    def _check_x_content_type_options(self, response: requests.Response):
        """Check for missing X-Content-Type-Options header"""
        if response.headers.get('X-Content-Type-Options', '').lower() != 'nosniff':
            self.add_enriched_vulnerability(
                "X-Content-Type-Options Header Missing",
                "Low",
                "X-Content-Type-Options: nosniff header is missing or incorrectly configured",
                response.headers.get('X-Content-Type-Options', 'Missing'),
                "Add 'X-Content-Type-Options: nosniff' header to all responses.",
                category="Security Headers",
                owasp="A05:2021 - Security Misconfiguration",
                cwe=["CWE-16"],
                background="The X-Content-Type-Options response HTTP header is a marker used by the server to indicate that the MIME types advertised in the Content-Type headers should be followed and not be changed.",
                impact="MIME-sniffing can lead to security vulnerabilities where a browser interprets a response in a different way than intended, potentially leading to XSS.",
                references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options"]
            )

    def _check_http2_support(self, url: str):
        """Check for HTTP/2 protocol support (Hidden HTTP/2)"""
        try:
            import ssl
            import socket

            # Parse URL to get host
            from urllib.parse import urlparse
            parsed = urlparse(url)
            host = parsed.hostname
            port = parsed.port or (443 if parsed.scheme == 'https' else 80)

            # Create SSL context to check HTTP/2 support
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection((host, port)) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    # Check if HTTP/2 is supported via ALPN
                    negotiated_protocol = ssock.selected_alpn_protocol()
                    if negotiated_protocol == 'h2':
                        self.add_enriched_vulnerability(
                            "Hidden HTTP/2",
                            "Info",
                            "Origin advertises HTTP/2 (h2) via ALPN; ensure HTTP/2-specific hardening (HPACK/DoS controls, reverse-proxy config).",
                            f"HTTP/2 protocol negotiated: {negotiated_protocol}",
                            "Ensure HTTP/2-specific security controls are implemented including HPACK compression controls and DoS protection.",
                            category="Protocol",
                            owasp="A05:2021 - Security Misconfiguration",
                            cwe=["CWE-16"],
                            background="HTTP/2 introduces new attack vectors compared to HTTP/1.1, including HPACK compression attacks and request multiplexing vulnerabilities.",
                            impact="HTTP/2-specific attacks could bypass traditional protections. HPACK compression can be exploited for DoS attacks.",
                            references=[
                                "https://portswigger.net/research/http2",
                                "https://cwe.mitre.org/data/definitions/16.html"
                            ]
                        )
        except Exception:
            # If we can't check HTTP/2, don't report an error
            pass

    def _check_request_url_override(self, url: str):
        """Check for request URL override vulnerabilities"""
        # This would check for URL override parameters that could be manipulated
        # For now, implement a basic check for common override parameters
        try:
            from urllib.parse import urlparse, parse_qs
            parsed = urlparse(url)
            query_params = parse_qs(parsed.query)

            override_params = ['url', 'redirect', 'return', 'next', 'continue', 'goto', 'dest']
            for param in override_params:
                if param in query_params:
                    self.add_enriched_vulnerability(
                        "Request URL Override",
                        "Low",
                        f"URL override parameter '{param}' found in request",
                        f"Parameter '{param}' with value: {query_params[param][0][:100]}...",
                        "Validate and sanitize URL parameters that control redirects or resource loading.",
                        category="Injection",
                        owasp="A03:2021 - Injection",
                        cwe=["CWE-601"],
                        background="URL override parameters can be manipulated by attackers to redirect users to malicious sites or load unauthorized resources.",
                        impact="Can lead to phishing attacks, open redirect vulnerabilities, and unauthorized resource access.",
                        references=["https://owasp.org/www-community/attacks/Open_redirect"]
                    )
        except Exception:
            pass

    def _check_cookie_domain_scoping(self, response: requests.Response, url: str):
        """Check for cookie domain scoping issues"""
        try:
            from urllib.parse import urlparse
            parsed = urlparse(url)
            site_domain = parsed.hostname

            for cookie_header in response.headers.getlist('Set-Cookie'):
                # Parse cookie manually since we don't have http.cookies
                cookie_parts = cookie_header.split(';')
                cookie_name_value = cookie_parts[0].strip()
                cookie_attrs = [part.strip() for part in cookie_parts[1:]]

                domain_attr = None
                for attr in cookie_attrs:
                    if attr.lower().startswith('domain='):
                        domain_attr = attr.split('=', 1)[1].strip()
                        break

                if domain_attr:
                    # Check if domain is too broad
                    if not (domain_attr == site_domain or site_domain.endswith('.' + domain_attr)):
                        self.add_enriched_vulnerability(
                            "Cookie Domain Scoping Issue",
                            "Low",
                            f"Cookie domain '{domain_attr}' is too broad for site '{site_domain}'",
                            f"Cookie: {cookie_name_value}, Domain: {domain_attr}",
                            "Set cookie domain to the most specific domain possible, preferably omit domain attribute for host-only cookies.",
                            category="Cookie Security",
                            owasp="A05:2021 - Security Misconfiguration",
                            cwe=["CWE-565"],
                            background="Overly broad cookie domains can allow cookies to be sent to unintended subdomains, potentially exposing them to attacks.",
                            impact="Cookies may be sent to unintended domains, increasing attack surface and potential for cookie theft.",
                            references=["https://tools.ietf.org/html/rfc6265#section-4.1.2.3"]
                        )
        except Exception:
            pass

    def _check_cloud_resources(self, js_content: str):
        """Check for exposed cloud resources in JavaScript"""
        import re

        # Patterns for cloud resource URLs
        cloud_patterns = [
            r'https?://[^\'"]*\.s3\.amazonaws\.com[^\'"]*',
            r'https?://[^\'"]*\.blob\.core\.windows\.net[^\'"]*',
            r'https?://[^\'"]*\.googleapis\.com[^\'"]*',
            r'https?://[^\'"]*\.cloudfront\.net[^\'"]*',
            r'https?://storage\.googleapis\.com[^\'"]*'
        ]

        for pattern in cloud_patterns:
            matches = re.findall(pattern, js_content, re.IGNORECASE)
            for match in matches:
                if 'private' not in match.lower() and 'signed' not in match.lower():
                    self.add_enriched_vulnerability(
                        "Cloud Resource Exposure",
                        "Medium",
                        "Potentially exposed cloud storage resource found in JavaScript",
                        f"Resource URL: {match[:100]}...",
                        "Ensure cloud storage resources are properly secured with appropriate access controls and signed URLs.",
                        category="Information Disclosure",
                        owasp="A01:2021 - Broken Access Control",
                        cwe=["CWE-284"],
                        background="Cloud storage resources that are publicly accessible can expose sensitive data or allow unauthorized access.",
                        impact="Sensitive data may be exposed to unauthorized users, leading to data breaches or further attacks.",
                        references=[
                            "https://owasp.org/www-project-top-ten/OWASP_Top_Ten_2017/Top_10-2017_A5-Broken_Access_Control",
                            "https://cwe.mitre.org/data/definitions/284.html"
                        ]
                    )

    def _check_secret_uncached_url_input(self, url: str, response: requests.Response):
        """Check for secret input in uncached URL parameters"""
        try:
            from urllib.parse import urlparse, parse_qs
            parsed = urlparse(url)
            query_params = parse_qs(parsed.query)

            # Check for potential secrets in URL parameters
            secret_indicators = ['key', 'token', 'secret', 'password', 'api_key', 'apikey', 'auth', 'session']
            cache_headers = response.headers.get('Cache-Control', '').lower()

            # If response is not cached (no-store, private, etc.), check for secrets
            if 'no-store' in cache_headers or 'private' in cache_headers:
                for param_name, param_values in query_params.items():
                    if any(indicator in param_name.lower() for indicator in secret_indicators):
                        for value in param_values:
                            if len(value) > 10:  # Only flag potentially sensitive values
                                self.add_enriched_vulnerability(
                                    "Secret in Uncached URL",
                                    "Medium",
                                    f"Potential secret found in URL parameter '{param_name}'",
                                    f"Parameter value: {value[:50]}... (response not cached)",
                                    "Avoid placing secrets in URL parameters. Use POST requests or secure headers for sensitive data.",
                                    category="Information Disclosure",
                                    owasp="A02:2021 - Cryptographic Failures",
                                    cwe=["CWE-598"],
                                    background="Secrets in URL parameters can be logged by proxies, stored in browser history, and leaked through referrer headers.",
                                    impact="Secrets may be exposed in logs, browser history, or referrer headers, compromising security.",
                                    references=[
                                        "https://cwe.mitre.org/data/definitions/598.html",
                                        "https://owasp.org/www-community/attacks/Password_in_URL"
                                    ]
                                )
        except Exception:
            pass

    def _check_dom_data_manipulation(self, js_content: str):
        """Check for DOM data manipulation vulnerabilities"""
        import re

        # Look for dangerous DOM sinks with user-controlled data
        dangerous_patterns = [
            r'innerHTML\s*=\s*[^;]+',
            r'outerHTML\s*=\s*[^;]+',
            r'document\.write\s*\([^)]+\)',
            r'document\.writeln\s*\([^)]+\)',
            r'eval\s*\([^)]+\)',
            r'setTimeout\s*\([^)]*eval[^)]*\)',
            r'setInterval\s*\([^)]*eval[^)]*\)'
        ]

        for pattern in dangerous_patterns:
            matches = re.findall(pattern, js_content, re.IGNORECASE)
            for match in matches:
                if 'location.' in match or 'document.' in match or 'window.' in match:
                    self.add_enriched_vulnerability(
                        "DOM Data Manipulation",
                        "Medium",
                        "Potentially dangerous DOM manipulation with user-controlled data",
                        f"Code pattern: {match[:100]}...",
                        "Avoid using dangerous DOM sinks with untrusted data. Use safe alternatives like textContent or proper sanitization.",
                        category="Cross-Site Scripting",
                        owasp="A03:2021 - Injection",
                        cwe=["CWE-79"],
                        background="DOM-based XSS occurs when untrusted data is used in dangerous DOM operations without proper validation or sanitization.",
                        impact="Can lead to XSS attacks where malicious scripts are executed in users' browsers.",
                        references=[
                            "https://owasp.org/www-community/attacks/DOM_Based_XSS",
                            "https://portswigger.net/web-security/cross-site-scripting/dom-based"
                        ]
                    )

    def _check_secret_input_header_reflection(self, url: str):
        """Check for secret input reflected in headers"""
        try:
            # This would typically check if secrets from input are reflected in response headers
            # For now, implement a basic check by making a test request
            import requests
            from urllib.parse import urlparse

            parsed = urlparse(url)
            test_params = {
                'test_secret': 'secret_value_123',
                'api_key': 'test_key_456'
            }

            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            if parsed.query:
                test_url += f"?{parsed.query}&test_secret=secret_value_123&api_key=test_key_456"
            else:
                test_url += "?test_secret=secret_value_123&api_key=test_key_456"

            # Use the session from the analyzer
            response = self.session.get(test_url, timeout=10)

            # Check if our test secrets appear in response headers
            for header_name, header_value in response.headers.items():
                if 'secret_value_123' in header_value or 'test_key_456' in header_value:
                    self.add_enriched_vulnerability(
                        "Secret Input Header Reflection",
                        "Medium",
                        f"User input reflected in response header '{header_name}'",
                        f"Header value: {header_value[:100]}...",
                        "Avoid reflecting user input in response headers. Validate and sanitize all input before use.",
                        category="Injection",
                        owasp="A03:2021 - Injection",
                        cwe=["CWE-79"],
                        background="When user input is reflected in HTTP headers without proper validation, it can lead to header injection attacks.",
                        impact="Can lead to HTTP header injection, cache poisoning, or other injection-based attacks.",
                        references=[
                            "https://owasp.org/www-community/attacks/HTTP_Response_Splitting",
                            "https://cwe.mitre.org/data/definitions/79.html"
                        ]
                    )
        except Exception:
            # Don't fail if the test request doesn't work
            pass
