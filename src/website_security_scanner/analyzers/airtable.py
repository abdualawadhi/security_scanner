#!/usr/bin/env python3
"""
Airtable Security Analyzer
Low-Code Platform Security Scanner

Specialized analyzer for Airtable applications with platform-specific
vulnerability detection and comprehensive traditional web vulnerability
scanning (XSS, SQLi, CSRF, Open Redirect, etc.).

Author: Bachelor Thesis Project - Low-Code Platforms Security Analysis
"""

import re
import base64
from typing import Any, Dict, List
from urllib.parse import urlparse, parse_qs

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


class AirtableAnalyzer(AdvancedChecksMixin, BaseAnalyzer):
    """
    Specialized analyzer for Airtable applications.
    
    Provides comprehensive security analysis for Airtable low-code applications,
    detecting exposures of base IDs, API keys, table schemas, and permission
    configurations that could lead to unauthorized data access.
    """

    def __init__(self, session: requests.Session):
        """
        Initialize Airtable analyzer.
        
        Args:
            session: Configured requests session for HTTP operations
        """
        super().__init__(session)
        self.base_ids: List[str] = []
        self.api_keys: List[str] = []
        self.table_schemas: List[Dict[str, Any]] = []
        self.permission_models: List[Dict[str, Any]] = []
        
        # Initialize vulnerability detectors
        self.xss_detector = XSSDetector(session)
        self.sqli_detector = SQLInjectionDetector(session)
        self.csrf_detector = CSRFDetector(session)
        self.redirect_detector = OpenRedirectDetector(session)

    def analyze(
        self, url: str, response: requests.Response, soup: BeautifulSoup
    ) -> Dict[str, Any]:
        """Comprehensive Airtable security analysis"""

        # Record HTTP context for use in enriched vulnerabilities
        self._record_http_context(url, response)

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
        self._check_referrer_policy(response)
        self._check_permissions_policy(response)
        self._check_other_security_headers(response)
        self._check_vulnerable_dependencies(js_content)

        # NEW ENHANCED CHECKS - Airtable-specific missing vulnerabilities
        self._check_http2_support(url)
        self._check_request_url_override(url)
        self._check_cookie_domain_scoping(response, url)
        self._check_secret_uncached_url_input(url, response)
        self._check_dom_data_manipulation(js_content)

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
                    impact="SQL injection can lead to data breaches, data loss, authentication bypass, privilege escalation, and in severe cases, complete server compromise.",
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

        # CSRF Detection (CRITICAL for Airtable - Burp found 28 instances)
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
                    impact="CSRF can lead to unauthorized transactions, password changes, email modifications, data deletion, and privilege escalation. Airtable's state-changing operations are particularly at risk.",
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
                    impact="Weak CSRF protection can still allow attackers to perform unauthorized actions on behalf of authenticated users, compromising data integrity.",
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
                    impact="API CSRF vulnerabilities can lead to unauthorized API calls, data modification, and privilege escalation. This is critical for Airtable's REST API.",
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
                    impact="Similar to standard open redirects, this can be used for phishing and malware distribution, exploiting user trust.",
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
                    impact="Attackers can craft malicious URLs that redirect victims to phishing sites or malicious content, exploiting user trust.",
                    references=[
                        "https://cwe.mitre.org/data/definitions/601.html"
                    ]
                )

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
                    
                    # Create evidence pattern for Base ID highlighting
                    base_id_evidence = {
                        "type": "regex",
                        "pattern": rf"(?i){re.escape(match)}"
                    }
                    
                    self.add_enriched_vulnerability(
                        "Airtable Base ID Exposure",
                        "Medium",
                        f"Airtable Base ID exposed: {match}",
                        base_id_evidence,  # Pass evidence dict for highlighting
                        "Review Base ID usage and implement proper access controls",
                        category="Data Exposure",
                        owasp="A04:2021 - Insecure Design",
                        cwe=["CWE-200"],
                        background=(
                            "Airtable bases are identified by Base IDs which are used in API calls "
                            "and internal routing. Exposing Base IDs can facilitate reconnaissance "
                            "and unauthorized API usage when combined with leaked credentials."
                        ),
                        impact=(
                            "An attacker who obtains valid Base IDs can more easily target specific bases, "
                            "attempt credential stuffing against corresponding APIs, or correlate other leaked "
                            "information to pivot into data exfiltration attacks."
                        ),
                        references=[
                            "https://support.airtable.com/docs/airtable-api-overview",
                            "https://owasp.org/www-community/attacks/Threat_Agents",
                        ],
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
                    
                    # Create evidence pattern for API key highlighting
                    api_key_evidence = {
                        "type": "regex",
                        "pattern": rf"(?i){re.escape(match[:20])}"
                    }
                    
                    self.add_enriched_vulnerability(
                        "Airtable API Key Exposure",
                        "Critical",
                        f"Airtable API key exposed: {match[:10]}...",
                        api_key_evidence,  # Pass evidence dict for highlighting
                        "Immediately revoke exposed API key and use server-side proxy",
                        category="Secret Management",
                        owasp="A02:2021 - Cryptographic Failures",
                        cwe=["CWE-798", "CWE-319"],
                        background=(
                            "Airtable API keys provide full access to bases and can be used to "
                            "read, write, and delete data. These keys are typically long-lived "
                            "credentials that should never be exposed in client-side code."
                        ),
                        impact=(
                            "An exposed API key allows attackers to directly access and manipulate "
                            "Airtable data, potentially leading to data theft, modification, or "
                            "complete compromise of the base. This can result in data breaches, "
                            "service disruption, and compliance violations."
                        ),
                        references=[
                            "https://support.airtable.com/docs/api-keys",
                            "https://owasp.org/www-project-top-ten/2021/A02_2021-Cryptographic_Failures/",
                            "https://cwe.mitre.org/data/definitions/798.html",
                        ],
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
                        self.add_enriched_vulnerability(
                            "Sensitive Table Field Exposure",
                            "Medium",
                            f"Sensitive table structure exposed: {match}",
                            match,
                            "Review field permissions and data access rules",
                            category="Data Exposure",
                            owasp="A04:2021 - Insecure Design",
                            cwe=["CWE-200"],
                            background=(
                                "Airtable applications often expose table structures and field names in client-side "
                                "JavaScript. When sensitive field names (like email, password, SSN) are exposed, it "
                                "provides attackers with valuable information about the data schema and can help "
                                "them craft more targeted attacks."
                            ),
                            impact=(
                                "Exposed sensitive field names allow attackers to understand the data structure, "
                                "facilitate data mining attacks, and potentially exploit field-level vulnerabilities. "
                                "This can lead to privacy violations and help attackers focus their efforts on the "
                                "most valuable data targets."
                            ),
                            references=[
                                "https://support.airtable.com/docs/field-types",
                                "https://owasp.org/www-project-top-ten/2021/A04_2021-Insecure_Design/",
                                "https://cwe.mitre.org/data/definitions/200.html",
                            ],
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
            self.add_enriched_vulnerability(
                "Public Access Configuration",
                "High",
                "Airtable base appears to have public access",
                "Public access patterns detected",
                "Review sharing settings and implement proper access controls",
                category="Access Control",
                owasp="A01:2021 - Broken Access Control",
                cwe=["CWE-284"],
                background=(
                    "Airtable allows bases to be shared publicly with 'anyone with the link' access. "
                    "While convenient for collaboration, public access exposes all data to unauthorized "
                    "viewing and potential data harvesting by automated bots and malicious actors."
                ),
                impact=(
                    "Public access allows anyone with the link to view, copy, or download all data in the base. "
                    "This can lead to data breaches, privacy violations, and loss of intellectual property. "
                    "Sensitive business data, customer information, or proprietary content becomes accessible "
                    "to anyone who discovers the sharing link."
                ),
                references=[
                    "https://support.airtable.com/docs/sharing-bases",
                    "https://owasp.org/www-project-top-ten/2021/A01_2021-Broken_Access_Control/",
                    "https://cwe.mitre.org/data/definitions/284.html",
                ],
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
                    # Create evidence pattern for data access highlighting
                    data_access_evidence = {
                        "type": "regex",
                        "pattern": rf"(?i){re.escape(match)}"
                    }
                    
                    self.add_enriched_vulnerability(
                        "Unsafe Data Access Pattern",
                        "Medium",
                        f"Potentially unsafe data access: {match}",
                        data_access_evidence,
                        "Review data access patterns and implement proper filtering",
                        category="Data Exposure",
                        owasp="A04:2021 - Insecure Design",
                        cwe=["CWE-89"],
                        background=(
                            "Client-side code appears to construct broad or unfiltered data queries (e.g., using '*' or 'all'). "
                            "This can expose more rows or columns than intended and makes authorization defects easier to exploit."
                        ),
                        impact=(
                            "If an attacker can influence or exploit these broad queries, they may retrieve full tables or sensitive "
                            "records, instead of just minimal data needed for the UI."
                        ),
                        references=[
                            "https://owasp.org/www-project-top-ten/2021/A01_2021-Broken_Access_Control/",
                            "https://cwe.mitre.org/data/definitions/89.html",
                        ],
                    )

    def _check_session_tokens_in_url(self, url: str):
        """Check for session tokens in URL"""
        # More comprehensive list of session/auth related parameters
        token_params = [
            "session", "token", "sid", "auth", "state", "nonce", "code",
            "access_token", "id_token", "session_id", "session_code"
        ]
        pattern = r'[?&](' + '|'.join(token_params) + r')='
        
        if re.search(pattern, url, re.IGNORECASE):
            # Create evidence pattern for session token highlighting
            session_evidence = {
                "type": "regex",
                "pattern": r"(?i)[?&](" + "|".join(token_params) + r")=[^&\s]*"
            }
            
            self.add_enriched_vulnerability(
                "Session Token in URL",
                "Medium",
                "Session token or authentication parameter found in URL query string",
                session_evidence,
                "Use secure, HttpOnly cookies for session management and pass authentication tokens in the Authorization header or POST body.",
                category="Session Management",
                owasp="A07:2021 - Identification and Authentication Failures",
                cwe=["CWE-598", "CWE-523"],
                background=(
                    "Putting session IDs, authentication tokens, or OAuth2 state/nonce parameters in URLs is insecure "
                    "because URLs are logged in many places (browser history, server logs, analytics tools, SIEM) "
                    "and can be leaked via Referer headers to third-party sites."
                ),
                impact=(
                    "If an attacker obtains such a URL from logs or via Referer headers, they may be able to hijack "
                    "active user sessions, perform replay attacks, or bypass authentication to access the Airtable "
                    "application with the victim's privileges."
                ),
                references=[
                    "https://owasp.org/www-community/vulnerabilities/Information_exposure_through_query_strings_in_url",
                    "https://cwe.mitre.org/data/definitions/598.html",
                    "https://cwe.mitre.org/data/definitions/523.html",
                ],
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
                    # Create evidence pattern for secret highlighting
                    secret_evidence = {
                        "type": "regex",
                        "pattern": rf"(?i){re.escape(match[:20])}"
                    }
                    
                    self.add_enriched_vulnerability(
                        "Potential Secret in JavaScript",
                        "High",
                        f"Potential secret found in JavaScript: {match[:10]}...",
                        secret_evidence,
                        "Remove secrets from client-side code",
                        category="Secret Management",
                        owasp="A02:2021 - Cryptographic Failures",
                        cwe=["CWE-798"],
                        background=(
                            "Secrets embedded in JavaScript code are exposed to anyone who can access the application. "
                            "This includes API keys, passwords, tokens, and other sensitive credentials that should "
                            "never be stored in client-side code."
                        ),
                        impact=(
                            "Exposed secrets allow attackers to directly access backend services, APIs, or databases. "
                            "This can lead to complete system compromise, data breaches, and unauthorized access to "
                            "critical systems and data."
                        ),
                        references=[
                            "https://owasp.org/www-project-top-ten/2021/A02_2021-Cryptographic_Failures/",
                            "https://cwe.mitre.org/data/definitions/798.html",
                            "https://github.com/GitHubSecrets/GitHubSecrets",
                        ],
                    )

    def _check_cookie_security(self, response: requests.Response):
        """Check cookie security attributes"""
        set_cookies = response.headers.get("Set-Cookie", "")
        if not set_cookies:
            return

        # Check for missing Secure attribute on cookies in HTTPS sessions
        if "Secure" not in set_cookies:
            # Create evidence pattern to highlight Set-Cookie header lines
            cookie_evidence = {
                "type": "regex",
                "pattern": r"(?i)^Set-Cookie:.*",
            }
            
            self.add_enriched_vulnerability(
                "Cookie Without Secure Attribute",
                "Low",
                "Cookie lacks the 'Secure' attribute",
                cookie_evidence,
                "Set the 'Secure' attribute for all cookies. Ensure the application is only served over HTTPS.",
                category="Session Management",
                owasp="A05:2021 - Security Misconfiguration",
                cwe=["CWE-614"],
                background=(
                    "The 'Secure' attribute instructs the browser to only transmit the cookie over encrypted (HTTPS) connections. "
                    "When this attribute is missing, the cookie may be sent over unencrypted HTTP, making it vulnerable to interception."
                ),
                impact=(
                    "Insecure cookies can be intercepted by an attacker using man-in-the-middle (MITM) techniques "
                    "on insecure networks (like public Wi-Fi), leading to session hijacking and unauthorized account access."
                ),
                references=[
                    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie#Secure",
                    "https://cwe.mitre.org/data/definitions/614.html",
                    "https://owasp.org/www-community/vulnerabilities/Insecure_Cookie"
                ],
            )

        # Check for missing HttpOnly attribute
        if "HttpOnly" not in set_cookies:
            self.add_enriched_vulnerability(
                "Cookie Without HttpOnly Attribute",
                "Low",
                "Cookie lacks the 'HttpOnly' attribute",
                {"type": "regex", "pattern": r"(?i)^Set-Cookie:.*"},
                "Set the 'HttpOnly' attribute for all sensitive cookies to prevent client-side script access.",
                category="Session Management",
                owasp="A05:2021 - Security Misconfiguration",
                cwe=["CWE-1004"],
                background=(
                    "The 'HttpOnly' attribute prevents client-side scripts (like JavaScript) from accessing the cookie, "
                    "which is a critical defense against session theft via Cross-Site Scripting (XSS)."
                ),
                impact=(
                    "If an XSS vulnerability exists, an attacker can steal the session cookie and hijack the user's "
                    "session if the 'HttpOnly' attribute is missing."
                ),
                references=[
                    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie#HttpOnly",
                    "https://cwe.mitre.org/data/definitions/1004.html"
                ],
            )

    def _check_csp_policy(self, response: requests.Response):
        """Check Content Security Policy"""
        csp = response.headers.get("Content-Security-Policy", "")
        if not csp:
            self.add_enriched_vulnerability(
                "Missing Content Security Policy",
                "Low",
                "No CSP header found",
                [],
                "Implement a strong Content Security Policy to mitigate XSS and other injection attacks.",
                category="Security Headers",
                owasp="A05:2021 - Security Misconfiguration",
                cwe=["CWE-693"],
                background=(
                    "Content Security Policy (CSP) is an added layer of security that helps to detect and mitigate certain types of attacks, "
                    "including Cross-Site Scripting (XSS) and data injection attacks."
                ),
                impact=(
                    "The absence of a CSP makes the application more vulnerable to XSS attacks, as it allows the browser to execute "
                    "any script from any source, including malicious ones injected by an attacker."
                ),
                references=[
                    "https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP",
                    "https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html"
                ],
            )
        else:
            # Check for unsafe-inline in script-src or style-src
            csp_lower = csp.lower()
            if "unsafe-inline" in csp_lower:
                severity = "Medium"
                description = "Content Security Policy contains 'unsafe-inline' directive"
                
                if "style-src" in csp_lower and "unsafe-inline" in csp_lower:
                    description += ", allowing arbitrary style execution"
                    
                self.add_enriched_vulnerability(
                    "Weak Content Security Policy",
                    severity,
                    description,
                    {"type": "exact", "pattern": f"Content-Security-Policy: {csp[:200]}"},
                    "Remove 'unsafe-inline' from CSP directives. Use nonces or hashes instead.",
                    category="Security Headers",
                    owasp="A05:2021 - Security Misconfiguration",
                    cwe=["CWE-693", "CWE-116", "CWE-79"],
                    background=(
                        "Using 'unsafe-inline' in CSP allows the execution of inline scripts or styles, which significantly "
                        "weakens the security provided by CSP. Specifically, 'unsafe-inline' in style-src can allow an attacker "
                        "to perform style-based data exfiltration."
                    ),
                    impact=(
                        "An attacker can bypass CSP protections to execute malicious scripts (if in script-src) or "
                        "manipulate page styles to exfiltrate sensitive data or perform UI redressing."
                    ),
                    references=[
                        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/style-src",
                        "https://portswigger.net/research/blind-css-exfiltration"
                    ],
                )
            
            # Check for missing form-action (allows form hijacking)
            if "form-action" not in csp_lower:
                self.add_enriched_vulnerability(
                    "Weak Content Security Policy",
                    "Low",
                    "CSP lacks 'form-action' directive, allowing potential form hijacking",
                    {"type": "exact", "pattern": f"Content-Security-Policy: {csp[:200]}"},
                    "Add a 'form-action' directive to your CSP to restrict where forms can be submitted.",
                    category="Security Headers",
                    owasp="A05:2021 - Security Misconfiguration",
                    cwe=["CWE-693"],
                    background=(
                        "The 'form-action' directive restricts the URLs which can be used as the target of a form submission from a given context. "
                        "Without this directive, forms can be hijacked via HTML injection to send sensitive data to an attacker's server."
                    ),
                    impact=(
                        "An attacker with HTML injection capabilities could hijack forms on the page to steal user credentials or other "
                        "sensitive information submitted via forms."
                    ),
                    references=[
                        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/form-action",
                        "https://portswigger.net/web-security/cross-site-scripting/content-security-policy"
                    ],
                )
            
            # Check for other weak patterns
            weak_patterns = ["unsafe-eval", "*", "data:"]
            found_weak = [p for p in weak_patterns if p in csp_lower]
            if found_weak:
                self.add_enriched_vulnerability(
                    "Weak Content Security Policy",
                    "Low",
                    f"CSP contains weak directives: {', '.join(found_weak)}",
                    {"type": "exact", "pattern": f"Content-Security-Policy: {csp[:200]}"},
                    "Review and tighten CSP directives to follow the principle of least privilege.",
                    category="Security Headers",
                    owasp="A05:2021 - Security Misconfiguration",
                    cwe=["CWE-693"],
                    background="Weak CSP directives like '*' or 'unsafe-eval' provide limited protection against sophisticated attacks.",
                    impact="Attackers may be able to bypass CSP to execute arbitrary code or load malicious resources.",
                    references=["https://csp-evaluator.withgoogle.com/"]
                )

    def _check_clickjacking(self, response: requests.Response):
        """Check for clickjacking protection"""
        xfo = response.headers.get("X-Frame-Options", "")
        if not xfo:
            self.add_enriched_vulnerability(
                "Missing Clickjacking Protection",
                "Low",
                "No X-Frame-Options header",
                [],  # Pass evidence as 4th positional parameter
                "Implement X-Frame-Options header",
                category="Security Headers",
                owasp="A05:2021 - Security Misconfiguration",
                cwe=["CWE-693"],
                background=(
                    "X-Frame-Options header prevents your website from being embedded in an iframe, "
                    "protecting against clickjacking attacks where malicious sites overlay invisible frames "
                    "to trick users into clicking on unintended elements."
                ),
                impact=(
                    "Without X-Frame-Options, attackers can embed your site in malicious frames and perform "
                    "clickjacking attacks, potentially leading to unauthorized actions, credential theft, "
                    "or other security breaches."
                ),
                references=[
                    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options",
                    "https://owasp.org/www-community/attacks/Clickjacking",
                    "https://cwe.mitre.org/data/definitions/693.html",
                ],
            )
        elif xfo.lower() in ["allow-from", "sameorigin"]:
            # Highlight weak X-Frame-Options when present
            xfo_evidence = {
                "type": "exact",
                "pattern": f"X-Frame-Options: {xfo}",
            }
            
            self.add_enriched_vulnerability(
                "Weak Clickjacking Protection",
                "Low",
                f"Weak X-Frame-Options value: {xfo}",
                xfo_evidence,  # Pass evidence as 4th positional parameter
                "Use DENY or SAMEORIGIN with proper validation",
                category="Security Headers",
                owasp="A05:2021 - Security Misconfiguration",
                cwe=["CWE-693"],
                background=(
                    "X-Frame-Options should use 'DENY' or 'SAMEORIGIN' for proper protection. "
                    "The 'allow-from' directive is deprecated and may not be supported by all browsers."
                ),
                impact=(
                    "Weak X-Frame-Options values may not provide adequate protection against clickjacking "
                    "attacks, potentially allowing malicious sites to embed your content in unintended ways."
                ),
                references=[
                    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options",
                    "https://owasp.org/www-community/attacks/Clickjacking",
                    "https://cwe.mitre.org/data/definitions/693.html",
                ],
            )

    def _check_information_disclosure(self, js_content: str, html_content: str, response: requests.Response):
        """Check for information disclosure"""
        error_patterns = [
            r'error[:\s]+["\']([^"\']+)["\']',
            r'exception[:\s]+["\']([^"\']+)["\']',
            r'stack\s*trace',
        ]
        
        # Email address pattern
        email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'

        content = js_content + html_content
        
        for pattern in error_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                # Create evidence pattern for error highlighting
                error_evidence = {
                    "type": "regex",
                    "pattern": pattern
                }
                
                self.add_enriched_vulnerability(
                    "Information Disclosure",
                    "Low",
                    "Potential error information exposed",
                    error_evidence,
                    "Review error handling and remove sensitive error details",
                    category="Information Disclosure",
                    owasp="A05:2021 - Security Misconfiguration",
                    cwe=["CWE-200"],
                    background=(
                        "Error messages that contain detailed technical information can reveal "
                        "internal application structure, database schemas, or system configuration. "
                        "Attackers can use this information to craft more targeted attacks."
                    ),
                    impact=(
                        "Information disclosure in error messages provides attackers with valuable "
                        "reconnaissance data about your application's internal workings, potentially "
                        "leading to more effective exploitation attempts."
                    ),
                    references=[
                        "https://owasp.org/www-project-top-ten/2021/A05_2021-Security_Misconfiguration/",
                        "https://cwe.mitre.org/data/definitions/200.html",
                    ],
                )
                break

        # Check for email disclosure
        emails = re.findall(email_pattern, content)
        if emails:
            # Filter out common false positives if necessary
            unique_emails = list(set(emails))[:5]  # Limit to 5
            self.add_enriched_vulnerability(
                "Email Address Disclosure",
                "Info",
                f"Email addresses found in response: {', '.join(unique_emails)}",
                {"type": "regex", "pattern": email_pattern},
                "Review if these email addresses should be publicly visible and implement masking if necessary.",
                category="Information Disclosure",
                owasp="A01:2021 - Broken Access Control",
                cwe=["CWE-200"],
                background="Disclosure of email addresses can facilitate phishing attacks and reconnaissance.",
                impact="Attackers can use discovered email addresses for targeted phishing or social engineering attacks.",
                references=["https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/03-Identity_Management_Testing/01-Test_Role_Definitions"]
            )

    def _check_reflected_input(self, url: str, response: requests.Response, html_content: str):
        """Check for reflected input (potential XSS)"""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        for param, values in params.items():
            for value in values:
                if value in html_content:
                    # Create evidence pattern for reflected input highlighting
                    reflected_evidence = {
                        "type": "regex",
                        "pattern": rf"(?i){re.escape(value)}"
                    }
                    
                    self.add_enriched_vulnerability(
                        "Reflected Input (Potential XSS)",
                        "Medium",
                        f"Input parameter '{param}' is reflected in response",
                        reflected_evidence,
                        "Implement output encoding and input validation",
                        category="Cross-Site Scripting",
                        owasp="A03:2021 - Injection",
                        cwe=["CWE-79"],
                        background=(
                            "Reflected input occurs when user-supplied data appears in the HTTP response "
                            "without proper encoding or validation. This can enable Cross-Site Scripting (XSS) "
                            "attacks where malicious scripts execute in victims' browsers."
                        ),
                        impact=(
                            "Reflected XSS allows attackers to inject malicious scripts that execute in "
                            "the context of other users' browsers, potentially leading to session hijacking, "
                            "credential theft, or unauthorized actions on behalf of the victim."
                        ),
                        references=[
                            "https://owasp.org/www-project-top-ten/2021/A03_2021-Injection/",
                            "https://cwe.mitre.org/data/definitions/79.html",
                            "https://portswigger.net/web-security/cross-site-scripting/reflected",
                        ],
                    )

    def _check_cacheable_https(self, response: requests.Response, url: str):
        """Check for cacheable HTTPS responses"""
        cache_control = response.headers.get("Cache-Control", "")
        if "no-store" not in cache_control and url.startswith("https://"):
            # Create evidence pattern for Cache-Control header highlighting
            cache_evidence = {
                "type": "regex",
                "pattern": r"(?i)^Cache-Control:.*"
            } if cache_control else []
            
            self.add_enriched_vulnerability(
                "Cacheable HTTPS Response",
                "Low",
                "HTTPS response may be cached",
                cache_evidence,
                "Implement proper cache control for sensitive pages",
                category="Security Headers",
                owasp="A05:2021 - Security Misconfiguration",
                cwe=["CWE-525"],
                background=(
                    "HTTPS responses without proper cache control headers may be stored by "
                    "intermediate caches, potentially exposing sensitive data to unauthorized parties "
                    "who can access cached content."
                ),
                impact=(
                    "Cacheable HTTPS responses can lead to sensitive information being stored "
                    "in shared caches, allowing unauthorized access to private data and potentially "
                    "violating privacy regulations."
                ),
                references=[
                    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cache-Control",
                    "https://owasp.org/www-project-top-ten/2021/A05_2021-Security_Misconfiguration/",
                    "https://cwe.mitre.org/data/definitions/525.html",
                ],
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
                    # Create evidence pattern for redirect highlighting
                    redirect_evidence = {
                        "type": "regex",
                        "pattern": rf"(?i){re.escape(match)}"
                    }
                    
                    self.add_enriched_vulnerability(
                        "Open Redirection",
                        "Medium",
                        f"Potential open redirection: {match}",
                        redirect_evidence,
                        "Validate and whitelist redirect URLs",
                        category="Server-Side Request Forgery",
                        owasp="A10:2021 - Server-Side Request Forgery",
                        cwe=["CWE-601"],
                        background=(
                            "Open redirection vulnerabilities occur when applications accept user-controlled "
                            "input that specifies a redirect destination without proper validation. Attackers can "
                            "exploit this to redirect users to malicious sites."
                        ),
                        impact=(
                            "Open redirection can be used for phishing attacks, malware distribution, or "
                            "bypassing authentication mechanisms. Attackers can redirect legitimate users to "
                            "malicious sites that appear trustworthy."
                        ),
                        references=[
                            "https://owasp.org/www-project-top-ten/2021/A10_2021-Server-Side_Request_Forgery/",
                            "https://cwe.mitre.org/data/definitions/601.html",
                            "https://portswigger.net/web-security/web-server-request-smuggling",
                        ],
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
                    # Create evidence pattern for AJAX highlighting
                    ajax_evidence = {
                        "type": "regex",
                        "pattern": pattern
                    }
                    
                    self.add_enriched_vulnerability(
                        "Missing AJAX Security Headers",
                        "Low",
                        "AJAX requests may lack security headers",
                        ajax_evidence,
                        "Implement proper AJAX security headers",
                        category="Cross-Site Scripting",
                        owasp="A05:2021 - Security Misconfiguration",
                        cwe=["CWE-1007"],
                        background=(
                            "AJAX requests without proper security headers like X-Requested-With can be "
                            "vulnerable to CSRF attacks. These headers help servers distinguish between legitimate "
                            "AJAX requests and malicious cross-site requests."
                        ),
                        impact=(
                            "Missing AJAX security headers increases the risk of CSRF attacks, where malicious "
                            "websites can make unauthorized AJAX requests on behalf of authenticated users, potentially "
                            "leading to data theft or unauthorized actions."
                        ),
                        references=[
                            "https://owasp.org/www-project-cheat-sheets/cheatsheets/Cross_Site_Request_Forgery_Cheat_Sheet.html",
                            "https://developer.mozilla.org/en-US/docs/Web/API/XMLHttpRequest",
                            "https://cwe.mitre.org/data/definitions/1007.html",
                        ],
                    )
                break

    def _check_hsts(self, response: requests.Response):
        """Check HSTS implementation"""
        hsts = response.headers.get("Strict-Transport-Security", "")
        if not hsts:
            self.add_enriched_vulnerability(
                "Missing HSTS Header",
                "Low",
                "No HSTS header found",
                [],  # Pass evidence as 4th positional parameter
                "Implement HTTP Strict Transport Security",
                category="Security Headers",
                owasp="A05:2021 - Security Misconfiguration",
                cwe=["CWE-523"],
                background=(
                    "HTTP Strict Transport Security (HSTS) enforces HTTPS connections and protects against "
                    "protocol downgrade attacks and cookie hijacking. Without HSTS, browsers may fall back to HTTP "
                    "if the HTTPS connection fails."
                ),
                impact=(
                    "Missing HSTS allows attackers to perform SSL stripping attacks, intercepting and modifying "
                    "traffic by forcing connections to use insecure HTTP instead of HTTPS. This compromises the "
                    "entire encryption channel."
                ),
                references=[
                    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security",
                    "https://owasp.org/www-project-cheat-sheets/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html",
                    "https://cwe.mitre.org/data/definitions/523.html",
                ],
            )
        else:
            # Check for weak HSTS - highlight the actual HSTS header
            hsts_lower = hsts.lower()
            if "max-age=0" in hsts_lower or ("max-age=" in hsts_lower and int(hsts_lower.split("max-age=")[1].split(";")[0]) < 31536000):
                hsts_evidence = {
                    "type": "exact",
                    "pattern": f"Strict-Transport-Security: {hsts}",
                }
                
                self.add_enriched_vulnerability(
                    "Weak HSTS Configuration",
                    "Low",
                    f"HSTS has weak max-age: {hsts[:50]}...",
                    hsts_evidence,  # Pass evidence as 4th positional parameter
                    "Set max-age to at least 31536000 (1 year)",
                    category="Security Headers",
                    owasp="A05:2021 - Security Misconfiguration",
                    cwe=["CWE-523"],
                    background=(
                        "HSTS should have a sufficiently long max-age (at least 31536000 seconds = 1 year) "
                        "to ensure browsers remember to use HTTPS for an extended period. Short max-age values "
                        "reduce the effectiveness of HSTS protection."
                    ),
                    impact=(
                        "Weak HSTS configuration provides minimal protection, as browsers may quickly forget "
                        "to enforce HTTPS, making the application vulnerable to SSL stripping attacks in the near future."
                    ),
                    references=[
                        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security",
                        "https://owasp.org/www-project-cheat-sheets/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html",
                        "https://cwe.mitre.org/data/definitions/523.html",
                    ],
                )

    def _check_content_type_options(self, response: requests.Response):
        """Check X-Content-Type-Options"""
        xcto = response.headers.get("X-Content-Type-Options", "")
        if xcto != "nosniff":
            if xcto:
                # Highlight incorrect X-Content-Type-Options when present
                xcto_evidence = {
                    "type": "exact",
                    "pattern": f"X-Content-Type-Options: {xcto}",
                }
            else:
                xcto_evidence = []  # No header to highlight when missing
                
            self.add_enriched_vulnerability(
                "Missing X-Content-Type-Options",
                "Low",
                "X-Content-Type-Options header missing or incorrect",
                xcto_evidence,  # Pass evidence as 4th positional parameter
                "Set X-Content-Type-Options: nosniff",
                category="Security Headers",
                owasp="A05:2021 - Security Misconfiguration",
                cwe=["CWE-173"],
                background=(
                    "X-Content-Type-Options: nosniff prevents browsers from MIME-sniffing the content type. "
                    "Without this header, browsers may interpret content differently than intended, potentially "
                    "executing malicious scripts disguised as safe content types."
                ),
                impact=(
                    "Missing X-Content-Type-Options allows MIME-sniffing attacks where malicious content can be "
                    "executed by browsers that misinterpret the content type. This can lead to XSS attacks and "
                    "other security vulnerabilities."
                ),
                references=[
                    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options",
                    "https://owasp.org/www-project-cheat-sheets/cheatsheets/HTTP_Headers_Cheat_Sheet.html",
                    "https://cwe.mitre.org/data/definitions/173.html",
                ],
            )

    def _check_referrer_policy(self, response: requests.Response):
        """Check Referrer-Policy header"""
        rp = response.headers.get("Referrer-Policy", "")
        if not rp:
            self.add_enriched_vulnerability(
                "Missing Referrer-Policy Header",
                "Low",
                "No Referrer-Policy header found",
                [],
                "Implement a secure Referrer-Policy, such as 'strict-origin-when-cross-origin'.",
                category="Security Headers",
                owasp="A05:2021 - Security Misconfiguration",
                cwe=["CWE-116"],
                background=(
                    "The Referrer-Policy header controls how much referrer information (sent via the Referer header) "
                    "should be included with requests. Without this header, browsers may leak sensitive information "
                    "in the URL (like session tokens or IDs) to third-party sites."
                ),
                impact=(
                    "Missing Referrer-Policy can lead to information disclosure, where sensitive data contained in "
                    "URLs is leaked to third-party websites when a user clicks a link or when the page loads "
                    "third-party resources."
                ),
                references=[
                    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy",
                    "https://owasp.org/www-project-cheat-sheets/cheatsheets/HTTP_Headers_Cheat_Sheet.html#referrer-policy"
                ],
            )
        elif rp.lower() in ["unsafe-url", "no-referrer-when-downgrade"]:
             self.add_enriched_vulnerability(
                "Weak Referrer-Policy Configuration",
                "Low",
                f"Weak Referrer-Policy value: {rp}",
                {"type": "exact", "pattern": f"Referrer-Policy: {rp}"},
                "Use a more secure Referrer-Policy like 'no-referrer' or 'strict-origin-when-cross-origin'.",
                category="Security Headers",
                owasp="A05:2021 - Security Misconfiguration",
                cwe=["CWE-116"],
                background="Weak Referrer-Policy values may leak full URLs including query parameters to third-party sites.",
                impact="Sensitive information in the URL can be disclosed to third-party sites.",
                references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy"]
            )

    def _check_permissions_policy(self, response: requests.Response):
        """Check Permissions-Policy header"""
        pp = response.headers.get("Permissions-Policy", "")
        if not pp:
            self.add_enriched_vulnerability(
                "Missing Permissions-Policy Header",
                "Low",
                "No Permissions-Policy header found",
                [],
                "Implement a Permissions-Policy to control which browser features are available.",
                category="Security Headers",
                owasp="A05:2021 - Security Misconfiguration",
                cwe=["CWE-16"],
                background=(
                    "Permissions-Policy (formerly Feature-Policy) allows web developers to selectively enable, "
                    "disable, and modify the behavior of certain APIs and web features in the browser."
                ),
                impact=(
                    "Absence of Permissions-Policy allows all supported features to be used, increasing the attack "
                    "surface if the site is compromised or if it embeds untrusted third-party content."
                ),
                references=[
                    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy",
                    "https://w3c.github.io/webappsec-permissions-policy/"
                ],
            )

    def _check_other_security_headers(self, response: requests.Response):
        """Check for other common security headers"""
        headers = response.headers
        
        # X-XSS-Protection
        xxp = headers.get("X-XSS-Protection", "")
        if not xxp:
             self.add_enriched_vulnerability(
                "Missing X-XSS-Protection Header",
                "Info",
                "No X-XSS-Protection header found",
                [],
                "Implement X-XSS-Protection: 0 to disable the legacy browser XSS filter, or use CSP instead.",
                category="Security Headers",
                owasp="A05:2021 - Security Misconfiguration",
                cwe=["CWE-693"],
                background="The X-XSS-Protection header is a legacy feature that enabled the browser's reflected XSS filter. Most modern browsers now recommend disabling it in favor of a strong CSP.",
                impact="Minimal impact in modern browsers, but its absence may be flagged in compliance audits.",
                references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-XSS-Protection"]
            )

        # X-Permitted-Cross-Domain-Policies
        xpcdp = headers.get("X-Permitted-Cross-Domain-Policies", "")
        if not xpcdp:
            self.add_enriched_vulnerability(
                "Missing X-Permitted-Cross-Domain-Policies Header",
                "Info",
                "No X-Permitted-Cross-Domain-Policies header found",
                [],
                "Implement X-Permitted-Cross-Domain-Policies: none if you don't use Flash or PDF across domains.",
                category="Security Headers",
                owasp="A05:2021 - Security Misconfiguration",
                cwe=["CWE-16"],
                background="This header tells clients like Flash and Adobe Reader what cross-domain policies are allowed for the site.",
                impact="Minimal impact unless the application serves Flash or PDF content to cross-domain clients.",
                references=["https://owasp.org/www-project-secure-headers/index.html#x-permitted-cross-domain-policies"]
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
                    # Create evidence pattern for library version highlighting
                    dependency_evidence = {
                        "type": "regex",
                        "pattern": rf"(?i){re.escape(version)}"
                    }
                    
                    self.add_enriched_vulnerability(
                        "Potentially Vulnerable Dependency",
                        "Low",
                        f"Old library version detected: {version}",
                        dependency_evidence,
                        "Update to latest stable version",
                        category="Vulnerable Components",
                        owasp="A06:2021 - Vulnerable and Outdated Components",
                        cwe=["CWE-937"],
                        background=(
                            "Older versions of JavaScript libraries may contain known vulnerabilities that have been "
                            "fixed in newer releases. Using outdated dependencies increases the attack surface of the application."
                        ),
                        impact=(
                            "If these libraries contain exploitable vulnerabilities, attackers may be able to execute "
                            "cross-site scripting attacks, bypass security controls, or access sensitive data through "
                            "the vulnerable component."
                        ),
                        references=[
                            "https://owasp.org/www-project-top-ten/2021/A06_2021-Vulnerable_and_Outdated_Components/",
                            "https://cwe.mitre.org/data/definitions/937.html",
                            "https://npmjs.com/advisories",
                        ],
                    )
