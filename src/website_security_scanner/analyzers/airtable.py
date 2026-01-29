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
from .advanced_checks import AdvancedChecksMixin


class AirtableAnalyzer(AdvancedChecksMixin, BaseAnalyzer):
    """Specialized analyzer for Airtable applications"""

    def __init__(self, session: requests.Session):
        super().__init__(session)
        self.base_ids = []
        self.api_keys = []
        self.table_schemas = []
        self.permission_models = []
        # Keep the last main request/response for HTTP pair enrichment
        self._last_request = None
        self._last_response = None

    def _record_http_context(self, url: str, response: requests.Response):
        """Store the primary HTTP request/response for later use in findings."""
        self._last_response = response
        try:
            self._last_request = response.request
        except Exception:
            self._last_request = None

    def _build_http_instance(self, evidence_list: List[Any] = None) -> Dict[str, Any]:
        """Build a basic HTTP instance dictionary (start line + headers only).

        Bodies are intentionally omitted to focus on protocol and header context,
        reducing report size and avoiding accidental data leakage.
        """
        req_txt = ""
        resp_txt = ""
        if self._last_request is not None:
            try:
                method = getattr(self._last_request, "method", "GET")
                path = getattr(self._last_request, "path_url", "") or getattr(self._last_request, "url", "")
                headers = "\n".join(f"{k}: {v}" for k, v in getattr(self._last_request, "headers", {}).items())
                req_txt = f"{method} {path} HTTP/1.1\n{headers}"
            except Exception:
                req_txt = ""
        if self._last_response is not None:
            try:
                status = self._last_response.status_code
                reason = getattr(self._last_response, "reason", "")
                headers = "\n".join(f"{k}: {v}" for k, v in self._last_response.headers.items())
                resp_txt = f"HTTP/1.1 {status} {reason}\n{headers}"
            except Exception:
                resp_txt = ""
        return {
            "url": getattr(self._last_request, "url", None) or getattr(self._last_response, "url", ""),
            "request": req_txt,
            "response": resp_txt,
            "evidence": evidence_list or [],
        }

    def _add_enriched_vulnerability(
        self,
        vuln_type: str,
        severity: str,
        description: str,
        evidence: Any = "",
        recommendation: str = "",
        confidence: str = "Firm",
        category: str = "General",
        owasp: str = "N/A",
        cwe: List[str] = None,
        background: str = "",
        impact: str = "",
        references: List[str] = None,
    ):
        """Wrapper to add richer metadata plus HTTP instance to vulnerabilities.

        This preserves the existing BaseAnalyzer.add_vulnerability behavior while
        extending the stored dict with background, impact, references, and
        a default HTTP instance for the main page.
        """
        # Handle evidence parameter - can be string, dict, or list
        if isinstance(evidence, dict) or isinstance(evidence, list):
            evidence_list = evidence if isinstance(evidence, list) else [evidence]
        else:
            evidence_list = [evidence] if evidence else []
            
        super().add_vulnerability(
            vuln_type,
            severity,
            description,
            evidence if isinstance(evidence, str) else str(evidence),
            recommendation,
            confidence,
            category,
            owasp,
            cwe
        )
        vuln = self.vulnerabilities[-1]
        vuln["background"] = background or ""
        vuln["impact"] = impact or ""
        vuln["references"] = references or []
        if self._last_response is not None:
            vuln["instances"] = [self._build_http_instance(evidence_list=evidence_list)]

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
        self._check_vulnerable_dependencies(js_content)

        # NEW ENHANCED CHECKS - Airtable-specific missing vulnerabilities
        self._check_http2_support(url)
        self._check_request_url_override(url)
        self._check_cookie_domain_scoping(response, url)
        self._check_secret_uncached_url_input(url, response)
        self._check_dom_data_manipulation(js_content)

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
                    
                    self._add_enriched_vulnerability(
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
                    
                    self._add_enriched_vulnerability(
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
                        self._add_enriched_vulnerability(
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
            self._add_enriched_vulnerability(
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
                    
                    self._add_enriched_vulnerability(
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
        if re.search(r'[?&](session|token|sid)=', url, re.IGNORECASE):
            # Create evidence pattern for session token highlighting
            session_evidence = {
                "type": "regex",
                "pattern": r"(?i)[?&](session|token|sid)=[^&\s]*"
            }
            
            self._add_enriched_vulnerability(
                "Session Token in URL",
                "Medium",
                "Session token found in URL",
                session_evidence,
                "Use secure cookies for session management",
                category="Session Management",
                owasp="A07:2021 - Identification and Authentication Failures",
                cwe=["CWE-384"],
                background=(
                    "Putting session IDs or tokens in URLs is insecure because URLs are logged in many places (browser history, "
                    "server logs, analytics tools) and can be leaked via referrer headers."
                ),
                impact=(
                    "If an attacker obtains such a URL, they may be able to hijack active user sessions and access the Airtable "
                    "application with that user's privileges."
                ),
                references=[
                    "https://owasp.org/www-community/vulnerabilities/Information_exposure_through_query_strings_in_url",
                    "https://cwe.mitre.org/data/definitions/384.html",
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
                    
                    self._add_enriched_vulnerability(
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
        """Check cookie security headers"""
        cookies = response.headers.get("Set-Cookie", "")
        if "Secure" not in cookies:
            # Create evidence pattern to highlight Set-Cookie header lines
            cookie_evidence = {
                "type": "regex",
                "pattern": r"(?i)^Set-Cookie:.*(session|auth|token|sid|cookie)[^\n]*",
            }
            
            self._add_enriched_vulnerability(
                "Insecure Cookie",
                "Medium",
                "Cookie lacks Secure flag",
                cookie_evidence,  # Pass evidence as 4th positional parameter
                "Set Secure flag for cookies",
                category="Session Management",
                owasp="A05:2021 - Security Misconfiguration",
                cwe=["CWE-614"],
                background=(
                    "The Secure flag is a critical cookie attribute that ensures cookies are only transmitted "
                    "over HTTPS connections. Without this flag, cookies can be sent over unencrypted HTTP, "
                    "making them vulnerable to interception and session hijacking attacks."
                ),
                impact=(
                    "Cookies without the Secure flag can be intercepted by attackers monitoring network traffic, "
                    "leading to session hijacking, unauthorized access to user accounts, and potential data "
                    "breaches. This is particularly dangerous on public WiFi networks and other insecure connections."
                ),
                references=[
                    "https://owasp.org/www-project-cheat-sheets/cheatsheets/Session_Management_Cheat_Sheet.html",
                    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie#Secure",
                    "https://cwe.mitre.org/data/definitions/614.html",
                ],
            )

    def _check_csp_policy(self, response: requests.Response):
        """Check Content Security Policy"""
        csp = response.headers.get("Content-Security-Policy", "")
        if not csp:
            self._add_enriched_vulnerability(
                "Missing Content Security Policy",
                "Low",
                "No CSP header found",
                [],  # Pass evidence as 4th positional parameter
                "Implement Content Security Policy",
                category="Security Headers",
                owasp="A05:2021 - Security Misconfiguration",
                cwe=["CWE-693"],
                background=(
                    "Content Security Policy (CSP) is a security layer that helps detect and mitigate "
                    "certain types of attacks, including Cross-Site Scripting (XSS) and data injection attacks. "
                    "Without a CSP, browsers have more freedom in interpreting and executing content from various sources."
                ),
                impact=(
                    "Missing CSP allows XSS attacks to succeed more easily, enables data injection attacks, "
                    "and provides attackers with more vectors to exploit web application vulnerabilities. "
                    "This can lead to session hijacking, data theft, and unauthorized actions on behalf of users."
                ),
                references=[
                    "https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP",
                    "https://owasp.org/www-project-cheat-sheets/cheatsheets/Content_Security_Policy_Cheat_Sheet.html",
                    "https://cwe.mitre.org/data/definitions/693.html",
                ],
            )
        else:
            # Check for weak CSP - highlight the actual CSP header
            weak_patterns = ["unsafe-inline", "unsafe-eval", "*", "data:"]
            if any(weak in csp.lower() for weak in weak_patterns):
                csp_evidence = {
                    "type": "exact",
                    "pattern": f"Content-Security-Policy: {csp}",
                }
                
                self._add_enriched_vulnerability(
                    "Weak Content Security Policy",
                    "Medium",
                    f"CSP contains weak directives: {csp[:100]}...",
                    csp_evidence,  # Pass evidence as 4th positional parameter
                    "Remove unsafe directives from CSP",
                    category="Security Headers",
                    owasp="A05:2021 - Security Misconfiguration",
                    cwe=["CWE-693"],
                    background=(
                        "Content Security Policy should avoid unsafe directives like 'unsafe-inline' and 'unsafe-eval' "
                        "which defeat the purpose of CSP by allowing inline scripts and dynamic code execution."
                    ),
                    impact=(
                        "Weak CSP directives allow XSS attacks to bypass protections, making the policy ineffective "
                        "against code injection attacks. This provides a false sense of security while remaining vulnerable."
                    ),
                    references=[
                        "https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP",
                        "https://owasp.org/www-project-cheat-sheets/cheatsheets/Content_Security_Policy_Cheat_Sheet.html",
                        "https://cwe.mitre.org/data/definitions/693.html",
                    ],
                )

    def _check_clickjacking(self, response: requests.Response):
        """Check for clickjacking protection"""
        xfo = response.headers.get("X-Frame-Options", "")
        if not xfo:
            self._add_enriched_vulnerability(
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
            
            self._add_enriched_vulnerability(
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

        for pattern in error_patterns:
            if re.search(pattern, js_content + html_content, re.IGNORECASE):
                # Create evidence pattern for error highlighting
                error_evidence = {
                    "type": "regex",
                    "pattern": pattern
                }
                
                self._add_enriched_vulnerability(
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
                    
                    self._add_enriched_vulnerability(
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
            
            self._add_enriched_vulnerability(
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
                    
                    self._add_enriched_vulnerability(
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
                    
                    self._add_enriched_vulnerability(
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
            self._add_enriched_vulnerability(
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
                
                self._add_enriched_vulnerability(
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
                
            self._add_enriched_vulnerability(
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
                    
                    self._add_enriched_vulnerability(
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
