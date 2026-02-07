#!/usr/bin/env python3
"""
Generic Web Security Analyzer
Low-Code Platform Security Scanner

Generic web application security analyzer for platforms that don't
fit into specific low-code categories.

Author: Bachelor Thesis Project - Low-Code Platforms Security Analysis
"""

import re
import base64
from typing import Any, Dict, List
from urllib.parse import urlparse, parse_qs, urljoin

import requests
from bs4 import BeautifulSoup

from .base import BaseAnalyzer
from .advanced_checks import AdvancedChecksMixin
from .common_web_checks import CommonWebChecksMixin
from .verification_metadata_mixin import VerificationMetadataMixin
from ..utils.evidence_builder import EvidenceBuilder


class GenericWebAnalyzer(CommonWebChecksMixin, AdvancedChecksMixin, VerificationMetadataMixin, BaseAnalyzer):
    """
    Generic web application security analyzer.
    
    Provides comprehensive security analysis for web applications that don't fit
    specific low-code platform categories. Performs broad vulnerability scanning
    including forms, links, scripts, and common web security issues.
    """

    def __init__(self, session: requests.Session):
        """
        Initialize generic web analyzer.
        
        Args:
            session: Configured requests session for HTTP operations
        """
        super().__init__(session)
        self.forms: List[Dict[str, Any]] = []
        self.links: List[str] = []
        self.scripts: List[str] = []
        self.endpoints: List[str] = []

    def analyze(
        self, url: str, response: requests.Response, soup: BeautifulSoup
    ) -> Dict[str, Any]:
        """
        Comprehensive generic web security analysis.
        
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

        # Analyze forms
        self._analyze_forms(soup)

        # Analyze links and endpoints
        self._analyze_links(soup, url)
        self._analyze_endpoints(js_content, url)

        # Generic security checks
        self._check_session_tokens_in_url(url)
        self._check_secrets_in_javascript(js_content, url, soup)
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
        self._check_directory_traversal(url, response)
        self._check_sql_injection_points(js_content, html_content)
        self._check_command_injection(js_content)
        self._check_file_upload(soup)
        self._check_websockets(js_content)

        # Advanced Burp-aligned checks
        self._check_http2_support(url)
        self._check_request_url_override(url)
        self._check_cookie_domain_scoping(response, url)
        self._check_secret_uncached_url_input(url, response)
        self._check_dom_data_manipulation(js_content)
        self._check_cloud_resources(js_content + "\n" + html_content)
        self._check_secret_input_header_reflection(url)

        return {
            "forms": self.forms,
            "links": self.links,
            "scripts": self.scripts,
            "endpoints": self.endpoints,
            "vulnerabilities": self.vulnerabilities,
            "generic_findings": self.findings,
        }

    def _extract_javascript(self, soup: BeautifulSoup) -> str:
        """Extract JavaScript content for analysis"""
        js_content = ""

        for script in soup.find_all("script"):
            if script.string:
                js_content += script.string + "\n"

        return js_content

    def _analyze_forms(self, soup: BeautifulSoup):
        """Analyze form security"""
        forms = soup.find_all("form")
        
        for form in forms:
            form_info = {
                "action": form.get("action", ""),
                "method": form.get("method", "GET"),
                "fields": []
            }
            
            # Extract form fields
            inputs = form.find_all(["input", "textarea", "select"])
            for inp in inputs:
                field_info = {
                    "name": inp.get("name", ""),
                    "type": inp.get("type", ""),
                    "required": inp.has_attr("required")
                }
                form_info["fields"].append(field_info)
            
            self.forms.append(form_info)
            
            # Security checks for forms
            self._check_form_security(form, form_info)

    def _check_form_security(self, form: BeautifulSoup, form_info: Dict):
        """Check individual form security"""
        # Check for CSRF protection
        csrf_input = form.find("input", {"name": re.compile(r"csrf", re.IGNORECASE)})
        if not csrf_input:
            csrf_evidence = EvidenceBuilder.exact_match(
                f"Form action: {form_info['action']}",
                "Form without CSRF protection"
            )
            self.add_enriched_vulnerability(
                "Missing CSRF Protection",
                "Medium",
                "Form lacks CSRF protection",
                csrf_evidence,
                "Implement CSRF tokens for all forms",
                category="Cross-Site Scripting",
                owasp="A03:2021 - Injection",
                cwe=["CWE-352"]
            )
        
        # Check for sensitive fields without proper protection
        sensitive_fields = ["password", "creditcard", "ssn", "email"]
        for field in form_info["fields"]:
            if any(sensitive in field["name"].lower() for sensitive in sensitive_fields):
                if form_info["method"].upper() == "GET":
                    sensitive_evidence = EvidenceBuilder.exact_match(
                        field["name"],
                        f"Sensitive field in GET form: {field['name']}"
                    )
                    self.add_enriched_vulnerability(
                        "Sensitive Data in GET Form",
                        "Medium",
                        f"Sensitive field '{field['name']}' in GET form",
                        sensitive_evidence,
                        "Use POST method for forms with sensitive data",
                        category="Data Exposure",
                        owasp="A02:2021 - Cryptographic Failures",
                        cwe=["CWE-598"]
                    )

    def _analyze_links(self, soup: BeautifulSoup, base_url: str):
        """Analyze links for security issues"""
        links = soup.find_all("a", href=True)
        
        for link in links:
            href = link["href"]
            self.links.append(href)
            
            # Check for suspicious links
            if href.startswith(("javascript:", "data:")):
                self.add_enriched_vulnerability(
                    "Suspicious Link Protocol",
                    "Low",
                    f"Suspicious link protocol: {href[:20]}",
                    href,
                    "Review link protocols and remove unsafe ones",
                    category="Cross-Site Scripting",
                    owasp="A03:2021 - Injection",
                    cwe=["CWE-79"]
                )

    def _analyze_endpoints(self, js_content: str, base_url: str):
        """Analyze API endpoints in JavaScript"""
        endpoint_patterns = [
            r'["\']https?://[^"\']+["\']',
            r'["\']/[^"\']*["\']',
            r'fetch\s*\(\s*["\']([^"\']+)["\']',
            r'ajax\s*\(\s*["\']url["\']?\s*[:=]\s*["\']([^"\']+)["\']',
        ]

        for pattern in endpoint_patterns:
            matches = re.findall(pattern, js_content, re.IGNORECASE)
            for match in matches:
                raw = match.strip("\"'")
                if raw.startswith("/"):
                    endpoint_url = urljoin(base_url, raw)
                elif raw.startswith(("http://", "https://")):
                    endpoint_url = raw
                else:
                    continue

                if endpoint_url not in self.endpoints:
                    self.endpoints.append(endpoint_url)
                    
                    # Check for sensitive endpoints
                    if any(sensitive in endpoint_url.lower() for sensitive in ["admin", "api", "config", "debug", "test"]):
                        if not self._is_same_origin_url(base_url, endpoint_url):
                            continue
                        self.add_enriched_vulnerability(
                            "Potentially Sensitive Endpoint",
                            "Info",
                            f"Potentially sensitive endpoint: {endpoint_url}",
                            endpoint_url,
                            "Review endpoint access controls",
                            confidence="Tentative",
                            category="Information Disclosure",
                            owasp="A01:2021 - Broken Access Control",
                            cwe=["CWE-200"]
                        )

    def _check_session_tokens_in_url(self, url: str):
        return CommonWebChecksMixin._check_session_tokens_in_url(self, url)

    def _check_secrets_in_javascript(self, js_content: str, url: str, soup: BeautifulSoup = None):
        return CommonWebChecksMixin._check_secrets_in_javascript(self, js_content, url, soup)

    def _check_cookie_security(self, response: requests.Response):
        return CommonWebChecksMixin._check_cookie_security(self, response)

    def _check_csp_policy(self, response: requests.Response):
        return CommonWebChecksMixin._check_csp_policy(self, response)

    def _check_clickjacking(self, response: requests.Response):
        return CommonWebChecksMixin._check_clickjacking(self, response)

    def _check_information_disclosure(self, js_content: str, html_content: str, response: requests.Response):
        return CommonWebChecksMixin._check_information_disclosure(self, js_content, html_content, response)

    def _check_reflected_input(self, url: str, response: requests.Response, html_content: str):
        return CommonWebChecksMixin._check_reflected_input(self, url, response, html_content)

    def _check_cacheable_https(self, response: requests.Response, url: str):
        return CommonWebChecksMixin._check_cacheable_https(self, response, url)

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
                if match.startswith(("http://", "https://", "//")):
                    self.add_enriched_vulnerability(
                        "Open Redirection Indicator",
                        "Low",
                        f"Potential redirect target hardcoded in client-side code: {match}",
                        match,
                        "Validate and whitelist redirect URLs",
                        confidence="Tentative",
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
                        "Info",
                        "AJAX requests may lack security headers",
                        "",
                        "Implement proper AJAX security headers",
                        confidence="Tentative",
                        category="Cross-Site Scripting",
                        owasp="A05:2021 - Security Misconfiguration",
                        cwe=["CWE-1007"]
                    )
                break

    def _check_linkfinder(self, js_content: str):
        """Check for exposed links and endpoints"""
        base_url = getattr(self._last_request, "url", "") if self._last_request else ""
        url_patterns = [
            r'["\']https?://[^"\']+["\']',
            r'["\']/[^"\']*["\']',
        ]

        for pattern in url_patterns:
            matches = re.findall(pattern, js_content)
            for match in matches:
                raw = match.strip("\"'")
                endpoint_url = urljoin(base_url, raw) if raw.startswith("/") else raw
                if base_url and not self._is_same_origin_url(base_url, endpoint_url):
                    continue
                # Check for sensitive endpoints
                if any(sensitive in endpoint_url.lower() for sensitive in ["admin", "api", "config", "debug"]):
                    self.add_enriched_vulnerability(
                        "Exposed Sensitive Endpoint",
                        "Info",
                        f"Potentially sensitive endpoint: {endpoint_url}",
                        endpoint_url,
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
        if not self._is_html_response(response):
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
        if not self._is_html_response(response):
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
            r'jquery[-.]?(\d+\.[\d\.]+)',
            r'bootstrap[-.]?(\d+\.[\d\.]+)',
            r'angular[-.]?(\d+\.[\d\.]+)',
            r'react[-.]?(\d+\.[\d\.]+)',
        ]

        for pattern in library_patterns:
            matches = re.findall(pattern, js_content, re.IGNORECASE)
            for version in matches:
                # This is a simplified check - in practice, you'd use a vulnerability database
                if version.startswith(("1.", "2.", "3.", "4.")):  # Older versions
                    self.add_enriched_vulnerability(
                        "Potentially Vulnerable Dependency",
                        "Info",
                        f"Old library version detected: {version}",
                        version,
                        "Update to latest stable version",
                        confidence="Tentative",
                        category="Vulnerable Components",
                        owasp="A06:2021 - Vulnerable and Outdated Components",
                        cwe=["CWE-937"]
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
                if any(sensitive in content.lower() for sensitive in ["admin", "private", "secret", "debug"]):
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

    def _check_directory_traversal(self, url: str, response: requests.Response):
        """Check for directory traversal vulnerabilities"""
        # Simple check for path parameters that might be vulnerable
        if re.search(r'[?&](path|dir|file|folder)=', url, re.IGNORECASE):
            self.add_enriched_vulnerability(
                "Directory Traversal Indicator",
                "Info",
                "URL contains a path parameter that warrants further testing",
                url,
                "Validate and sanitize all path parameters",
                confidence="Tentative",
                category="Injection",
                owasp="A03:2021 - Injection",
                cwe=["CWE-22"]
            )

    def _check_sql_injection_points(self, js_content: str, html_content: str):
        """Check for potential SQL injection points"""
        sql_patterns = [
            r'select\s+.*\s+from',
            r'insert\s+into',
            r'update\s+.*\s+set',
            r'delete\s+from',
            r'drop\s+table',
        ]

        content = js_content + html_content
        for pattern in sql_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                self.add_enriched_vulnerability(
                    "Potential SQL Injection Point",
                    "Info",
                    "SQL keywords found in client-side code (heuristic indicator)",
                    "",
                    "Review database queries and use parameterized queries",
                    confidence="Tentative",
                    category="Injection",
                    owasp="A03:2021 - Injection",
                    cwe=["CWE-89"]
                )
                break

    def _check_command_injection(self, js_content: str):
        """Check for command injection vulnerabilities"""
        cmd_patterns = [
            r'exec\s*\(',
            r'system\s*\(',
            r'shell_exec\s*\(',
            r'eval\s*\(',
        ]

        for pattern in cmd_patterns:
            if re.search(pattern, js_content, re.IGNORECASE):
                self.add_enriched_vulnerability(
                    "Command Injection Indicator",
                    "Info",
                    "Potential command execution function found in client-side code (heuristic indicator)",
                    "",
                    "Avoid command execution functions with user input",
                    confidence="Tentative",
                    category="Injection",
                    owasp="A03:2021 - Injection",
                    cwe=["CWE-78"]
                )
                break

    def _check_file_upload(self, soup: BeautifulSoup):
        """Check file upload functionality"""
        file_inputs = soup.find_all("input", {"type": "file"})
        
        for file_input in file_inputs:
            # Check for file validation
            form = file_input.find_parent("form")
            accept_attr = file_input.get("accept", "")
            
            if not accept_attr:
                self.add_enriched_vulnerability(
                    "Unrestricted File Upload",
                    "Medium",
                    "File upload input without explicit type restrictions",
                    str(file_input)[:50],
                    "Implement file type validation and content inspection",
                    confidence="Tentative",
                    category="Injection",
                    owasp="A03:2021 - Injection",
                    cwe=["CWE-434"]
                )

    def _check_websockets(self, js_content: str):
        """Check WebSocket security"""
        ws_patterns = [
            r'new\s+WebSocket\s*\(',
            r'ws://',
            r'wss://',
        ]

        for pattern in ws_patterns:
            if re.search(pattern, js_content, re.IGNORECASE):
                # Check if using secure WebSocket
                if "ws://" in js_content and "wss://" not in js_content:
                    self.add_enriched_vulnerability(
                        "Insecure WebSocket Connection",
                        "Medium",
                        "Using unsecure WebSocket (ws://) instead of secure (wss://)",
                        "",
                        "Use secure WebSocket connections (wss://)",
                        category="Cryptographic Failures",
                        owasp="A02:2021 - Cryptographic Failures",
                        cwe=["CWE-319"]
                    )
                break
