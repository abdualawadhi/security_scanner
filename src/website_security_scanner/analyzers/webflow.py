#!/usr/bin/env python3
"""
Webflow Security Analyzer
Low-Code Platform Security Scanner

Specialized analyzer for Webflow applications with platform-specific
vulnerability detection and comprehensive traditional web vulnerability
scanning.

Author: Bachelor Thesis Project - Low-Code Platforms Security Analysis
"""

import re
from typing import Any, Dict, List
from urllib.parse import urljoin

import requests
from bs4 import BeautifulSoup

from .base import BaseAnalyzer
from .advanced_checks import AdvancedChecksMixin
from .common_web_checks import CommonWebChecksMixin
from .verification_metadata_mixin import VerificationMetadataMixin
from ..utils.evidence_builder import EvidenceBuilder


class WebflowAnalyzer(CommonWebChecksMixin, AdvancedChecksMixin, VerificationMetadataMixin, BaseAnalyzer):
    """
    Specialized analyzer for Webflow applications.
    
    Provides comprehensive security analysis for Webflow websites,
    detecting data-wf attributes, webflow.js exposure, form endpoint
    vulnerabilities, CMS JSON API exposures, and CSRF issues.
    """

    # Webflow-specific patterns
    WEBFLOW_MARKERS = [
        r'webflow\.js',
        r'data-wf-site',
        r'data-wf-page',
        r'uploads-ssl\.webflow\.com',
        r'cdn\.prod\.website-files\.com',
    ]

    WEBFLOW_API_PATTERN = re.compile(
        r'https?://api\.webflow\.com/[^"\'<>\s]+',
        re.IGNORECASE
    )

    DATA_WF_SITE_PATTERN = re.compile(
        r'data-wf-site=["\']([a-f0-9]{24})["\']',
        re.IGNORECASE
    )

    DATA_WF_PAGE_PATTERN = re.compile(
        r'data-wf-page=["\']([a-f0-9]{24})["\']',
        re.IGNORECASE
    )

    FORM_ENDPOINT_PATTERN = re.compile(
        r'action=["\'](https?://[^"\']*(?:formie|webflow|forms)[^"\']*)["\']',
        re.IGNORECASE
    )

    CMS_API_PATTERN = re.compile(
        r'https?://[^"\'<>\s]*webflow[^"\'<>\s]*/collections/[^"\'<>\s]*',
        re.IGNORECASE
    )

    def __init__(self, session: requests.Session):
        """
        Initialize Webflow analyzer.
        
        Args:
            session: Configured requests session for HTTP operations
        """
        super().__init__(session)
        self.webflow_markers: List[str] = []
        self.site_ids: List[str] = []
        self.page_ids: List[str] = []
        self.api_endpoints: List[str] = []
        self.form_endpoints: List[str] = []
        self.cms_endpoints: List[str] = []

    def analyze(
        self, url: str, response: requests.Response, soup: BeautifulSoup
    ) -> Dict[str, Any]:
        """
        Comprehensive Webflow security analysis.
        
        Args:
            url: Target URL being analyzed
            response: HTTP response from target
            soup: Parsed BeautifulSoup object
            
        Returns:
            Dictionary containing analysis results and vulnerabilities
        """
        # Record HTTP context for enriched vulnerability reporting
        self._record_http_context(url, response)

        html_content = str(soup)
        js_content = self._extract_javascript(soup)
        combined_content = html_content + "\n" + js_content

        # Detect Webflow markers
        self._detect_webflow_markers(html_content)

        # Detect site and page IDs
        self._detect_webflow_ids(html_content)

        # Detect API endpoints
        self._detect_api_endpoints(combined_content)

        # Detect form endpoints
        self._detect_form_endpoints(soup, html_content)

        # Detect CMS API endpoints
        self._detect_cms_endpoints(combined_content)

        # Check form CSRF protection
        self._check_form_csrf(soup)

        # Check for public collection data
        self._check_public_collections(js_content)

        # Perform common security checks
        self._check_session_tokens_in_url(url)
        self._check_secrets_in_javascript(js_content, url, soup)
        self._check_cookie_security(response)
        self._check_csp_policy(response)
        self._check_clickjacking(response)
        self._check_information_disclosure(js_content, html_content, response)
        self._check_reflected_input(url, response, html_content)
        self._check_cacheable_https(response, url)

        # Advanced checks
        self._check_http2_support(url)
        self._check_request_url_override(url)
        self._check_cookie_domain_scoping(response, url)
        self._check_secret_uncached_url_input(url, response)
        self._check_dom_data_manipulation(js_content)
        self._check_cloud_resources(combined_content)
        self._check_secret_input_header_reflection(url)

        return {
            "webflow_markers": self.webflow_markers,
            "site_ids": self.site_ids,
            "page_ids": self.page_ids,
            "api_endpoints": self.api_endpoints,
            "form_endpoints": self.form_endpoints,
            "cms_endpoints": self.cms_endpoints,
            "vulnerabilities": self.vulnerabilities,
            "webflow_specific_findings": self.findings,
        }

    def _extract_javascript(self, soup: BeautifulSoup) -> str:
        """Extract all JavaScript content from the page."""
        js_content = ""

        # Extract inline scripts
        for script in soup.find_all("script"):
            if script.string:
                js_content += script.string + "\n"

        # Extract external scripts
        for script in soup.find_all("script", src=True):
            try:
                script_url = urljoin(soup.base.get("href", "") if soup.base else "", script["src"])
                script_response = self.session.get(script_url, timeout=5)
                if script_response.status_code == 200:
                    js_content += script_response.text + "\n"
            except Exception:
                pass

        return js_content

    def _detect_webflow_markers(self, html_content: str):
        """Detect Webflow-specific markers in content."""
        markers = []
        for pattern in self.WEBFLOW_MARKERS:
            if re.search(pattern, html_content, re.IGNORECASE):
                markers.append(pattern)
        self.webflow_markers = markers
        self.findings["webflow_markers_found"] = markers

    def _detect_webflow_ids(self, html_content: str):
        """Detect Webflow site and page IDs."""
        # Site IDs
        site_matches = self.DATA_WF_SITE_PATTERN.findall(html_content)
        self.site_ids = list(set(site_matches))

        # Page IDs
        page_matches = self.DATA_WF_PAGE_PATTERN.findall(html_content)
        self.page_ids = list(set(page_matches))

        for site_id in self.site_ids:
            evidence = EvidenceBuilder.exact_match(
                site_id,
                "Webflow site identifier (data-wf-site) exposed in markup",
            )
            self.add_enriched_vulnerability(
                "Webflow Site Identifier Exposure",
                "Info",
                "Webflow site identifier (data-wf-site) is exposed in client markup.",
                evidence,
                "Site identifiers are generally public but ensure they do not enable unauthorized access to private CMS content or staging environments.",
                category="Information Disclosure",
                owasp="A01:2021 - Broken Access Control",
                cwe=["CWE-200"],
                background="Webflow site IDs are used internally but are generally considered public information. They may be used to identify sites in Webflow's systems.",
                impact="Site IDs alone typically don't enable unauthorized access, but they may assist in reconnaissance or identifying related sites.",
            )

        for page_id in self.page_ids:
            evidence = EvidenceBuilder.exact_match(
                page_id,
                "Webflow page identifier (data-wf-page) exposed in markup",
            )
            self.add_enriched_vulnerability(
                "Webflow Page Identifier Exposure",
                "Info",
                "Webflow page identifier (data-wf-page) is exposed in client markup.",
                evidence,
                "Page identifiers are generally public information in Webflow sites.",
                category="Information Disclosure",
                owasp="A01:2021 - Broken Access Control",
                cwe=["CWE-200"],
            )

    def _detect_api_endpoints(self, content: str):
        """Detect Webflow API endpoints in content."""
        endpoints = []
        for match in self.WEBFLOW_API_PATTERN.finditer(content or ""):
            endpoint = match.group(0)
            if endpoint not in endpoints:
                endpoints.append(endpoint)

        self.api_endpoints = endpoints

        for endpoint in endpoints:
            evidence = EvidenceBuilder.exact_match(
                endpoint,
                "Webflow API endpoint referenced in client content",
            )
            self.add_enriched_vulnerability(
                "Webflow API Endpoint Exposure",
                "Info",
                f"Webflow API endpoint referenced in client content: {endpoint}",
                evidence,
                "Ensure API endpoints are properly protected and do not expose sensitive data or allow unauthorized operations.",
                category="Information Disclosure",
                owasp="A01:2021 - Broken Access Control",
                cwe=["CWE-200"],
                background="Webflow API endpoints may provide access to CMS content and site configuration.",
                impact="Exposed API endpoints may allow unauthorized access to CMS content if not properly secured.",
            )

    def _detect_form_endpoints(self, soup: BeautifulSoup, html_content: str):
        """Detect form endpoints and validate security."""
        forms = soup.find_all("form")
        
        for form in forms:
            action = form.get("action", "")
            if action and ("webflow" in action.lower() or "formie" in action.lower()):
                self.form_endpoints.append(action)

                # Check for HTTPS
                if action.startswith("http://"):
                    evidence = EvidenceBuilder.exact_match(
                        action,
                        "Form submission over insecure HTTP",
                    )
                    self.add_enriched_vulnerability(
                        "Insecure Form Submission",
                        "High",
                        f"Form submits to insecure endpoint: {action}",
                        evidence,
                        "Configure all forms to submit over HTTPS only.",
                        category="Cryptographic Failures",
                        owasp="A02:2021 - Cryptographic Failures",
                        cwe=["CWE-319"],
                    )

            # Check for missing CSRF protection
            self._check_individual_form_csrf(form)

    def _check_form_csrf(self, soup: BeautifulSoup):
        """Check all forms for CSRF protection."""
        forms = soup.find_all("form")
        for form in forms:
            self._check_individual_form_csrf(form)

    def _check_individual_form_csrf(self, form: BeautifulSoup):
        """Check individual form for CSRF protection."""
        method = form.get("method", "GET").upper()
        
        # Only check state-changing methods
        if method != "POST":
            return

        # Look for CSRF tokens
        csrf_input = form.find("input", {"name": re.compile(r"csrf|_token|authenticity", re.IGNORECASE)})
        
        # Check for data attributes that might indicate AJAX form handling
        has_ajax_handler = form.get("data-wf-form-id") or form.get("data-wf-page-form")

        if not csrf_input and has_ajax_handler:
            action = form.get("action", "")
            evidence = EvidenceBuilder.exact_match(
                str(form)[:150],
                "Webflow form without visible CSRF protection",
            )
            self.add_enriched_vulnerability(
                "Missing CSRF Protection",
                "Medium",
                "Webflow form may lack CSRF protection. Verify CSRF tokens are implemented in the form handler.",
                evidence,
                "Ensure all state-changing forms implement proper CSRF protection, either via tokens or SameSite cookies.",
                category="Cross-Site Request Forgery",
                owasp="A01:2021 - Broken Access Control",
                cwe=["CWE-352"],
                background="CSRF attacks force authenticated users to execute unwanted actions. Forms without CSRF protection are vulnerable to these attacks.",
                impact="Attackers may be able to submit forms on behalf of authenticated users, leading to data modification or unauthorized actions.",
                references=[
                    "https://owasp.org/www-community/attacks/csrf",
                    "https://cwe.mitre.org/data/definitions/352.html",
                ],
            )

    def _detect_cms_endpoints(self, content: str):
        """Detect CMS API endpoints."""
        endpoints = []
        for match in self.CMS_API_PATTERN.finditer(content or ""):
            endpoint = match.group(0)
            if endpoint not in endpoints:
                endpoints.append(endpoint)

        self.cms_endpoints = endpoints

        if endpoints:
            self.findings["cms_api_endpoints"] = endpoints

    def _check_public_collections(self, js_content: str):
        """Check for public collection data exposure."""
        # Look for collection data in JavaScript
        collection_pattern = re.compile(
            r'collection[s]?["\']?\s*:\s*\{|items["\']?\s*:\s*\[|cms["\']?\s*:\s*\{',
            re.IGNORECASE
        )

        if collection_pattern.search(js_content):
            # Check for field definitions that might expose schema
            field_pattern = re.compile(
                r'["\']slug["\']|["\']name["\']|["\']field["\']|["\']schema["\']',
                re.IGNORECASE
            )

            if field_pattern.search(js_content):
                evidence = EvidenceBuilder.regex_pattern(
                    r'collection[s]?["\']?\s*:\s*\{|items["\']?\s*:\s*\[',
                    "CMS collection data detected in JavaScript",
                )
                self.add_enriched_vulnerability(
                    "CMS Collection Data Exposure",
                    "Low",
                    "CMS collection data appears to be exposed in client-side JavaScript.",
                    evidence,
                    "Review CMS data exposure to ensure no sensitive fields or internal data structures are exposed unnecessarily.",
                    category="Information Disclosure",
                    owasp="A01:2021 - Broken Access Control",
                    cwe=["CWE-200"],
                )
