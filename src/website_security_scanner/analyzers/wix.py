#!/usr/bin/env python3
"""
Wix Security Analyzer
Low-Code Platform Security Scanner

Specialized analyzer for Wix applications with platform-specific
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


class WixAnalyzer(CommonWebChecksMixin, AdvancedChecksMixin, VerificationMetadataMixin, BaseAnalyzer):
    """
    Specialized analyzer for Wix applications.
    
    Provides comprehensive security analysis for Wix websites,
    detecting wix.com resources, wixBiSession/wixRenderer globals,
    exposed _api endpoints, and site data leakage.
    """

    # Wix-specific patterns
    WIX_RESOURCE_PATTERNS = [
        r'wixstatic\.com',
        r'static\.parastorage\.com',
        r'wix\.com',
        r'wixsite\.com',
    ]

    WIX_GLOBALS = [
        r'wixBiSession',
        r'wixRenderer',
        r'wixData',
        r'wixWindow',
        r'wixLocation',
        r'Wix',
    ]

    WIX_API_PATTERN = re.compile(
        r'/_api/[^\s"\'<>]+',
        re.IGNORECASE
    )

    WIX_CODE_PATTERN = re.compile(
        r'\$w\.\w+|import\s+[^\'"]*[\'"]wix-[^\'"]+[\'"]',
        re.IGNORECASE
    )

    COLLECTION_PATTERN = re.compile(
        r'wixData\.query\(["\']([^"\']+)["\']',
        re.IGNORECASE
    )

    SITE_DATA_PATTERN = re.compile(
        r'siteData|siteConfiguration|wixConfig',
        re.IGNORECASE
    )

    VELO_PATTERN = re.compile(
        r'velo|wix-code|wixBackend|backend/[^\s"\'<>]+',
        re.IGNORECASE
    )

    def __init__(self, session: requests.Session):
        """
        Initialize Wix analyzer.
        
        Args:
            session: Configured requests session for HTTP operations
        """
        super().__init__(session)
        self.wix_markers: List[str] = []
        self.api_endpoints: List[str] = []
        self.collections: List[str] = []
        self.wix_globals_found: List[str] = []
        self.velo_references: List[str] = []

    def analyze(
        self, url: str, response: requests.Response, soup: BeautifulSoup
    ) -> Dict[str, Any]:
        """
        Comprehensive Wix security analysis.
        
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

        # Detect Wix resources
        self._detect_wix_resources(html_content)

        # Detect Wix globals
        self._detect_wix_globals(js_content)

        # Detect API endpoints
        self._detect_api_endpoints(combined_content)

        # Detect data collections
        self._detect_collections(js_content)

        # Detect Velo references
        self._detect_velo_references(combined_content)

        # Check for site data exposure
        self._check_site_data_exposure(js_content)

        # Check for sensitive configuration
        self._check_configuration_exposure(js_content)

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
            "wix_markers": self.wix_markers,
            "wix_globals": self.wix_globals_found,
            "api_endpoints": self.api_endpoints,
            "collections": self.collections,
            "velo_references": self.velo_references,
            "vulnerabilities": self.vulnerabilities,
            "wix_specific_findings": self.findings,
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

    def _detect_wix_resources(self, html_content: str):
        """Detect Wix-specific resource references."""
        markers = []
        for pattern in self.WIX_RESOURCE_PATTERNS:
            if re.search(pattern, html_content, re.IGNORECASE):
                markers.append(pattern)
        self.wix_markers = markers
        self.findings["wix_resources_found"] = markers

    def _detect_wix_globals(self, js_content: str):
        """Detect Wix global objects and session data."""
        globals_found = []
        for pattern in self.WIX_GLOBALS:
            if re.search(pattern, js_content, re.IGNORECASE):
                globals_found.append(pattern)

        self.wix_globals_found = globals_found
        self.findings["wix_globals_found"] = globals_found

        # Check for wixBiSession which may contain session data
        if 'wixBiSession' in globals_found:
            bi_pattern = re.compile(
                r'wixBiSession\s*=\s*\{([^}]+)\}',
                re.IGNORECASE | re.DOTALL
            )
            matches = bi_pattern.findall(js_content)

            for match in matches:
                # Check for potentially sensitive fields
                sensitive_fields = ['userId', 'sessionId', 'visitorId', 'email', 'name']
                found_sensitive = [field for field in sensitive_fields if field in match.lower()]

                if found_sensitive:
                    evidence = EvidenceBuilder.exact_match(
                        match[:200],
                        f"wixBiSession contains fields: {', '.join(found_sensitive)}",
                    )
                    self.add_enriched_vulnerability(
                        "Wix Session Data Exposure",
                        "Medium",
                        "wixBiSession object appears to contain user/session identifiers.",
                        evidence,
                        "Review wixBiSession data to ensure no sensitive user information is exposed in client-side code.",
                        category="Information Disclosure",
                        owasp="A04:2021 - Insecure Design",
                        cwe=["CWE-200"],
                        background="wixBiSession is a Wix global object used for analytics and session tracking. It may contain user identifiers.",
                        impact="Exposed session identifiers can potentially be used for session tracking or correlation attacks.",
                    )

    def _detect_api_endpoints(self, content: str):
        """Detect Wix _api endpoints."""
        endpoints = []
        for match in self.WIX_API_PATTERN.finditer(content or ""):
            endpoint = match.group(0)
            if endpoint not in endpoints:
                endpoints.append(endpoint)

        self.api_endpoints = endpoints

        for endpoint in endpoints:
            evidence = EvidenceBuilder.exact_match(
                endpoint,
                "Wix _api endpoint referenced in client content",
            )
            self.add_enriched_vulnerability(
                "Wix API Endpoint Exposure",
                "Info",
                f"Wix API endpoint referenced in client content: {endpoint}",
                evidence,
                "Review access controls on exposed endpoints. Ensure sensitive operations require proper authentication.",
                category="Information Disclosure",
                owasp="A01:2021 - Broken Access Control",
                cwe=["CWE-200"],
                background="Wix _api endpoints provide access to site functionality and data. Proper access controls are essential.",
                impact="Exposed API endpoints may allow unauthorized access to site data or functionality if not properly secured.",
            )

    def _detect_collections(self, js_content: str):
        """Detect Wix data collection queries."""
        collections = []
        for match in self.COLLECTION_PATTERN.finditer(js_content or ""):
            collection_name = match.group(1)
            if collection_name and collection_name not in collections:
                collections.append(collection_name)

        self.collections = collections

        for collection in collections:
            # Check for sensitive collection names
            sensitive_collections = ['user', 'customer', 'order', 'payment', 'password', 'admin']
            is_sensitive = any(sc in collection.lower() for sc in sensitive_collections)

            evidence = EvidenceBuilder.exact_match(
                collection,
                f"Wix data collection referenced in client code: {collection}",
            )
            self.add_enriched_vulnerability(
                "Wix Data Collection Exposure",
                "Medium" if is_sensitive else "Info",
                f"Wix data collection referenced in client code: {collection}",
                evidence,
                "Review collection permissions and ensure access controls are enforced server-side for sensitive collections.",
                category="Information Disclosure",
                owasp="A01:2021 - Broken Access Control",
                cwe=["CWE-200"],
                background="Wix collections store site data. Exposing collection names can reveal data structure.",
                impact="Collection exposure may reveal data structure and allow targeted queries for sensitive data.",
            )

    def _detect_velo_references(self, content: str):
        """Detect Velo (Wix Code) references."""
        references = []
        for match in self.VELO_PATTERN.finditer(content or ""):
            ref = match.group(0)
            if ref and ref not in references:
                references.append(ref)

        self.velo_references = references[:10]  # Limit to first 10
        self.findings["velo_references"] = references[:10]

    def _check_site_data_exposure(self, js_content: str):
        """Check for Wix site data exposure."""
        site_data_pattern = re.compile(
            r'(site|app|router)\s*[=:]\s*\{[^}]*(?:name|title|description|id)',
            re.IGNORECASE
        )

        if site_data_pattern.search(js_content):
            # Check for additional sensitive data
            sensitive_pattern = re.compile(
                r'["\'](email|phone|address|apiKey|secret|password)["\']\s*:\s*["\'][^"\']+["\']',
                re.IGNORECASE
            )

            sensitive_matches = sensitive_pattern.findall(js_content)
            if sensitive_matches:
                evidence = EvidenceBuilder.exact_match(
                    str(sensitive_matches[:3]),
                    "Potentially sensitive data detected in site configuration",
                )
                self.add_enriched_vulnerability(
                    "Wix Site Data Exposure",
                    "High",
                    "Potentially sensitive data found in Wix site configuration/client code.",
                    evidence,
                    "Remove sensitive data from client-side code. Use Wix Secrets Manager for sensitive values and backend functions for sensitive operations.",
                    category="Information Disclosure",
                    owasp="A04:2021 - Insecure Design",
                    cwe=["CWE-200", "CWE-798"],
                    background="Exposing sensitive data in client-side code allows attackers to extract credentials and other sensitive information.",
                    impact="Exposed sensitive data can lead to account compromise, data breaches, and unauthorized access.",
                )

    def _check_configuration_exposure(self, js_content: str):
        """Check for configuration exposure."""
        config_pattern = re.compile(
            r'["\']?config["\']?\s*[=:]\s*\{[^}]*\}',
            re.IGNORECASE | re.DOTALL
        )

        matches = config_pattern.findall(js_content)

        for match in matches:
            # Check for sensitive configuration keys
            sensitive_keys = ['key', 'token', 'secret', 'password', 'auth', 'endpoint']
            found_keys = [key for key in sensitive_keys if key in match.lower()]

            if found_keys:
                evidence = EvidenceBuilder.exact_match(
                    match[:200],
                    f"Configuration object with potential sensitive keys: {', '.join(found_keys)}",
                )
                self.add_enriched_vulnerability(
                    "Configuration Data Exposure",
                    "Medium",
                    "Configuration object detected in client code that may contain sensitive settings.",
                    evidence,
                    "Review configuration objects to ensure no sensitive values are exposed. Use Wix Secrets Manager for sensitive configuration.",
                    category="Information Disclosure",
                    owasp="A04:2021 - Insecure Design",
                    cwe=["CWE-200"],
                )
