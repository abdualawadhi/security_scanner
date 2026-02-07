#!/usr/bin/env python3
"""
Mendix Security Analyzer
Low-Code Platform Security Scanner

Specialized analyzer for Mendix applications with platform-specific
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


class MendixAnalyzer(CommonWebChecksMixin, AdvancedChecksMixin, VerificationMetadataMixin, BaseAnalyzer):
    """
    Specialized analyzer for Mendix applications.
    
    Provides comprehensive security analysis for Mendix low-code applications,
    detecting mxclientsystem paths, REST API exposures, entity metadata leaks,
    and role information exposure in client-side code.
    """

    # Mendix-specific patterns
    MENDIX_MARKERS = [
        r'/mxclientsystem/',
        r'mxui',
        r'mendix',
        r'window\.mx',
        r'mx\.data',
        r'mx\.session',
    ]

    REST_ENDPOINT_PATTERN = re.compile(
        r'/rest/[^\s"\'<>]+',
        re.IGNORECASE
    )

    API_ENDPOINT_PATTERN = re.compile(
        r'/api/[^\s"\'<>]+',
        re.IGNORECASE
    )

    ODATA_PATTERN = re.compile(
        r'/odata/[^\s"\'<>]+',
        re.IGNORECASE
    )

    ENTITY_PATTERN = re.compile(
        r'["\']([A-Za-z_][A-Za-z0-9_]*)["\']\s*:\s*\{[^}]*["\']entity["\']',
        re.IGNORECASE
    )

    ROLE_PATTERN = re.compile(
        r'["\']roles?["\']\s*:\s*\[([^\]]+)\]|UserRole|MxUserRole',
        re.IGNORECASE
    )

    MICROFLOW_PATTERN = re.compile(
        r'["\']([A-Za-z_][A-Za-z0-9_]*)["\']\s*:\s*\{[^}]*["\']microflow["\']',
        re.IGNORECASE
    )

    def __init__(self, session: requests.Session):
        """
        Initialize Mendix analyzer.
        
        Args:
            session: Configured requests session for HTTP operations
        """
        super().__init__(session)
        self.mendix_markers: List[str] = []
        self.rest_endpoints: List[str] = []
        self.api_endpoints: List[str] = []
        self.odata_endpoints: List[str] = []
        self.entities: List[Dict[str, Any]] = []
        self.roles: List[str] = []
        self.microflows: List[str] = []

    def analyze(
        self, url: str, response: requests.Response, soup: BeautifulSoup
    ) -> Dict[str, Any]:
        """
        Comprehensive Mendix security analysis.
        
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

        # Detect Mendix markers
        self._detect_mendix_markers(combined_content)

        # Detect REST endpoints
        self._detect_rest_endpoints(combined_content)

        # Detect API endpoints
        self._detect_api_endpoints(combined_content)

        # Detect OData endpoints
        self._detect_odata_endpoints(combined_content)

        # Detect entity metadata
        self._detect_entity_metadata(js_content)

        # Detect role information
        self._detect_role_information(js_content)

        # Detect microflow references
        self._detect_microflows(js_content)

        # Validate REST endpoint authentication
        self._check_rest_authentication(url, self.rest_endpoints)

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
            "mendix_markers": self.mendix_markers,
            "rest_endpoints": self.rest_endpoints,
            "api_endpoints": self.api_endpoints,
            "odata_endpoints": self.odata_endpoints,
            "entities": self.entities,
            "roles": self.roles,
            "microflows": self.microflows,
            "vulnerabilities": self.vulnerabilities,
            "mendix_specific_findings": self.findings,
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

    def _detect_mendix_markers(self, content: str):
        """Detect Mendix framework markers."""
        markers = []
        for pattern in self.MENDIX_MARKERS:
            if re.search(pattern, content, re.IGNORECASE):
                markers.append(pattern)
        self.mendix_markers = markers
        self.findings["mendix_markers_found"] = markers

    def _detect_rest_endpoints(self, content: str):
        """Detect Mendix REST endpoints."""
        endpoints = []
        for match in self.REST_ENDPOINT_PATTERN.finditer(content or ""):
            endpoint = match.group(0)
            if endpoint not in endpoints:
                endpoints.append(endpoint)

        self.rest_endpoints = endpoints

        for endpoint in endpoints:
            # Check for sensitive endpoint patterns
            sensitive_patterns = ['admin', 'user', 'auth', 'password', 'private', 'internal']
            is_sensitive = any(pattern in endpoint.lower() for pattern in sensitive_patterns)

            evidence = EvidenceBuilder.exact_match(
                endpoint,
                "Mendix REST endpoint referenced in client content",
            )
            self.add_enriched_vulnerability(
                "Mendix REST Endpoint Exposure",
                "Medium" if is_sensitive else "Low",
                f"Mendix REST endpoint referenced in client content: {endpoint}",
                evidence,
                "Ensure REST endpoints are properly protected with authentication and authorization checks.",
                category="Information Disclosure",
                owasp="A01:2021 - Broken Access Control",
                cwe=["CWE-200", "CWE-306"],
                background="Mendix REST endpoints provide access to application data and business logic. Exposed endpoints without proper security controls can lead to unauthorized data access.",
                impact="Exposed REST endpoints may allow attackers to access or manipulate application data if authentication is not properly enforced.",
            )

    def _detect_api_endpoints(self, content: str):
        """Detect Mendix API endpoints."""
        endpoints = []
        for match in self.API_ENDPOINT_PATTERN.finditer(content or ""):
            endpoint = match.group(0)
            if endpoint not in endpoints and endpoint not in self.rest_endpoints:
                endpoints.append(endpoint)

        self.api_endpoints = endpoints

    def _detect_odata_endpoints(self, content: str):
        """Detect OData endpoints."""
        endpoints = []
        for match in self.ODATA_PATTERN.finditer(content or ""):
            endpoint = match.group(0)
            if endpoint not in endpoints:
                endpoints.append(endpoint)

        self.odata_endpoints = endpoints

        for endpoint in endpoints:
            evidence = EvidenceBuilder.exact_match(
                endpoint,
                "Mendix OData endpoint referenced in client content",
            )
            self.add_enriched_vulnerability(
                "Mendix OData Endpoint Exposure",
                "Medium",
                f"Mendix OData endpoint referenced in client content: {endpoint}",
                evidence,
                "Ensure OData endpoints have proper access controls and authentication. OData endpoints often expose full data models.",
                category="Information Disclosure",
                owasp="A01:2021 - Broken Access Control",
                cwe=["CWE-200", "CWE-306"],
                background="OData endpoints provide standardized access to data models and can expose significant amounts of application data if not properly secured.",
                impact="OData endpoints may expose entire data models, allowing attackers to query and extract large volumes of data.",
            )

    def _detect_entity_metadata(self, js_content: str):
        """Detect entity metadata exposure in client code."""
        entities = []
        entity_matches = self.ENTITY_PATTERN.findall(js_content)

        for match in entity_matches:
            if match not in [e.get('name') for e in entities]:
                entity_info = {"name": match}
                entities.append(entity_info)

                # Check for sensitive entity names
                sensitive_entities = ['user', 'account', 'password', 'payment', 'credit', 'customer', 'order']
                is_sensitive = any(se in match.lower() for se in sensitive_entities)

                if is_sensitive:
                    evidence = EvidenceBuilder.exact_match(
                        match,
                        f"Sensitive entity name detected: {match}",
                    )
                    self.add_enriched_vulnerability(
                        "Sensitive Entity Metadata Exposure",
                        "Medium",
                        f"Potentially sensitive entity '{match}' referenced in client-side code.",
                        evidence,
                        "Review entity metadata exposure to ensure data model structure is not unnecessarily disclosed.",
                        category="Information Disclosure",
                        owasp="A04:2021 - Insecure Design",
                        cwe=["CWE-200"],
                        background="Entity metadata exposure reveals the application's data model structure, which can aid attackers in crafting targeted attacks.",
                        impact="Revealed entity names can help attackers understand the data model and identify valuable targets for data extraction.",
                    )

        self.entities = entities

    def _detect_role_information(self, js_content: str):
        """Detect role information exposure."""
        roles = []
        role_matches = self.ROLE_PATTERN.findall(js_content)

        for match in role_matches:
            if isinstance(match, str):
                # Extract role names from array content
                role_names = re.findall(r'["\']([^"\']+)["\']', match)
                roles.extend(role_names)

        self.roles = list(set(roles))

        if roles:
            evidence = EvidenceBuilder.exact_match(
                str(roles[:5]),
                "Role information detected in client-side code",
            )
            self.add_enriched_vulnerability(
                "Role Information Exposure",
                "Low",
                "User role information is exposed in client-side code.",
                evidence,
                "Review whether role information needs to be exposed client-side. Consider implementing role checks server-side only.",
                category="Information Disclosure",
                owasp="A04:2021 - Insecure Design",
                cwe=["CWE-200"],
                background="Exposing role information client-side can aid attackers in understanding access control structures and identifying privilege escalation targets.",
                impact="Attackers can identify different user roles and potentially target higher-privilege accounts or functionality.",
            )

    def _detect_microflows(self, js_content: str):
        """Detect microflow references."""
        microflows = []
        microflow_matches = self.MICROFLOW_PATTERN.findall(js_content)

        for match in microflow_matches:
            if match not in microflows:
                microflows.append(match)

                # Check for sensitive microflow names
                sensitive_patterns = ['delete', 'admin', 'password', 'auth', 'login', 'create', 'update']
                is_sensitive = any(sp in match.lower() for sp in sensitive_patterns)

                if is_sensitive:
                    evidence = EvidenceBuilder.exact_match(
                        match,
                        f"Sensitive microflow name detected: {match}",
                    )
                    self.add_enriched_vulnerability(
                        "Sensitive Microflow Exposure",
                        "Low",
                        f"Potentially sensitive microflow '{match}' referenced in client code.",
                        evidence,
                        "Review microflow naming and ensure business logic implementation details are not unnecessarily exposed.",
                        category="Information Disclosure",
                        owasp="A04:2021 - Insecure Design",
                        cwe=["CWE-200"],
                    )

        self.microflows = microflows

    def _check_rest_authentication(self, url: str, endpoints: List[str]):
        """Validate REST endpoint authentication by probing."""
        # Sample a few endpoints to check for authentication
        test_endpoints = endpoints[:3]  # Limit to first 3

        for endpoint in test_endpoints:
            try:
                full_url = urljoin(url, endpoint)
                response = self.session.get(full_url, timeout=5)

                # If we get a successful response without authentication headers,
                # the endpoint might be unprotected
                if response.status_code == 200:
                    content_type = response.headers.get("Content-Type", "")
                    if "json" in content_type.lower() or "xml" in content_type.lower():
                        evidence = EvidenceBuilder.exact_match(
                            f"Status: {response.status_code}, Content-Type: {content_type}",
                            f"REST endpoint returned data without apparent authentication: {endpoint}",
                        )
                        self.add_enriched_vulnerability(
                            "Potentially Unprotected REST Endpoint",
                            "High",
                            f"REST endpoint appears to return data without authentication: {endpoint}",
                            evidence,
                            "Ensure all REST endpoints implement proper authentication and authorization checks.",
                            category="Access Control",
                            owasp="A01:2021 - Broken Access Control",
                            cwe=["CWE-306", "CWE-862"],
                            background="REST endpoints without authentication allow anyone to access application data and functionality.",
                            impact="Unprotected endpoints can lead to complete data exposure and unauthorized business operations.",
                        )
            except Exception:
                pass
