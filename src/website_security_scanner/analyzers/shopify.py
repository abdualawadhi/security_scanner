#!/usr/bin/env python3
"""
Shopify Security Analyzer
Low-Code Platform Security Scanner

Specialized analyzer for Shopify storefronts with platform-specific
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


class ShopifyAnalyzer(CommonWebChecksMixin, AdvancedChecksMixin, VerificationMetadataMixin, BaseAnalyzer):
    """
    Specialized analyzer for Shopify storefronts.
    
    Provides comprehensive security analysis for Shopify e-commerce applications,
    detecting Storefront API token exposures, checkout API vulnerabilities,
    public JSON endpoint exposures, and Shopify Analytics data leakage.
    """

    # Shopify-specific patterns
    SHOPIFY_ASSET_PATTERNS = [
        r'cdn\.shopify\.com',
        r'shopifycloud',
        r'shopifyassets',
        r'myshopify\.com',
    ]

    STOREFRONT_TOKEN_PATTERN = re.compile(
        r'(storefrontAccessToken|storefront_api_token|storefront-access-token)["\']?\s*[:=]\s*["\']([A-Za-z0-9_-]{16,})["\']',
        re.IGNORECASE,
    )

    CHECKOUT_TOKEN_PATTERN = re.compile(
        r'shopify-checkout-api-token["\']?\s*(?:content|value)?=?\s*["\']([^"\']+)["\']',
        re.IGNORECASE,
    )

    LIQUID_TEMPLATE_PATTERN = re.compile(
        r'\{\{\s*[^}]+\s*\}\}|\{%\s*[^%]+\s*%\}',
        re.IGNORECASE,
    )

    PUBLIC_JSON_ENDPOINTS = [
        "/products.json",
        "/collections.json",
        "/blogs.json",
        "/pages.json",
        "/cart.js",
        "/cart.json",
    ]

    def __init__(self, session: requests.Session):
        """
        Initialize Shopify analyzer.
        
        Args:
            session: Configured requests session for HTTP operations
        """
        super().__init__(session)
        self.storefront_tokens: List[str] = []
        self.checkout_tokens: List[str] = []
        self.public_endpoints: List[str] = []
        self.liquid_exposures: List[str] = []

    def analyze(
        self, url: str, response: requests.Response, soup: BeautifulSoup
    ) -> Dict[str, Any]:
        """
        Comprehensive Shopify security analysis.
        
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

        # Detect Shopify assets
        self._detect_shopify_assets(html_content)

        # Detect Storefront API tokens
        self._detect_storefront_tokens(js_content)

        # Detect checkout API tokens
        self._detect_checkout_api_tokens(html_content)

        # Detect public JSON endpoints
        self._detect_public_json_endpoints(combined_content)

        # Detect Liquid template exposure
        self._detect_liquid_exposure(html_content)

        # Check for Shopify Analytics data
        self._detect_analytics_data(js_content)

        # Check cart.js endpoint for data exposure
        self._check_cart_endpoint(url)

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
            "storefront_tokens": self.storefront_tokens,
            "checkout_tokens": self.checkout_tokens,
            "public_endpoints": self.public_endpoints,
            "liquid_exposures": self.liquid_exposures,
            "vulnerabilities": self.vulnerabilities,
            "shopify_specific_findings": self.findings,
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

    def _detect_shopify_assets(self, html_content: str):
        """Detect Shopify-specific asset references."""
        assets = []
        for pattern in self.SHOPIFY_ASSET_PATTERNS:
            matches = re.findall(pattern, html_content, re.IGNORECASE)
            if matches:
                assets.extend(matches)
        self.findings["shopify_assets"] = list(set(assets))

    def _detect_storefront_tokens(self, js_content: str):
        """Detect Storefront API tokens in JavaScript."""
        tokens = []
        for match in self.STOREFRONT_TOKEN_PATTERN.finditer(js_content or ""):
            token_value = match.group(2)
            if token_value and token_value not in tokens:
                tokens.append(token_value)

        self.storefront_tokens = tokens

        for token in tokens:
            evidence = EvidenceBuilder.exact_match(
                token,
                "Shopify Storefront API token exposed in client-side code",
            )
            self.add_enriched_vulnerability(
                "Shopify Storefront Access Token Exposure",
                "High",
                "Storefront API access token found exposed in client-side JavaScript.",
                evidence,
                "Rotate the exposed token immediately and ensure Storefront API tokens are only used server-side or have minimal required permissions.",
                category="API Security",
                owasp="A01:2021 - Broken Access Control",
                cwe=["CWE-798", "CWE-200"],
                background="Shopify Storefront API tokens provide access to store data. When exposed in client-side code, attackers can use them to access product, customer, and order information.",
                impact="Exposed tokens allow unauthorized access to store data, potentially exposing customer information, order details, and pricing data.",
                references=[
                    "https://shopify.dev/docs/api/storefront",
                    "https://cwe.mitre.org/data/definitions/798.html",
                ],
            )

    def _detect_checkout_api_tokens(self, html_content: str):
        """Detect checkout API tokens in HTML."""
        tokens = []
        for match in self.CHECKOUT_TOKEN_PATTERN.finditer(html_content or ""):
            token_value = match.group(1)
            if token_value and token_value not in tokens:
                tokens.append(token_value)

        self.checkout_tokens = tokens

        for token in tokens:
            evidence = EvidenceBuilder.exact_match(
                token,
                "Checkout API token exposed in markup",
            )
            self.add_enriched_vulnerability(
                "Shopify Checkout API Token Exposure",
                "Medium",
                "Checkout API token appears exposed in client-side HTML/markup.",
                evidence,
                "Review checkout token scope and permissions. Ensure checkout tokens have minimal required permissions and are not exposed unnecessarily.",
                category="API Security",
                owasp="A02:2021 - Cryptographic Failures",
                cwe=["CWE-798", "CWE-200"],
                background="Checkout API tokens enable cart and checkout operations. Excessive exposure may allow manipulation of checkout processes.",
                impact="Exposed checkout tokens could allow attackers to manipulate cart contents or access checkout-related functionality.",
                references=[
                    "https://shopify.dev/docs/api/checkout",
                ],
            )

    def _detect_public_json_endpoints(self, content: str):
        """Detect references to public JSON endpoints."""
        found = []
        for endpoint in self.PUBLIC_JSON_ENDPOINTS:
            if endpoint in content:
                found.append(endpoint)

        self.public_endpoints = found

        for endpoint in found:
            evidence = EvidenceBuilder.exact_match(
                endpoint,
                "Public Shopify JSON endpoint referenced in client content",
            )
            self.add_enriched_vulnerability(
                "Public Shopify JSON Endpoint",
                "Info",
                f"Public Shopify JSON endpoint referenced: {endpoint}",
                evidence,
                "Review whether publicly accessible endpoints expose any sensitive business data or customer information.",
                category="Information Disclosure",
                owasp="A01:2021 - Broken Access Control",
                cwe=["CWE-200"],
                background="Shopify provides public JSON endpoints for AJAX operations. While generally intended for public access, they may expose business-sensitive data.",
                impact="Public endpoints may expose product data, inventory levels, or customer information depending on store configuration.",
            )

    def _detect_liquid_exposure(self, html_content: str):
        """Detect exposed Liquid template code."""
        matches = self.LIQUID_TEMPLATE_PATTERN.findall(html_content)
        if matches:
            self.liquid_exposures = matches[:10]  # Limit to first 10

            sensitive_patterns = [
                r'password',
                r'secret',
                r'key',
                r'token',
                r'customer\.email',
                r'customer\.name',
                r'order\.',
            ]

            has_sensitive = any(
                re.search(pattern, str(match), re.IGNORECASE)
                for match in matches
                for pattern in sensitive_patterns
            )

            if has_sensitive:
                evidence = EvidenceBuilder.exact_match(
                    str(matches[:3]),
                    "Liquid template code with potentially sensitive variables exposed",
                )
                self.add_enriched_vulnerability(
                    "Liquid Template Data Exposure",
                    "Low",
                    "Liquid template code appears to contain sensitive variable references.",
                    evidence,
                    "Review Liquid templates to ensure sensitive customer or order data is not unnecessarily exposed in HTML comments or rendered output.",
                    category="Information Disclosure",
                    owasp="A04:2021 - Insecure Design",
                    cwe=["CWE-200"],
                )

    def _detect_analytics_data(self, js_content: str):
        """Detect Shopify Analytics data exposure."""
        analytics_pattern = re.compile(
            r'ShopifyAnalytics|window\._shopify|_ga_|analytics',
            re.IGNORECASE
        )

        if analytics_pattern.search(js_content):
            self.findings["analytics_detected"] = True

            # Check for enhanced e-commerce data exposure
            ecommerce_pattern = re.compile(
                r'window\.ShopifyAnalytics\.lib\.track\(|window\.dataLayer',
                re.IGNORECASE
            )

            if ecommerce_pattern.search(js_content):
                evidence = EvidenceBuilder.regex_pattern(
                    r"ShopifyAnalytics|window\.dataLayer",
                    "Shopify Analytics/Tracking code detected",
                )
                self.add_enriched_vulnerability(
                    "Analytics Data Collection",
                    "Info",
                    "Shopify Analytics or Google Analytics tracking detected.",
                    evidence,
                    "Ensure analytics implementation complies with privacy regulations (GDPR, CCPA) and has appropriate consent mechanisms.",
                    category="Privacy",
                    owasp="A04:2021 - Insecure Design",
                    cwe=["CWE-200"],
                )

    def _check_cart_endpoint(self, url: str):
        """Check cart.js endpoint for potential data exposure."""
        try:
            cart_url = urljoin(url, "/cart.js")
            response = self.session.get(cart_url, timeout=5)

            if response.status_code == 200:
                content_type = response.headers.get("Content-Type", "")
                if "json" in content_type.lower():
                    self.findings["cart_js_accessible"] = True

                    # Check if cart contains sensitive data patterns
                    content = response.text.lower()
                    sensitive_indicators = [
                        "email", "customer", "address", "phone",
                        "properties", "note"
                    ]

                    found_sensitive = [
                        ind for ind in sensitive_indicators
                        if ind in content
                    ]

                    if found_sensitive:
                        evidence = EvidenceBuilder.exact_match(
                            f"Accessible at: {cart_url}",
                            f"Cart endpoint accessible, contains fields: {', '.join(found_sensitive)}",
                        )
                        self.add_enriched_vulnerability(
                            "Cart Data Exposure",
                            "Low",
                            "/cart.js endpoint is accessible and may expose cart/cart item data.",
                            evidence,
                            "Review cart data structure to ensure no sensitive customer data is exposed via the cart endpoint.",
                            category="Information Disclosure",
                            owasp="A01:2021 - Broken Access Control",
                            cwe=["CWE-200"],
                        )
        except Exception:
            pass
