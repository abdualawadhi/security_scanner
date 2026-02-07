#!/usr/bin/env python3
"""
Analyzer Factory
Low-Code Platform Security Scanner

Factory functions for creating appropriate analyzers for different platforms.

Author: Bachelor Thesis Project - Low-Code Platforms Security Analysis
"""

import requests
from bs4 import BeautifulSoup

from .base import BaseAnalyzer
from .bubble import BubbleAnalyzer
from .outsystems import OutSystemsAnalyzer
from .airtable_enhanced import AirtableAnalyzer
from .generic import GenericWebAnalyzer
from .shopify import ShopifyAnalyzer
from .webflow import WebflowAnalyzer
from .wix import WixAnalyzer
from .mendix import MendixAnalyzer
from .reports import SecurityReportGenerator


def get_analyzer_for_platform(platform_type: str, session: requests.Session) -> BaseAnalyzer:
    """Factory function to get appropriate analyzer for platform"""
    
    analyzers = {
        "bubble": BubbleAnalyzer,
        "bubble.io": BubbleAnalyzer,
        "outsystems": OutSystemsAnalyzer,
        "outsystems.dev": OutSystemsAnalyzer,
        "airtable": AirtableAnalyzer,
        "airtable.com": AirtableAnalyzer,
        "shopify": ShopifyAnalyzer,
        "myshopify.com": ShopifyAnalyzer,
        "webflow": WebflowAnalyzer,
        "webflow.io": WebflowAnalyzer,
        "wix": WixAnalyzer,
        "wix.com": WixAnalyzer,
        "mendix": MendixAnalyzer,
        "mendixcloud.com": MendixAnalyzer,
        "mern": GenericWebAnalyzer,
        "mern-stack": GenericWebAnalyzer,
        "generic": GenericWebAnalyzer,
        "unknown": GenericWebAnalyzer,
    }
    
    analyzer_class = analyzers.get(platform_type.lower(), GenericWebAnalyzer)
    return analyzer_class(session)


def analyze_platform_security(
    url: str,
    platform_type: str,
    response: requests.Response,
    soup: BeautifulSoup,
    session: requests.Session,
) -> dict:
    """Main function to analyze platform security using appropriate analyzer"""
    analyzer = get_analyzer_for_platform(platform_type, session)
    results = analyzer.analyze(url, response, soup)

    # Generate additional analysis
    report_generator = SecurityReportGenerator()
    results["executive_summary"] = report_generator.generate_executive_summary(results)
    results["recommendations_matrix"] = (
        report_generator.generate_recommendations_matrix(
            results.get("vulnerabilities", [])
        )
    )

    return results


def get_supported_platforms() -> list:
    """Get list of supported platforms"""
    return [
        "bubble.io",
        "outsystems", 
        "airtable.com",
        "shopify",
        "webflow",
        "wix",
        "mendix",
        "generic",
        "mern",
        "mern-stack",
    ]


def validate_platform_type(platform_type: str) -> bool:
    """Validate if platform type is supported"""
    supported = get_supported_platforms()
    return platform_type.lower() in [p.lower() for p in supported]


def get_platform_info(platform_type: str) -> dict:
    """Get information about a specific platform"""
    platform_info = {
        "bubble.io": {
            "name": "Bubble.io",
            "description": "Visual web application builder",
            "analyzer": "BubbleAnalyzer",
            "common_vulnerabilities": [
                "Workflow API exposure",
                "Privacy rules bypass",
                "Database schema leak",
                "Authentication token exposure",
            ]
        },
        "outsystems": {
            "name": "OutSystems",
            "description": "Enterprise low-code platform",
            "analyzer": "OutSystemsAnalyzer", 
            "common_vulnerabilities": [
                "REST API security issues",
                "Screen action privilege escalation",
                "Entity exposure",
                "Session management problems",
            ]
        },
        "airtable.com": {
            "name": "Airtable",
            "description": "Database and workflow platform",
            "analyzer": "AirtableAnalyzer",
            "common_vulnerabilities": [
                "Base ID exposure",
                "API key exposure",
                "Table structure analysis",
                "Permission model issues",
            ]
        },
        "generic": {
            "name": "Generic Web Application",
            "description": "General web security analysis",
            "analyzer": "GenericWebAnalyzer",
            "common_vulnerabilities": [
                "Missing security headers",
                "Cross-site scripting",
                "SQL injection",
                "File upload issues",
            ]
        },
        "shopify": {
            "name": "Shopify",
            "description": "E-commerce storefront platform",
            "analyzer": "ShopifyAnalyzer",
            "common_vulnerabilities": [
                "Storefront token exposure",
                "Public JSON endpoints",
                "Missing security headers",
                "XSS in custom themes",
            ]
        },
        "webflow": {
            "name": "Webflow",
            "description": "Visual web design platform",
            "analyzer": "WebflowAnalyzer",
            "common_vulnerabilities": [
                "Public API endpoints",
                "Missing CSRF on forms",
                "XSS in embedded scripts",
            ]
        },
        "wix": {
            "name": "Wix",
            "description": "Website builder platform",
            "analyzer": "WixAnalyzer",
            "common_vulnerabilities": [
                "Exposed API endpoints",
                "Information disclosure",
                "Missing security headers",
            ]
        },
        "mendix": {
            "name": "Mendix",
            "description": "Enterprise low-code platform",
            "analyzer": "MendixAnalyzer",
            "common_vulnerabilities": [
                "Exposed REST endpoints",
                "Information disclosure",
                "Access control issues",
            ]
        },
        "mern": {
            "name": "MERN Stack",
            "description": "MongoDB Express React Node.js applications",
            "analyzer": "GenericWebAnalyzer",
            "common_vulnerabilities": [
                "NoSQL injection",
                "XSS in React components",
                "JWT token issues",
                "CORS misconfiguration",
            ]
        }
    }
    
    return platform_info.get(platform_type.lower(), platform_info.get("generic", {}))
