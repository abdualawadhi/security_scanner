#!/usr/bin/env python3
"""
Security Analyzers Package
Low-Code Platform Security Scanner

This package contains specialized analyzers for different low-code platforms
and security vulnerability detection methods.

Author: Bachelor Thesis Project - Low-Code Platforms Security Analysis
"""

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
from .factory import (
    get_analyzer_for_platform,
    analyze_platform_security,
    get_supported_platforms,
    validate_platform_type,
    get_platform_info,
)

__all__ = [
    "BaseAnalyzer",
    "BubbleAnalyzer", 
    "OutSystemsAnalyzer",
    "AirtableAnalyzer",
    "GenericWebAnalyzer",
    "ShopifyAnalyzer",
    "WebflowAnalyzer",
    "WixAnalyzer",
    "MendixAnalyzer",
    "SecurityReportGenerator",
    "get_analyzer_for_platform",
    "analyze_platform_security",
    "get_supported_platforms",
    "validate_platform_type",
    "get_platform_info",
]

__version__ = "2.0.0"
__author__ = "Bachelor Thesis Project"
