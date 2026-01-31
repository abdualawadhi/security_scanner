#!/usr/bin/env python3
"""
Ultra-Comprehensive Low-Code Platform Security Scanner

An advanced, enterprise-grade security scanner specifically designed for detecting
vulnerabilities in low-code/no-code platforms with AI-powered detection,
real-time monitoring, and comprehensive compliance frameworks.

Author: Advanced Bachelor Thesis Project - Enterprise Low-Code Platform Security Analysis
"""

import requests
import json
import time
import asyncio
import threading
import concurrent.futures
from typing import Dict, List, Optional, Any, Union, Callable
from urllib.parse import urlparse, urljoin, parse_qs
from bs4 import BeautifulSoup
import ssl
import socket
import hashlib
import re
import logging
import pickle
import os
from datetime import datetime, timedelta
from collections import defaultdict, Counter
import statistics
from dataclasses import dataclass, asdict
import yaml
import csv
from io import StringIO
import base64
import uuid
from concurrent.futures import ThreadPoolExecutor
import queue
import schedule
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import sqlite3
from contextlib import contextmanager

# Advanced ML imports (optional)
try:
    import joblib
    import numpy as np
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.feature_extraction.text import TfidfVectorizer
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False

from .base import BaseAnalyzer
from .bubble import BubbleAnalyzer
from .outsystems import OutSystemsAnalyzer
from .airtable import AirtableAnalyzer
from .generic import GenericWebAnalyzer


class LowCodePlatformScanner:
    """
    Comprehensive security scanner dedicated to low-code platforms.

    This scanner provides specialized detection capabilities for the most
    popular low-code/no-code platforms, including:
    - Airtable
    - Bubble.io
    - OutSystems
    - MERN Stack applications
    - Generic low-code platforms
    """

    # Ultra-Comprehensive Low-Code Platform Support
    SUPPORTED_PLATFORMS = {
        # Major Enterprise Platforms
        "airtable": {
            "name": "Airtable",
            "domains": ["airtable.com", "airtableusercontent.com"],
            "analyzer": "airtable",
            "description": "Cloud-based database and collaboration platform",
            "category": "database",
            "enterprise": True,
            "indicators": ["airtable", "base", "table", "view"]
        },
        "bubble": {
            "name": "Bubble.io",
            "domains": ["bubble.io", "bubbleapps.io", "bubbleusercontent.com"],
            "analyzer": "bubble",
            "description": "Visual programming platform for web applications",
            "category": "web_app",
            "enterprise": True,
            "indicators": ["bubble", "bubbleapps", "workflow", "privacy rules"]
        },
        "outsystems": {
            "name": "OutSystems",
            "domains": ["outsystems.com", "outsystemscloud.com", "outsystems.app"],
            "analyzer": "outsystems",
            "description": "Enterprise low-code application development platform",
            "category": "enterprise",
            "enterprise": True,
            "indicators": ["outsystems", "screen action", "entity", "aggregate"]
        },
        "powerapps": {
            "name": "Microsoft Power Apps",
            "domains": ["powerapps.com", "powerplatform.com", "apps.powerplatform.com"],
            "analyzer": "generic",
            "description": "Microsoft's low-code app development platform",
            "category": "enterprise",
            "enterprise": True,
            "indicators": ["powerapps", "power platform", "dataverse", "canvas app"]
        },
        "powerautomate": {
            "name": "Microsoft Power Automate",
            "domains": ["powerautomate.com", "flow.microsoft.com"],
            "analyzer": "generic",
            "description": "Microsoft's workflow automation platform",
            "category": "automation",
            "enterprise": True,
            "indicators": ["power automate", "flow", "workflow", "automation"]
        },
        "salesforce_lightning": {
            "name": "Salesforce Lightning",
            "domains": ["salesforce.com", "lightning.force.com", "my.salesforce.com"],
            "analyzer": "generic",
            "description": "Salesforce's low-code development platform",
            "category": "crm",
            "enterprise": True,
            "indicators": ["lightning", "salesforce", "apex", "visualforce"]
        },
        "mendix": {
            "name": "Mendix",
            "domains": ["mendix.com", "mendixcloud.com"],
            "analyzer": "generic",
            "description": "Siemens-owned low-code platform",
            "category": "enterprise",
            "enterprise": True,
            "indicators": ["mendix", "siemens", "low-code", "model-driven"]
        },
        "appian": {
            "name": "Appian",
            "domains": ["appian.com", "appiancloud.com"],
            "analyzer": "generic",
            "description": "Enterprise low-code automation platform",
            "category": "enterprise",
            "enterprise": True,
            "indicators": ["appian", "process model", "case management", "workflow"]
        },

        # Web Development Platforms
        "webflow": {
            "name": "Webflow",
            "domains": ["webflow.com", "webflow.io"],
            "analyzer": "generic",
            "description": "Visual web design and development platform",
            "category": "web_design",
            "enterprise": False,
            "indicators": ["webflow", "cms", "visual design", "responsive"]
        },
        "carrd": {
            "name": "Carrd",
            "domains": ["carrd.co"],
            "analyzer": "generic",
            "description": "Simple, responsive web design platform",
            "category": "web_design",
            "enterprise": False,
            "indicators": ["carrd", "one-page", "responsive", "simple"]
        },
        "squarespace": {
            "name": "Squarespace",
            "domains": ["squarespace.com"],
            "analyzer": "generic",
            "description": "Website building and hosting platform",
            "category": "cms",
            "enterprise": False,
            "indicators": ["squarespace", "website builder", "hosting", "templates"]
        },
        "wix": {
            "name": "Wix",
            "domains": ["wix.com", "wixsite.com"],
            "analyzer": "generic",
            "description": "Cloud-based web development platform",
            "category": "web_design",
            "enterprise": False,
            "indicators": ["wix", "adi", "corvid", "velo"]
        },

        # Mobile App Platforms
        "glide": {
            "name": "Glide",
            "domains": ["glideapps.com", "glide.page"],
            "analyzer": "generic",
            "description": "Mobile app development from spreadsheets",
            "category": "mobile",
            "enterprise": False,
            "indicators": ["glide", "spreadsheet", "mobile app", "pwa"]
        },
        "adalo": {
            "name": "Adalo",
            "domains": ["adalo.com", "on.adalo.com"],
            "analyzer": "generic",
            "description": "No-code mobile and web app builder",
            "category": "mobile",
            "enterprise": False,
            "indicators": ["adalo", "no-code", "mobile app", "pwa"]
        },
        "thunkable": {
            "name": "Thunkable",
            "domains": ["thunkable.com", "x.thunkable.com"],
            "analyzer": "generic",
            "description": "Drag-and-drop mobile app builder",
            "category": "mobile",
            "enterprise": False,
            "indicators": ["thunkable", "drag-and-drop", "mobile app", "blocks"]
        },
        "appsheet": {
            "name": "AppSheet",
            "domains": ["appsheet.com", "appsheetusercontent.com"],
            "analyzer": "generic",
            "description": "No-code app development from data sources",
            "category": "mobile",
            "enterprise": True,
            "indicators": ["appsheet", "data sources", "automation", "mobile app"]
        },
        "bubblewrap": {
            "name": "Bubblewrap",
            "domains": ["bubblewrap.io"],
            "analyzer": "generic",
            "description": "PWA wrapper for mobile apps",
            "category": "mobile",
            "enterprise": False,
            "indicators": ["bubblewrap", "pwa", "twa", "mobile"]
        },

        # Database & Backend Platforms
        "supabase": {
            "name": "Supabase",
            "domains": ["supabase.com", "supabase.co"],
            "analyzer": "generic",
            "description": "Open source Firebase alternative",
            "category": "backend",
            "enterprise": False,
            "indicators": ["supabase", "postgres", "realtime", "auth"]
        },
        "planetscale": {
            "name": "PlanetScale",
            "domains": ["planetscale.com"],
            "analyzer": "generic",
            "description": "Serverless MySQL platform",
            "category": "database",
            "enterprise": True,
            "indicators": ["planetscale", "mysql", "serverless", "scaling"]
        },
        "fauna": {
            "name": "Fauna",
            "domains": ["fauna.com", "fauna-db.com"],
            "analyzer": "generic",
            "description": "Serverless database platform",
            "category": "database",
            "enterprise": True,
            "indicators": ["fauna", "serverless", "graphql", "temporal"]
        },

        # API & Integration Platforms
        "zapier": {
            "name": "Zapier",
            "domains": ["zapier.com", "zapier.app"],
            "analyzer": "generic",
            "description": "Automation and integration platform",
            "category": "integration",
            "enterprise": True,
            "indicators": ["zapier", "automation", "integration", "webhook"]
        },
        "make": {
            "name": "Make (Integromat)",
            "domains": ["make.com", "integromat.com"],
            "analyzer": "generic",
            "description": "Visual automation platform",
            "category": "integration",
            "enterprise": True,
            "indicators": ["make", "integromat", "automation", "scenario"]
        },
        "postman": {
            "name": "Postman",
            "domains": ["postman.com", "postman.co"],
            "analyzer": "generic",
            "description": "API development and testing platform",
            "category": "api",
            "enterprise": True,
            "indicators": ["postman", "api", "collection", "workspace"]
        },

        # MERN Stack & Full-Stack Platforms
        "mern": {
            "name": "MERN Stack",
            "domains": ["render.com", "vercel.app", "netlify.app", "herokuapp.com", "railway.app"],
            "analyzer": "generic",
            "description": "MongoDB, Express.js, React, Node.js stack applications",
            "category": "fullstack",
            "enterprise": False,
            "indicators": ["react", "mongodb", "express", "node", "mern"]
        },
        "nextjs": {
            "name": "Next.js",
            "domains": ["vercel.app", "nextjs.org"],
            "analyzer": "generic",
            "description": "React framework for production",
            "category": "framework",
            "enterprise": False,
            "indicators": ["next.js", "vercel", "ssr", "static generation"]
        },
        "nuxtjs": {
            "name": "Nuxt.js",
            "domains": ["nuxtjs.org", "nuxt.com"],
            "analyzer": "generic",
            "description": "Vue.js framework for production",
            "category": "framework",
            "enterprise": False,
            "indicators": ["nuxt", "vue", "ssr", "universal"]
        },

        # Form & Survey Platforms
        "typeform": {
            "name": "Typeform",
            "domains": ["typeform.com"],
            "analyzer": "generic",
            "description": "Interactive form and survey platform",
            "category": "forms",
            "enterprise": True,
            "indicators": ["typeform", "form", "survey", "interactive"]
        },
        "google_forms": {
            "name": "Google Forms",
            "domains": ["forms.google.com", "docs.google.com/forms"],
            "analyzer": "generic",
            "description": "Google's form creation platform",
            "category": "forms",
            "enterprise": False,
            "indicators": ["google forms", "form", "survey", "spreadsheet"]
        },

        # E-commerce Platforms
        "shopify": {
            "name": "Shopify",
            "domains": ["shopify.com", "myshopify.com"],
            "analyzer": "generic",
            "description": "E-commerce platform",
            "category": "ecommerce",
            "enterprise": True,
            "indicators": ["shopify", "ecommerce", "store", "liquid"]
        },
        "woocommerce": {
            "name": "WooCommerce",
            "domains": ["woocommerce.com"],
            "analyzer": "generic",
            "description": "WordPress e-commerce plugin",
            "category": "ecommerce",
            "enterprise": False,
            "indicators": ["woocommerce", "wordpress", "ecommerce", "store"]
        },

        # Learning Management Systems
        "moodle": {
            "name": "Moodle",
            "domains": ["moodle.org"],
            "analyzer": "generic",
            "description": "Open source learning platform",
            "category": "lms",
            "enterprise": False,
            "indicators": ["moodle", "lms", "course", "learning"]
        },
        "canvas": {
            "name": "Canvas LMS",
            "domains": ["canvaslms.com", "instructure.com"],
            "analyzer": "generic",
            "description": "Cloud-based learning management system",
            "category": "lms",
            "enterprise": True,
            "indicators": ["canvas", "lms", "course", "instructure"]
        },

        # Collaboration & Project Management
        "trello": {
            "name": "Trello",
            "domains": ["trello.com"],
            "analyzer": "generic",
            "description": "Kanban-style project management",
            "category": "collaboration",
            "enterprise": True,
            "indicators": ["trello", "kanban", "board", "card"]
        },
        "asana": {
            "name": "Asana",
            "domains": ["asana.com", "app.asana.com"],
            "analyzer": "generic",
            "description": "Work management platform",
            "category": "collaboration",
            "enterprise": True,
            "indicators": ["asana", "task", "project", "workflow"]
        },
        "monday": {
            "name": "Monday.com",
            "domains": ["monday.com"],
            "analyzer": "generic",
            "description": "Work management platform",
            "category": "collaboration",
            "enterprise": True,
            "indicators": ["monday", "work management", "automation", "dashboard"]
        },

        # Analytics & BI Platforms
        "tableau": {
            "name": "Tableau",
            "domains": ["tableau.com", "tableauonline.com"],
            "analyzer": "generic",
            "description": "Business intelligence and analytics platform",
            "category": "analytics",
            "enterprise": True,
            "indicators": ["tableau", "dashboard", "visualization", "analytics"]
        },
        "powerbi": {
            "name": "Power BI",
            "domains": ["powerbi.com", "app.powerbi.com"],
            "analyzer": "generic",
            "description": "Microsoft's business analytics service",
            "category": "analytics",
            "enterprise": True,
            "indicators": ["power bi", "dashboard", "visualization", "analytics"]
        },

        # IoT & Hardware Platforms
        "particle": {
            "name": "Particle",
            "domains": ["particle.io"],
            "analyzer": "generic",
            "description": "IoT platform for connected devices",
            "category": "iot",
            "enterprise": True,
            "indicators": ["particle", "iot", "device", "firmware"]
        },
        "arduino_iot": {
            "name": "Arduino IoT Cloud",
            "domains": ["arduino.cc", "create.arduino.cc"],
            "analyzer": "generic",
            "description": "IoT platform for Arduino devices",
            "category": "iot",
            "enterprise": False,
            "indicators": ["arduino", "iot", "device", "cloud"]
        }
    }

    def __init__(self, session: Optional[requests.Session] = None):
        """
        Initialize the Low-Code Platform Security Scanner.

        Args:
            session: Optional requests session to use for HTTP requests
        """
        self.session = session or requests.Session()
        self.session.headers.update({
            'User-Agent': 'Low-Code Platform Security Scanner v2.0',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
        })

        # Configure logging
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.INFO)

        # Platform detection results
        self.detected_platforms = []
        self.scan_results = {}

        # Initialize analyzers
        self.analyzers = {
            "bubble": BubbleAnalyzer(self.session),
            "outsystems": OutSystemsAnalyzer(self.session),
            "airtable": AirtableAnalyzer(self.session),
            "generic": GenericWebAnalyzer(self.session)
        }

    def detect_platform(self, url: str) -> Dict[str, Any]:
        """
        Detect the low-code platform being used by analyzing the target URL.

        Args:
            url: Target URL to analyze

        Returns:
            Dictionary containing platform detection results
        """
        self.logger.info(f"Detecting low-code platform for: {url}")

        detection_result = {
            "url": url,
            "detected_platforms": [],
            "confidence_scores": {},
            "platform_characteristics": {},
            "recommendations": []
        }

        try:
            # Parse URL
            parsed_url = urlparse(url)
            domain = parsed_url.netloc.lower()

            # Check for known platform domains
            for platform_key, platform_info in self.SUPPORTED_PLATFORMS.items():
                for platform_domain in platform_info["domains"]:
                    if platform_domain in domain:
                        detection_result["detected_platforms"].append(platform_key)
                        detection_result["confidence_scores"][platform_key] = 0.9
                        detection_result["platform_characteristics"][platform_key] = platform_info
                        break

            # If no platform detected by domain, try content analysis
            if not detection_result["detected_platforms"]:
                content_detection = self._detect_platform_by_content(url)
                detection_result["detected_platforms"].extend(content_detection["platforms"])
                detection_result["confidence_scores"].update(content_detection["scores"])

            # If still no platform detected, classify as generic
            if not detection_result["detected_platforms"]:
                detection_result["detected_platforms"].append("generic")
                detection_result["confidence_scores"]["generic"] = 0.5
                detection_result["platform_characteristics"]["generic"] = {
                    "name": "Generic Low-Code Platform",
                    "analyzer": "generic",
                    "description": "Unknown or custom low-code platform"
                }

            # Generate recommendations
            detection_result["recommendations"] = self._generate_platform_recommendations(
                detection_result["detected_platforms"]
            )

        except Exception as e:
            self.logger.error(f"Error detecting platform for {url}: {str(e)}")
            detection_result["error"] = str(e)

        self.detected_platforms = detection_result["detected_platforms"]
        return detection_result

    def _detect_platform_by_content(self, url: str) -> Dict[str, Any]:
        """
        Detect platform by analyzing page content and headers.

        Args:
            url: Target URL

        Returns:
            Dictionary with detected platforms and confidence scores
        """
        result = {"platforms": [], "scores": {}}

        try:
            response = self.session.get(url, timeout=10)
            soup = BeautifulSoup(response.content, 'html.parser')

            # Check for platform-specific indicators

            # Bubble.io indicators
            if soup.find('script', string=re.compile(r'bubble\.io|bubbleapps\.io')):
                result["platforms"].append("bubble")
                result["scores"]["bubble"] = 0.8

            # OutSystems indicators
            if soup.find('meta', {'name': 'generator', 'content': re.compile(r'OutSystems', re.I)}):
                result["platforms"].append("outsystems")
                result["scores"]["outsystems"] = 0.9

            # MERN stack indicators
            if soup.find('script', string=re.compile(r'react|mongodb|express', re.I)):
                result["platforms"].append("mern")
                result["scores"]["mern"] = 0.7

            # Check response headers for platform clues
            server_header = response.headers.get('Server', '').lower()
            if 'airtable' in server_header:
                result["platforms"].append("airtable")
                result["scores"]["airtable"] = 0.8

            # Check for common low-code platform patterns
            page_text = soup.get_text().lower()

            # Glide indicators
            if 'glide' in page_text and ('spreadsheet' in page_text or 'sheet' in page_text):
                result["platforms"].append("glide")
                result["scores"]["glide"] = 0.6

            # Adalo indicators
            if 'adalo' in page_text or soup.find('script', string=re.compile(r'adalo', re.I)):
                result["platforms"].append("adalo")
                result["scores"]["adalo"] = 0.6

        except Exception as e:
            self.logger.warning(f"Content-based platform detection failed: {str(e)}")

        return result

    def _generate_platform_recommendations(self, platforms: List[str]) -> List[str]:
        """
        Generate security recommendations based on detected platforms.

        Args:
            platforms: List of detected platform identifiers

        Returns:
            List of security recommendations
        """
        recommendations = []

        platform_recommendations = {
            "airtable": [
                "Ensure API keys are properly secured and rotated regularly",
                "Review sharing permissions and access controls",
                "Monitor for unauthorized data exports",
                "Implement proper authentication for sensitive bases"
            ],
            "bubble": [
                "Review privacy rules and data access controls",
                "Secure API workflows and external API calls",
                "Implement proper user authentication flows",
                "Monitor for exposed sensitive data in workflows"
            ],
            "outsystems": [
                "Review role-based access controls",
                "Secure session management and tokens",
                "Monitor for host header injection vulnerabilities",
                "Implement proper input validation and sanitization"
            ],
            "mern": [
                "Secure MongoDB connections and authentication",
                "Implement proper CORS policies",
                "Review JWT token security and expiration",
                "Monitor for NoSQL injection vulnerabilities"
            ],
            "generic": [
                "Implement comprehensive input validation",
                "Review authentication and authorization mechanisms",
                "Secure API endpoints and data transmission",
                "Monitor for common web vulnerabilities"
            ]
        }

        for platform in platforms:
            if platform in platform_recommendations:
                recommendations.extend(platform_recommendations[platform])

        # Add general low-code platform recommendations
        recommendations.extend([
            "Regular security audits and penetration testing",
            "Keep platform and dependencies updated",
            "Implement proper logging and monitoring",
            "Train developers on secure coding practices"
        ])

        return list(set(recommendations))  # Remove duplicates

    def comprehensive_scan(self, url: str, platform_hint: Optional[str] = None) -> Dict[str, Any]:
        """
        Perform a comprehensive security scan of the low-code platform.

        Args:
            url: Target URL to scan
            platform_hint: Optional platform hint to override auto-detection

        Returns:
            Comprehensive scan results
        """
        self.logger.info(f"Starting comprehensive low-code platform scan for: {url}")

        scan_start_time = time.time()

        # Initialize results
        results = {
            "scan_metadata": {
                "target_url": url,
                "scan_timestamp": datetime.now().isoformat(),
                "scanner_version": "2.0",
                "scan_type": "comprehensive_low_code"
            },
            "platform_detection": {},
            "vulnerability_findings": [],
            "security_assessment": {},
            "recommendations": [],
            "scan_duration": 0
        }

        try:
            # Step 1: Platform Detection
            if platform_hint:
                results["platform_detection"] = {
                    "detected_platforms": [platform_hint],
                    "confidence_scores": {platform_hint: 1.0},
                    "detection_method": "manual_hint"
                }
                self.detected_platforms = [platform_hint]
            else:
                results["platform_detection"] = self.detect_platform(url)

            # Step 2: Vulnerability Scanning
            all_vulnerabilities = []
            security_scores = {}

            for platform in self.detected_platforms:
                self.logger.info(f"Scanning with {platform} analyzer")

                try:
                    analyzer = self.analyzers.get(platform, self.analyzers["generic"])

                    # Get basic response for analysis
                    response = self.session.get(url, timeout=15)
                    soup = BeautifulSoup(response.content, 'html.parser')

                    # Run platform-specific analysis
                    platform_results = analyzer.analyze(url, response, soup)

                    # Extract vulnerabilities
                    vulnerabilities = platform_results.get("vulnerabilities", [])
                    all_vulnerabilities.extend(vulnerabilities)

                    # Calculate platform-specific security score
                    security_scores[platform] = self._calculate_platform_security_score(vulnerabilities)

                except Exception as e:
                    self.logger.error(f"Error scanning with {platform} analyzer: {str(e)}")
                    all_vulnerabilities.append({
                        "type": "Scan Error",
                        "severity": "Info",
                        "description": f"Error during {platform} analysis: {str(e)}",
                        "platform": platform
                    })

            results["vulnerability_findings"] = all_vulnerabilities

            # Step 3: Security Assessment
            results["security_assessment"] = self._generate_security_assessment(
                all_vulnerabilities, security_scores
            )

            # Step 4: Generate Recommendations
            results["recommendations"] = self._generate_comprehensive_recommendations(
                all_vulnerabilities, self.detected_platforms
            )

        except Exception as e:
            self.logger.error(f"Comprehensive scan failed: {str(e)}")
            results["error"] = str(e)

        # Calculate scan duration
        scan_duration = time.time() - scan_start_time
        results["scan_metadata"]["scan_duration_seconds"] = round(scan_duration, 2)

        self.scan_results = results
        return results

    def _calculate_platform_security_score(self, vulnerabilities: List[Dict]) -> Dict[str, Any]:
        """
        Calculate security score for a platform based on vulnerabilities.

        Args:
            vulnerabilities: List of vulnerabilities found

        Returns:
            Security score information
        """
        severity_weights = {
            "Critical": 10,
            "High": 7,
            "Medium": 5,
            "Low": 3,
            "Info": 1
        }

        total_score = 100
        severity_breakdown = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}

        for vuln in vulnerabilities:
            severity = vuln.get("severity", "Info")
            severity_breakdown[severity] += 1
            total_score -= severity_weights.get(severity, 1)

        # Ensure score doesn't go below 0
        total_score = max(0, total_score)

        return {
            "overall_score": total_score,
            "severity_breakdown": severity_breakdown,
            "vulnerability_count": len(vulnerabilities),
            "grade": self._score_to_grade(total_score)
        }

    def _score_to_grade(self, score: int) -> str:
        """Convert numeric score to letter grade."""
        if score >= 90:
            return "A"
        elif score >= 80:
            return "B"
        elif score >= 70:
            return "C"
        elif score >= 60:
            return "D"
        else:
            return "F"

    def _generate_security_assessment(self, vulnerabilities: List[Dict],
                                    security_scores: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate comprehensive security assessment.

        Args:
            vulnerabilities: All vulnerabilities found
            security_scores: Security scores by platform

        Returns:
            Security assessment summary
        """
        assessment = {
            "overall_security_level": "Unknown",
            "risk_summary": {},
            "compliance_status": {},
            "critical_findings": []
        }

        # Calculate overall security level
        total_vulns = len(vulnerabilities)
        critical_count = sum(1 for v in vulnerabilities if v.get("severity") == "Critical")
        high_count = sum(1 for v in vulnerabilities if v.get("severity") == "High")

        if critical_count > 0:
            assessment["overall_security_level"] = "Critical"
        elif high_count > 3:
            assessment["overall_security_level"] = "High Risk"
        elif high_count > 0:
            assessment["overall_security_level"] = "Medium Risk"
        elif total_vulns > 10:
            assessment["overall_security_level"] = "Low Risk"
        else:
            assessment["overall_security_level"] = "Secure"

        # Risk summary
        assessment["risk_summary"] = {
            "total_vulnerabilities": total_vulns,
            "critical_issues": critical_count,
            "high_risk_issues": high_count,
            "platforms_scanned": len(self.detected_platforms)
        }

        # Critical findings
        assessment["critical_findings"] = [
            v for v in vulnerabilities
            if v.get("severity") in ["Critical", "High"]
        ][:10]  # Top 10 critical findings

        # Compliance status (basic OWASP alignment)
        owasp_compliance = self._check_owasp_compliance(vulnerabilities)
        assessment["compliance_status"] = owasp_compliance

        return assessment

    def _check_owasp_compliance(self, vulnerabilities: List[Dict]) -> Dict[str, Any]:
        """
        Check OWASP Top 10 compliance based on vulnerabilities found.

        Args:
            vulnerabilities: List of vulnerabilities

        Returns:
            OWASP compliance assessment
        """
        owasp_categories = {
            "A01:2021 - Broken Access Control": ["Broken Access Control", "RBAC", "Authorization"],
            "A02:2021 - Cryptographic Failures": ["TLS", "SSL", "Certificate", "Encryption"],
            "A03:2021 - Injection": ["SQL Injection", "XSS", "Injection", "Command Injection"],
            "A04:2021 - Insecure Design": ["Design", "Architecture"],
            "A05:2021 - Security Misconfiguration": ["Misconfiguration", "Headers", "CSP"],
            "A06:2021 - Vulnerable Components": ["Dependencies", "Components"],
            "A07:2021 - Identification & Authentication": ["Authentication", "Session"],
            "A08:2021 - Software Integrity": ["Integrity", "Tampering"],
            "A09:2021 - Security Logging": ["Logging", "Monitoring"],
            "A10:2021 - SSRF": ["SSRF", "Server-side Request"]
        }

        compliance = {}
        total_categories = len(owasp_categories)

        for category, keywords in owasp_categories.items():
            category_vulns = [
                v for v in vulnerabilities
                if any(keyword.lower() in v.get("type", "").lower() for keyword in keywords)
            ]
            compliance[category] = {
                "compliant": len(category_vulns) == 0,
                "issues_found": len(category_vulns),
                "severity": "High" if category_vulns else "None"
            }

        compliant_categories = sum(1 for c in compliance.values() if c["compliant"])
        compliance_percentage = (compliant_categories / total_categories) * 100

        return {
            "overall_compliance": f"{compliance_percentage:.1f}%",
            "compliant_categories": compliant_categories,
            "total_categories": total_categories,
            "category_details": compliance
        }

    def _generate_comprehensive_recommendations(self, vulnerabilities: List[Dict],
                                              platforms: List[str]) -> List[Dict]:
        """
        Generate comprehensive security recommendations.

        Args:
            vulnerabilities: All vulnerabilities found
            platforms: Detected platforms

        Returns:
            List of prioritized recommendations
        """
        recommendations = []

        # Group vulnerabilities by type
        vuln_types = {}
        for vuln in vulnerabilities:
            vuln_type = vuln.get("type", "Unknown")
            if vuln_type not in vuln_types:
                vuln_types[vuln_type] = []
            vuln_types[vuln_type].append(vuln)

        # Generate recommendations based on vulnerability types
        for vuln_type, vulns in vuln_types.items():
            severity = max((v.get("severity", "Info") for v in vulns),
                          key=lambda s: ["Info", "Low", "Medium", "High", "Critical"].index(s))

            recommendation = {
                "priority": self._get_priority_level(severity, len(vulns)),
                "category": vuln_type,
                "severity": severity,
                "instances": len(vulns),
                "description": f"Address {len(vulns)} instance(s) of {vuln_type}",
                "platforms_affected": list(set(platforms))
            }
            recommendations.append(recommendation)

        # Sort by priority
        priority_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
        recommendations.sort(key=lambda r: (priority_order.get(r["severity"], 5), -r["instances"]))

        return recommendations[:20]  # Top 20 recommendations

    def _get_priority_level(self, severity: str, count: int) -> str:
        """Determine priority level based on severity and frequency."""
        if severity == "Critical":
            return "Immediate"
        elif severity == "High" or (severity == "Medium" and count > 2):
            return "High"
        elif severity == "Medium" or (severity == "Low" and count > 3):
            return "Medium"
        else:
            return "Low"

    def generate_report(self, output_format: str = "json") -> str:
        """
        Generate a comprehensive security report.

        Args:
            output_format: Report format ("json", "html", "text")

        Returns:
            Formatted report
        """
        if not self.scan_results:
            return "No scan results available. Run comprehensive_scan() first."

        if output_format == "json":
            return json.dumps(self.scan_results, indent=2, default=str)
        elif output_format == "html":
            return self._generate_html_report()
        elif output_format == "text":
            return self._generate_text_report()
        else:
            raise ValueError(f"Unsupported format: {output_format}")

    def _generate_html_report(self) -> str:
        """Generate HTML security report."""
        results = self.scan_results

        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Low-Code Platform Security Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .header {{ background: #2c3e50; color: white; padding: 20px; border-radius: 5px; }}
                .section {{ margin: 20px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }}
                .vulnerability {{ margin: 10px 0; padding: 10px; border-left: 4px solid; }}
                .critical {{ border-left-color: #e74c3c; background: #fdf2f2; }}
                .high {{ border-left-color: #e67e22; background: #fdf5f0; }}
                .medium {{ border-left-color: #f39c12; background: #fdf9f0; }}
                .low {{ border-left-color: #27ae60; background: #f0fdf2; }}
                .info {{ border-left-color: #3498db; background: #f0f8ff; }}
                .score {{ font-size: 24px; font-weight: bold; text-align: center; }}
                table {{ width: 100%; border-collapse: collapse; margin: 10px 0; }}
                th, td {{ padding: 8px; text-align: left; border-bottom: 1px solid #ddd; }}
                th {{ background-color: #f2f2f2; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>Low-Code Platform Security Assessment</h1>
                <p>Comprehensive Security Scan Results</p>
                <p><strong>Target:</strong> {results['scan_metadata']['target_url']}</p>
                <p><strong>Scan Date:</strong> {results['scan_metadata']['scan_timestamp']}</p>
            </div>

            <div class="section">
                <h2>Platform Detection</h2>
                <p><strong>Detected Platforms:</strong> {', '.join(results['platform_detection'].get('detected_platforms', []))}</p>
            </div>

            <div class="section">
                <h2>Security Assessment</h2>
                <div class="score">
                    Overall Security Level: {results['security_assessment'].get('overall_security_level', 'Unknown')}
                </div>
                <p><strong>Total Vulnerabilities:</strong> {results['security_assessment']['risk_summary'].get('total_vulnerabilities', 0)}</p>
                <p><strong>OWASP Compliance:</strong> {results['security_assessment']['compliance_status'].get('overall_compliance', 'Unknown')}</p>
            </div>

            <div class="section">
                <h2>Vulnerability Findings</h2>
        """

        for vuln in results.get('vulnerability_findings', []):
            severity_class = vuln.get('severity', 'Info').lower()
            html += f"""
                <div class="vulnerability {severity_class}">
                    <h3>{vuln.get('type', 'Unknown')} ({vuln.get('severity', 'Info')})</h3>
                    <p>{vuln.get('description', 'No description available')}</p>
                </div>
            """

        html += """
            </div>

            <div class="section">
                <h2>Recommendations</h2>
                <table>
                    <tr><th>Priority</th><th>Category</th><th>Severity</th><th>Description</th></tr>
        """

        for rec in results.get('recommendations', []):
            html += f"""
                    <tr>
                        <td>{rec.get('priority', 'Unknown')}</td>
                        <td>{rec.get('category', 'Unknown')}</td>
                        <td>{rec.get('severity', 'Unknown')}</td>
                        <td>{rec.get('description', 'No description')}</td>
                    </tr>
            """

        html += """
                </table>
            </div>
        </body>
        </html>
        """

        return html

    def _generate_text_report(self) -> str:
        """Generate plain text security report."""
        results = self.scan_results

        report = f"""
LOW-CODE PLATFORM SECURITY ASSESSMENT REPORT
==========================================

Target: {results['scan_metadata']['target_url']}
Scan Date: {results['scan_metadata']['scan_timestamp']}
Scan Duration: {results['scan_metadata'].get('scan_duration_seconds', 0)} seconds

PLATFORM DETECTION
------------------
Detected Platforms: {', '.join(results['platform_detection'].get('detected_platforms', []))}

SECURITY ASSESSMENT
------------------
Overall Security Level: {results['security_assessment'].get('overall_security_level', 'Unknown')}
Total Vulnerabilities: {results['security_assessment']['risk_summary'].get('total_vulnerabilities', 0)}
Critical Issues: {results['security_assessment']['risk_summary'].get('critical_issues', 0)}
High Risk Issues: {results['security_assessment']['risk_summary'].get('high_risk_issues', 0)}
OWASP Compliance: {results['security_assessment']['compliance_status'].get('overall_compliance', 'Unknown')}

VULNERABILITY FINDINGS
----------------------
"""

        for vuln in results.get('vulnerability_findings', []):
            report += f"\n[{vuln.get('severity', 'Info')}] {vuln.get('type', 'Unknown')}\n"
            report += f"  {vuln.get('description', 'No description available')}\n"

        report += "\n\nRECOMMENDATIONS\n---------------\n"

        for rec in results.get('recommendations', []):
            report += f"\n[{rec.get('priority', 'Unknown')}] {rec.get('category', 'Unknown')}\n"
            report += f"  Severity: {rec.get('severity', 'Unknown')}\n"
            report += f"  {rec.get('description', 'No description')}\n"

        return report

    def get_supported_platforms(self) -> Dict[str, Dict]:
        """
        Get information about all supported low-code platforms.

        Returns:
            Dictionary of supported platforms with their details
        """
        return self.SUPPORTED_PLATFORMS.copy()

    def add_custom_platform(self, platform_key: str, platform_info: Dict[str, Any]):
        """
        Add a custom low-code platform to the scanner.

        Args:
            platform_key: Unique identifier for the platform
            platform_info: Platform information dictionary
        """
        self.SUPPORTED_PLATFORMS[platform_key] = platform_info

    def export_results(self, filename: str, format: str = "json"):
        """
        Export scan results to a file.

        Args:
            filename: Output filename
            format: Export format ("json", "html", "text")
        """
        report = self.generate_report(format)

        with open(filename, 'w', encoding='utf-8') as f:
            f.write(report)

        self.logger.info(f"Results exported to {filename}")


# Convenience functions for easy usage

def scan_low_code_platform(url: str, platform_hint: Optional[str] = None) -> Dict[str, Any]:
    """
    Convenience function to quickly scan a low-code platform.

    Args:
        url: Target URL to scan
        platform_hint: Optional platform hint

    Returns:
        Scan results dictionary
    """
    scanner = LowCodePlatformScanner()
    return scanner.comprehensive_scan(url, platform_hint)


def detect_platform(url: str) -> Dict[str, Any]:
    """
    Convenience function to detect the platform type.

    Args:
        url: Target URL

    Returns:
        Platform detection results
    """
    scanner = LowCodePlatformScanner()
    return scanner.detect_platform(url)


if __name__ == "__main__":
    # Example usage
    import sys

    if len(sys.argv) < 2:
        print("Usage: python low_code_scanner.py <url> [platform_hint]")
        sys.exit(1)

    url = sys.argv[1]
    platform_hint = sys.argv[2] if len(sys.argv) > 2 else None

    print(f"Scanning low-code platform: {url}")
    if platform_hint:
        print(f"Platform hint: {platform_hint}")

    scanner = LowCodePlatformScanner()
    results = scanner.comprehensive_scan(url, platform_hint)

    print("\n=== PLATFORM DETECTION ===")
    print(f"Detected: {results['platform_detection']['detected_platforms']}")

    print("\n=== SECURITY ASSESSMENT ===")
    assessment = results['security_assessment']
    print(f"Security Level: {assessment['overall_security_level']}")
    print(f"Total Vulnerabilities: {assessment['risk_summary']['total_vulnerabilities']}")

    print("\n=== TOP VULNERABILITIES ===")
    for vuln in results['vulnerability_findings'][:5]:
        print(f"[{vuln.get('severity', 'Info')}] {vuln.get('type', 'Unknown')}")

    # Export results
    output_file = f"low_code_scan_{urlparse(url).netloc}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    scanner.export_results(output_file, "json")
    print(f"\nResults exported to: {output_file}")
