#!/usr/bin/env python3
"""
Advanced Security Analyzers Module
Low-Code Platform Security Scanner

This module contains specialized analyzers for different low-code platforms
and security vulnerability detection methods.

Author: Bachelor Thesis Project - Low-Code Platforms Security Analysis
"""

import base64
import hashlib
import json
import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup


class BaseAnalyzer:
    """Base class for all security analyzers"""

    def __init__(self, session: requests.Session):
        self.session = session
        self.vulnerabilities = []
        self.findings = {}

    def analyze(
        self, url: str, response: requests.Response, soup: BeautifulSoup
    ) -> Dict[str, Any]:
        """Base analyze method to be overridden by subclasses"""
        raise NotImplementedError("Subclasses must implement analyze method")

    def add_vulnerability(
        self,
        vuln_type: str,
        severity: str,
        description: str,
        evidence: str = "",
        recommendation: str = "",
    ):
        """Add a vulnerability to the findings"""
        vulnerability = {
            "type": vuln_type,
            "severity": severity,
            "description": description,
            "evidence": evidence,
            "recommendation": recommendation,
        }
        self.vulnerabilities.append(vulnerability)


class BubbleAnalyzer(BaseAnalyzer):
    """Specialized analyzer for Bubble.io applications"""

    def __init__(self, session: requests.Session):
        super().__init__(session)
        self.api_endpoints = []
        self.workflow_patterns = []
        self.database_schemas = []
        self.privacy_rules = []

    def analyze(
        self, url: str, response: requests.Response, soup: BeautifulSoup
    ) -> Dict[str, Any]:
        """Comprehensive Bubble.io security analysis"""

        # Extract JavaScript content for analysis
        js_content = self._extract_javascript(soup)

        # Analyze API endpoints
        self._analyze_api_endpoints(js_content)

        # Check for workflow exposure
        self._analyze_workflows(js_content)

        # Check for database schema exposure
        self._analyze_database_exposure(js_content)

        # Check for privacy rules implementation
        self._analyze_privacy_rules(js_content)

        # Check for authentication vulnerabilities
        self._analyze_authentication(url, response, soup)

        # Check for client-side data exposure
        self._analyze_client_side_data(js_content)

        # Analyze form security
        self._analyze_forms(soup)

        return {
            "api_endpoints": self.api_endpoints,
            "workflow_patterns": self.workflow_patterns,
            "database_schemas": self.database_schemas,
            "privacy_rules": self.privacy_rules,
            "vulnerabilities": self.vulnerabilities,
            "bubble_specific_findings": self.findings,
        }

    def _extract_javascript(self, soup: BeautifulSoup) -> str:
        """Extract all JavaScript content from the page"""
        js_content = ""

        # Extract inline scripts
        for script in soup.find_all("script"):
            if script.string:
                js_content += script.string + "\n"

        # Extract external scripts (attempt to fetch)
        for script in soup.find_all("script", src=True):
            try:
                script_url = urljoin(soup.base.get("href", ""), script["src"])
                script_response = self.session.get(script_url, timeout=5)
                if script_response.status_code == 200:
                    js_content += script_response.text + "\n"
            except Exception:
                pass  # Skip if unable to fetch external script

        return js_content

    def _analyze_api_endpoints(self, js_content: str):
        """Analyze Bubble API endpoints for security issues"""

        # Bubble API patterns
        api_patterns = [
            r'api/1\.1/wf/([^"\']+)',  # Workflow APIs
            r'api/1\.1/obj/([^"\']+)',  # Object APIs
            r'version-test/api/([^"\']+)',  # Version test APIs
        ]

        for pattern in api_patterns:
            matches = re.findall(pattern, js_content, re.IGNORECASE)
            for match in matches:
                endpoint = f"api/{match}"
                self.api_endpoints.append(endpoint)

                # Check if endpoint is exposed without authentication
                if self._check_unauthenticated_access(endpoint):
                    self.add_vulnerability(
                        "Bubble API Exposure",
                        "High",
                        f"Unauthenticated access to API endpoint: {endpoint}",
                        endpoint,
                        "Implement proper authentication and privacy rules",
                    )

    def _analyze_workflows(self, js_content: str):
        """Analyze Bubble workflows for security vulnerabilities"""

        workflow_patterns = [
            r"workflow_([a-zA-Z0-9_]+)",
            r'Workflow\s*:\s*"([^"]+)"',
            r'run_workflow\([^)]*"([^"]+)"',
        ]

        for pattern in workflow_patterns:
            matches = re.findall(pattern, js_content, re.IGNORECASE)
            for match in matches:
                self.workflow_patterns.append(match)

                # Check for sensitive workflow names
                if any(
                    sensitive in match.lower()
                    for sensitive in ["admin", "delete", "payment", "auth", "login"]
                ):
                    self.add_vulnerability(
                        "Sensitive Workflow Exposure",
                        "High",
                        f"Potentially sensitive workflow exposed: {match}",
                        match,
                        "Review workflow privacy settings and access controls",
                    )

    def _analyze_database_exposure(self, js_content: str):
        """Check for database schema and data exposure"""

        # Look for Thing definitions (Bubble's data structure)
        thing_patterns = [
            r"Thing\s*:\s*{([^}]+)}",
            r"_thing\s*=\s*{([^}]+)}",
            r"database_schema\s*[=:]\s*{([^}]+)}",
        ]

        for pattern in thing_patterns:
            matches = re.findall(pattern, js_content, re.MULTILINE | re.DOTALL)
            for match in matches:
                self.database_schemas.append(match)

                # Check for sensitive field exposure
                if any(
                    field in match.lower()
                    for field in ["password", "ssn", "credit_card", "api_key", "token"]
                ):
                    self.add_vulnerability(
                        "Sensitive Data Schema Exposure",
                        "Critical",
                        "Database schema with sensitive fields exposed in client code",
                        match[:200] + "..." if len(match) > 200 else match,
                        "Remove sensitive field definitions from client-side code",
                    )

    def _analyze_privacy_rules(self, js_content: str):
        """Analyze privacy rules implementation"""

        privacy_patterns = [
            r"privacy_rules?\s*[=:]\s*([^;]+)",
            r"can_view\s*[=:]\s*([^;]+)",
            r"can_edit\s*[=:]\s*([^;]+)",
        ]

        privacy_rule_count = 0
        for pattern in privacy_patterns:
            matches = re.findall(pattern, js_content, re.IGNORECASE)
            privacy_rule_count += len(matches)
            self.privacy_rules.extend(matches)

        if privacy_rule_count == 0:
            self.add_vulnerability(
                "Missing Privacy Rules",
                "High",
                "No privacy rules detected in client-side code",
                "No privacy rule patterns found",
                "Implement comprehensive privacy rules for data protection",
            )

    def _analyze_authentication(
        self, url: str, response: requests.Response, soup: BeautifulSoup
    ):
        """Analyze authentication mechanisms"""

        # Check for authentication tokens in JavaScript
        js_content = self._extract_javascript(soup)

        token_patterns = [
            r'token["\']?\s*[:=]\s*["\']([^"\']+)["\']',
            r'auth["\']?\s*[:=]\s*["\']([^"\']+)["\']',
            r'session["\']?\s*[:=]\s*["\']([^"\']+)["\']',
        ]

        for pattern in token_patterns:
            matches = re.findall(pattern, js_content, re.IGNORECASE)
            for match in matches:
                if len(match) > 10:  # Likely a real token
                    self.add_vulnerability(
                        "Authentication Token Exposure",
                        "Critical",
                        "Authentication token exposed in client-side code",
                        f"Token: {match[:10]}...",
                        "Store authentication tokens securely, not in client-side code",
                    )

    def _analyze_client_side_data(self, js_content: str):
        """Analyze client-side data exposure"""

        # Look for hardcoded sensitive data
        sensitive_patterns = [
            (r'api[_-]?key["\']?\s*[:=]\s*["\']([^"\']+)', "API Key"),
            (r'secret["\']?\s*[:=]\s*["\']([^"\']+)', "Secret"),
            (r'password["\']?\s*[:=]\s*["\']([^"\']+)', "Password"),
            (r'private[_-]?key["\']?\s*[:=]\s*["\']([^"\']+)', "Private Key"),
        ]

        for pattern, data_type in sensitive_patterns:
            matches = re.findall(pattern, js_content, re.IGNORECASE)
            for match in matches:
                if len(match) > 5:  # Skip obviously fake/placeholder values
                    self.add_vulnerability(
                        f"{data_type} Exposure",
                        "Critical",
                        f"{data_type} found in client-side code",
                        f"{data_type}: {match[:10]}...",
                        f"Remove {data_type.lower()} from client-side code and use server-side handling",
                    )

    def _analyze_forms(self, soup: BeautifulSoup):
        """Analyze forms for security issues"""

        forms = soup.find_all("form")
        for form in forms:
            form_action = form.get("action", "")
            form_method = form.get("method", "GET").upper()

            # Check for CSRF protection
            csrf_token = form.find("input", {"name": re.compile(r"csrf|_token", re.I)})
            if not csrf_token and form_method == "POST":
                self.add_vulnerability(
                    "Missing CSRF Protection",
                    "Medium",
                    f"Form without CSRF protection: {form_action}",
                    f"Form action: {form_action}",
                    "Implement CSRF tokens for all forms",
                )

            # Check for password fields without proper attributes
            password_fields = form.find_all("input", {"type": "password"})
            for pwd_field in password_fields:
                if not pwd_field.get("autocomplete"):
                    self.add_vulnerability(
                        "Missing Password Field Security",
                        "Low",
                        "Password field without autocomplete attribute",
                        f"Field name: {pwd_field.get('name', 'unnamed')}",
                        "Add appropriate autocomplete attributes to password fields",
                    )

    def _check_unauthenticated_access(self, endpoint: str) -> bool:
        """Check if an API endpoint allows unauthenticated access"""
        try:
            # Attempt to access the endpoint without authentication
            test_response = self.session.get(endpoint, timeout=5)
            # If we get a 200 response, it might be accessible without auth
            return test_response.status_code == 200
        except Exception:
            return False


class OutSystemsAnalyzer(BaseAnalyzer):
    """Specialized analyzer for OutSystems applications"""

    def __init__(self, session: requests.Session):
        super().__init__(session)
        self.rest_apis = []
        self.screen_actions = []
        self.entities = []

    def analyze(
        self, url: str, response: requests.Response, soup: BeautifulSoup
    ) -> Dict[str, Any]:
        """Comprehensive OutSystems security analysis"""

        js_content = self._extract_javascript(soup)

        # Analyze REST APIs
        self._analyze_rest_apis(js_content)

        # Analyze screen actions
        self._analyze_screen_actions(js_content)

        # Check for entity exposure
        self._analyze_entities(js_content)

        # Check session management
        self._analyze_session_management(js_content)

        # Analyze role-based access
        self._analyze_roles(js_content)

        return {
            "rest_apis": self.rest_apis,
            "screen_actions": self.screen_actions,
            "entities": self.entities,
            "vulnerabilities": self.vulnerabilities,
            "outsystems_specific_findings": self.findings,
        }

    def _extract_javascript(self, soup: BeautifulSoup) -> str:
        """Extract JavaScript content for analysis"""
        js_content = ""

        for script in soup.find_all("script"):
            if script.string:
                js_content += script.string + "\n"

        return js_content

    def _analyze_rest_apis(self, js_content: str):
        """Analyze OutSystems REST API exposure"""

        rest_patterns = [
            r'/rest/([^"\'?\s]+)',
            r'RestService_([^"\'?\s]+)',
            r'CallRestAPI\([^)]*["\']([^"\']+)["\']',
        ]

        for pattern in rest_patterns:
            matches = re.findall(pattern, js_content, re.IGNORECASE)
            for match in matches:
                self.rest_apis.append(match)

                # Check for sensitive API names
                if any(
                    sensitive in match.lower()
                    for sensitive in ["admin", "internal", "private", "secret"]
                ):
                    self.add_vulnerability(
                        "Sensitive REST API Exposure",
                        "High",
                        f"Potentially sensitive REST API exposed: {match}",
                        match,
                        "Review API permissions and authentication requirements",
                    )

    def _analyze_screen_actions(self, js_content: str):
        """Analyze OutSystems screen actions"""

        action_patterns = [
            r'ScreenAction_([^"\'()\s]+)',
            r'OnClick["\']?\s*[:=]\s*["\']?([^"\';\s]+)',
            r'ServerAction_([^"\'()\s]+)',
        ]

        for pattern in action_patterns:
            matches = re.findall(pattern, js_content, re.IGNORECASE)
            for match in matches:
                self.screen_actions.append(match)

                # Check for privileged actions
                if any(
                    priv in match.lower()
                    for priv in ["delete", "admin", "elevate", "privilege"]
                ):
                    self.add_vulnerability(
                        "Privileged Action Exposure",
                        "Medium",
                        f"Privileged screen action found: {match}",
                        match,
                        "Ensure proper authorization checks for privileged actions",
                    )

    def _analyze_entities(self, js_content: str):
        """Check for OutSystems entity exposure"""

        entity_patterns = [
            r'Entity["\']?\s*[:=]\s*["\']([^"\']+)',
            r'GetEntity\([^)]*["\']([^"\']+)',
            r"entity_([a-zA-Z0-9_]+)",
        ]

        for pattern in entity_patterns:
            matches = re.findall(pattern, js_content, re.IGNORECASE)
            for match in matches:
                self.entities.append(match)

                # Check for sensitive entity names
                if any(
                    sensitive in match.lower()
                    for sensitive in ["user", "account", "payment", "personal"]
                ):
                    self.add_vulnerability(
                        "Sensitive Entity Exposure",
                        "Medium",
                        f"Sensitive entity structure exposed: {match}",
                        match,
                        "Review entity permissions and data access rules",
                    )

    def _analyze_session_management(self, js_content: str):
        """Analyze session management implementation"""

        session_patterns = [
            r'session[_-]?id["\']?\s*[:=]\s*["\']([^"\']+)',
            r"GetUserId\(\)",
            r'session["\']?\s*[:=]\s*["\']([^"\']+)',
        ]

        session_found = False
        for pattern in session_patterns:
            matches = re.findall(pattern, js_content, re.IGNORECASE)
            if matches:
                session_found = True
                break

        if not session_found:
            self.add_vulnerability(
                "Session Management Issues",
                "Medium",
                "No clear session management implementation found",
                "No session patterns detected",
                "Implement secure session management with proper timeout and validation",
            )

    def _analyze_roles(self, js_content: str):
        """Analyze role-based access control"""

        role_patterns = [
            r'CheckRole\([^)]*["\']([^"\']+)',
            r'UserHasRole\([^)]*["\']([^"\']+)',
            r'role["\']?\s*[:=]\s*["\']([^"\']+)',
        ]

        roles_found = 0
        for pattern in role_patterns:
            matches = re.findall(pattern, js_content, re.IGNORECASE)
            roles_found += len(matches)

        if roles_found == 0:
            self.add_vulnerability(
                "Missing Role-Based Access Control",
                "High",
                "No role-based access control implementation detected",
                "No RBAC patterns found",
                "Implement proper role-based access control for sensitive operations",
            )


class AirtableAnalyzer(BaseAnalyzer):
    """Specialized analyzer for Airtable applications"""

    def __init__(self, session: requests.Session):
        super().__init__(session)
        self.base_ids = []
        self.api_keys = []
        self.table_ids = []

    def analyze(
        self, url: str, response: requests.Response, soup: BeautifulSoup
    ) -> Dict[str, Any]:
        """Comprehensive Airtable security analysis"""

        js_content = self._extract_javascript(soup)
        html_content = str(soup)

        # Analyze base ID exposure
        self._analyze_base_ids(js_content + html_content)

        # Check for API key exposure
        self._analyze_api_keys(js_content + html_content)

        # Analyze table structure exposure
        self._analyze_tables(js_content + html_content)

        # Check permissions and sharing settings
        self._analyze_permissions(js_content)

        return {
            "base_ids": self.base_ids,
            "api_keys": self.api_keys,
            "table_ids": self.table_ids,
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

    def _analyze_base_ids(self, content: str):
        """Check for Airtable base ID exposure"""

        # Airtable base IDs follow pattern: app[14 characters]
        base_pattern = r"app[A-Za-z0-9]{14}"
        matches = re.findall(base_pattern, content)

        for match in matches:
            if match not in self.base_ids:
                self.base_ids.append(match)

                self.add_vulnerability(
                    "Airtable Base ID Exposure",
                    "Medium",
                    f"Airtable base ID exposed in client code: {match}",
                    match,
                    "Avoid exposing base IDs in client-side code; use server-side proxies",
                )

    def _analyze_api_keys(self, content: str):
        """Check for Airtable API key exposure"""

        # Airtable API keys follow pattern: key[14 characters]
        key_pattern = r"key[A-Za-z0-9]{14}"
        matches = re.findall(key_pattern, content)

        for match in matches:
            if match not in self.api_keys:
                self.api_keys.append(match)

                self.add_vulnerability(
                    "Airtable API Key Exposure",
                    "Critical",
                    f"Airtable API key exposed in client code: {match}",
                    f"API Key: {match}",
                    "Never expose API keys in client-side code; use server-side authentication",
                )

    def _analyze_tables(self, content: str):
        """Analyze table structure exposure"""

        # Airtable table IDs follow pattern: tbl[14 characters]
        table_pattern = r"tbl[A-Za-z0-9]{14}"
        matches = re.findall(table_pattern, content)

        for match in matches:
            if match not in self.table_ids:
                self.table_ids.append(match)

        # Check for table schema information
        schema_patterns = [
            r"fields?\s*[:=]\s*\[[^\]]+\]",
            r"column[s]?\s*[:=]\s*\[[^\]]+\]",
            r"schema\s*[:=]\s*{[^}]+}",
        ]

        for pattern in schema_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE | re.MULTILINE)
            if matches:
                self.add_vulnerability(
                    "Table Schema Exposure",
                    "Low",
                    "Table schema information exposed in client code",
                    f"Schema patterns found: {len(matches)}",
                    "Minimize schema information exposure in client-side code",
                )
                break

    def _analyze_permissions(self, js_content: str):
        """Analyze Airtable permissions and access controls"""

        permission_patterns = [
            r'permission[s]?\s*[:=]\s*["\']([^"\']+)',
            r'access[_-]?level\s*[:=]\s*["\']([^"\']+)',
            r'share[d]?\s*[:=]\s*["\']([^"\']+)',
        ]

        permissions_found = False
        for pattern in permission_patterns:
            matches = re.findall(pattern, js_content, re.IGNORECASE)
            if matches:
                permissions_found = True
                # Check for overly permissive settings
                for match in matches:
                    if any(
                        perm in match.lower() for perm in ["public", "anyone", "edit"]
                    ):
                        self.add_vulnerability(
                            "Permissive Access Control",
                            "Medium",
                            f"Potentially permissive access setting: {match}",
                            match,
                            "Review and restrict access permissions as needed",
                        )

        if not permissions_found:
            self.add_vulnerability(
                "Unknown Permission Model",
                "Low",
                "Could not determine permission/access control implementation",
                "No permission patterns detected",
                "Ensure proper access controls are implemented and documented",
            )


class GenericWebAnalyzer(BaseAnalyzer):
    """Generic web application security analyzer"""

    def __init__(self, session: requests.Session):
        super().__init__(session)

    def analyze(
        self, url: str, response: requests.Response, soup: BeautifulSoup
    ) -> Dict[str, Any]:
        """Generic web application security analysis"""

        # Analyze forms for common issues
        self._analyze_forms(soup)

        # Check for common vulnerabilities
        self._analyze_common_vulns(response, soup)

        # Analyze JavaScript for sensitive data
        self._analyze_javascript_security(soup)

        # Check external resources
        self._analyze_external_resources(soup, url)

        return {
            "vulnerabilities": self.vulnerabilities,
            "generic_findings": self.findings,
        }

    def _analyze_forms(self, soup: BeautifulSoup):
        """Analyze forms for security issues"""

        forms = soup.find_all("form")
        for form in forms:
            method = form.get("method", "GET").upper()
            action = form.get("action", "")

            # Check for password fields sent over GET
            if method == "GET":
                password_fields = form.find_all("input", {"type": "password"})
                if password_fields:
                    self.add_vulnerability(
                        "Password Field in GET Form",
                        "High",
                        "Password field found in form using GET method",
                        f"Form action: {action}",
                        "Use POST method for forms containing sensitive data",
                    )

            # Check for forms without CSRF protection
            csrf_field = form.find("input", {"name": re.compile(r"csrf|_token", re.I)})
            if not csrf_field and method == "POST":
                self.add_vulnerability(
                    "Missing CSRF Protection",
                    "Medium",
                    f"POST form without CSRF token: {action}",
                    f"Form action: {action}",
                    "Implement CSRF protection for all state-changing forms",
                )

    def _analyze_common_vulns(self, response: requests.Response, soup: BeautifulSoup):
        """Check for common web vulnerabilities"""

        content = response.text.lower()

        # Check for potential XSS vulnerabilities
        xss_indicators = [
            r"<script[^>]*>.*?document\.write.*?</script>",
            r"<script[^>]*>.*?innerHTML.*?</script>",
            r"eval\s*\([^)]*\)",
            r'setTimeout\s*\([^)]*[\'"][^\'"]*[\'"]\s*[^)]*\)',
        ]

        for pattern in xss_indicators:
            if re.search(pattern, content, re.IGNORECASE | re.DOTALL):
                self.add_vulnerability(
                    "Potential XSS Vulnerability",
                    "High",
                    "Code patterns that might be vulnerable to XSS found",
                    "Dynamic content manipulation detected",
                    "Validate and sanitize all user inputs and use safe DOM manipulation",
                )
                break

        # Check for SQL injection indicators
        sql_indicators = [
            r'sql\s*=\s*[\'"][^\'"]*\+',
            r'query\s*=\s*[\'"][^\'"]*\+',
            r'select\s+[*\w]+\s+from\s+\w+\s+where\s+[^\'"]*\+',
        ]

        for pattern in sql_indicators:
            if re.search(pattern, content, re.IGNORECASE):
                self.add_vulnerability(
                    "Potential SQL Injection",
                    "Critical",
                    "Code patterns suggesting SQL injection vulnerability",
                    "Dynamic SQL construction detected",
                    "Use parameterized queries and input validation",
                )
                break

    def _analyze_javascript_security(self, soup: BeautifulSoup):
        """Analyze JavaScript for security issues"""

        scripts = soup.find_all("script")
        for script in scripts:
            if script.string:
                content = script.string

                # Check for hardcoded secrets
                secret_patterns = [
                    (r'password\s*[=:]\s*[\'"]([^\'"]+)[\'"]', "Password"),
                    (r'secret\s*[=:]\s*[\'"]([^\'"]+)[\'"]', "Secret"),
                    (r'token\s*[=:]\s*[\'"]([^\'"]+)[\'"]', "Token"),
                    (r'api[_-]?key\s*[=:]\s*[\'"]([^\'"]+)[\'"]', "API Key"),
                ]

                for pattern, secret_type in secret_patterns:
                    matches = re.findall(pattern, content, re.IGNORECASE)
                    for match in matches:
                        if len(match) > 5:  # Skip short/placeholder values
                            self.add_vulnerability(
                                f"Hardcoded {secret_type}",
                                "Critical",
                                f"{secret_type} hardcoded in JavaScript",
                                f"{secret_type}: {match[:10]}...",
                                f"Remove {secret_type.lower()} from client-side code",
                            )

    def _analyze_external_resources(self, soup: BeautifulSoup, base_url: str):
        """Analyze external resources for security issues"""

        parsed_base = urlparse(base_url)
        base_scheme = parsed_base.scheme

        # Check for mixed content
        if base_scheme == "https":
            http_resources = soup.find_all(
                ["img", "script", "link", "iframe"], src=re.compile(r"^http://", re.I)
            )

            if http_resources:
                self.add_vulnerability(
                    "Mixed Content",
                    "Medium",
                    f"Found {len(http_resources)} HTTP resources on HTTPS page",
                    f"{len(http_resources)} insecure resources",
                    "Serve all resources over HTTPS to prevent mixed content issues",
                )

        # Check for external JavaScript from untrusted domains
        external_scripts = soup.find_all("script", src=True)
        untrusted_domains = []

        for script in external_scripts:
            src = script.get("src", "")
            parsed_src = urlparse(src)

            if parsed_src.netloc and parsed_src.netloc != parsed_base.netloc:
                # Check against known CDN domains (simplified check)
                trusted_domains = [
                    "cdnjs.cloudflare.com",
                    "ajax.googleapis.com",
                    "code.jquery.com",
                    "unpkg.com",
                    "jsdelivr.net",
                ]

                if not any(trusted in parsed_src.netloc for trusted in trusted_domains):
                    untrusted_domains.append(parsed_src.netloc)

        if untrusted_domains:
            self.add_vulnerability(
                "External JavaScript from Untrusted Sources",
                "Medium",
                f"External scripts loaded from potentially untrusted domains: {', '.join(set(untrusted_domains))}",
                f"Domains: {', '.join(set(untrusted_domains))}",
                "Review external script sources and implement Content Security Policy",
            )


class SecurityReportGenerator:
    """Generate comprehensive security reports"""

    def __init__(self):
        self.vulnerability_weights = {"Critical": 10, "High": 7, "Medium": 4, "Low": 1}

    def calculate_security_score(
        self, vulnerabilities: List[Dict[str, Any]]
    ) -> Tuple[int, Dict[str, int]]:
        """Calculate overall security score based on vulnerabilities"""
        score = 100
        severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}

        for vuln in vulnerabilities:
            severity = vuln.get("severity", "Low")
            severity_counts[severity] += 1
            score -= self.vulnerability_weights.get(severity, 1)

        return max(0, score), severity_counts

    def generate_executive_summary(
        self, analysis_results: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Generate executive summary of security findings"""
        vulnerabilities = analysis_results.get("vulnerabilities", [])
        score, severity_counts = self.calculate_security_score(vulnerabilities)

        total_vulns = sum(severity_counts.values())
        risk_level = "Low"

        if severity_counts["Critical"] > 0:
            risk_level = "Critical"
        elif severity_counts["High"] > 0:
            risk_level = "High"
        elif severity_counts["Medium"] > 2:
            risk_level = "Medium"

        return {
            "security_score": score,
            "risk_level": risk_level,
            "total_vulnerabilities": total_vulns,
            "severity_breakdown": severity_counts,
            "platform_type": analysis_results.get("platform_type", "Unknown"),
            "scan_timestamp": analysis_results.get("timestamp", "Unknown"),
        }

    def generate_recommendations_matrix(
        self, vulnerabilities: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Generate prioritized recommendations based on vulnerabilities"""
        recommendations = []

        # Group vulnerabilities by type
        vuln_groups = {}
        for vuln in vulnerabilities:
            vuln_type = vuln.get("type", "Unknown")
            if vuln_type not in vuln_groups:
                vuln_groups[vuln_type] = []
            vuln_groups[vuln_type].append(vuln)

        # Generate recommendations for each group
        for vuln_type, vulns in vuln_groups.items():
            highest_severity = max(
                vulns,
                key=lambda x: self.vulnerability_weights.get(
                    x.get("severity", "Low"), 1
                ),
            )

            recommendation = {
                "category": vuln_type,
                "priority": highest_severity.get("severity", "Low"),
                "count": len(vulns),
                "description": highest_severity.get(
                    "recommendation", "Review and remediate this vulnerability"
                ),
                "effort_estimate": self._estimate_effort(vuln_type, len(vulns)),
                "impact": self._assess_impact(highest_severity.get("severity", "Low")),
            }
            recommendations.append(recommendation)

        # Sort by priority (Critical > High > Medium > Low)
        priority_order = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
        recommendations.sort(
            key=lambda x: priority_order.get(x["priority"], 0), reverse=True
        )

        return recommendations

    def _estimate_effort(self, vuln_type: str, count: int) -> str:
        """Estimate remediation effort"""
        base_efforts = {
            "API Key Exposure": "High",
            "SQL Injection": "High",
            "XSS": "Medium",
            "Missing CSRF Protection": "Medium",
            "Security Headers": "Low",
            "SSL/TLS Issues": "Medium",
        }

        base_effort = base_efforts.get(vuln_type, "Medium")

        # Adjust based on count
        if count > 5:
            if base_effort == "Low":
                return "Medium"
            elif base_effort == "Medium":
                return "High"

        return base_effort

    def _assess_impact(self, severity: str) -> str:
        """Assess business impact of vulnerability"""
        impact_mapping = {
            "Critical": "Severe - Immediate data breach risk",
            "High": "High - Significant security risk",
            "Medium": "Medium - Moderate security concern",
            "Low": "Low - Minor security improvement",
        }
        return impact_mapping.get(severity, "Unknown impact")


def get_analyzer_for_platform(
    platform_type: str, session: requests.Session
) -> BaseAnalyzer:
    """Factory function to get appropriate analyzer for platform"""
    analyzers = {
        "bubble": BubbleAnalyzer,
        "outsystems": OutSystemsAnalyzer,
        "airtable": AirtableAnalyzer,
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
) -> Dict[str, Any]:
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
