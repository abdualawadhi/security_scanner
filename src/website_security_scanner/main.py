#!/usr/bin/env python3
"""
Low-Code Platform Security Scanner
Bachelor Thesis: Low-Code Platforms for E-commerce: Comparative Security Analysis

This tool analyzes security vulnerabilities in low-code platforms including:
- Bubble.io applications
- OutSystems applications
- Airtable databases

Author: Bachelor Thesis Project
"""

import concurrent.futures
import json
import os
import re
import socket
import ssl
import time
import warnings
import hashlib
import uuid
from datetime import datetime
from typing import List, Dict, Any
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup

from .analyzers import (
    AirtableAnalyzer,
    BubbleAnalyzer,
    GenericWebAnalyzer,
    OutSystemsAnalyzer,
    ShopifyAnalyzer,
    WebflowAnalyzer,
    WixAnalyzer,
    MendixAnalyzer,
    get_analyzer_for_platform,
    analyze_platform_security,
)
from .analyzers.reports import SecurityReportGenerator
from .report_generator import ProfessionalReportGenerator
from .result_transformer import transform_results_for_professional_report
from .utils.platform_detector import AdvancedPlatformDetector
from .utils.evidence_verifier import verify_vulnerabilities
from .utils.rate_limiter import RateLimiter, ThrottledSession
from .models.vulnerability import EnhancedVulnerability, ScanResult
from .plugins.plugin_manager import PluginManager
from .utils.parallel_scanner import ParallelScanner, create_parallel_scan
from .config.constants import DEFAULT_REQUEST_TIMEOUT, SEVERITY_LEVELS, CONFIDENCE_LEVELS
from .verifier import VulnerabilityVerifier


class LowCodeSecurityScanner:
    def __init__(
        self,
        enable_plugins: bool = True,
        enable_parallel: bool = True,
        verify_ssl: bool = True,
        timeout_seconds: int = DEFAULT_REQUEST_TIMEOUT,
        scan_depth: int = 1,
        fetch_external_js_assets: bool = True,
        max_external_js_assets: int = 8,
        allow_third_party_js: bool = False,
        max_js_bytes: int = 512 * 1024,
        active_verification: bool = True,
        evidence_verification: bool = True,
        min_interval_seconds: float = 0.2,
        max_requests_per_minute: int = 60,
    ):
        rate_limiter = RateLimiter(
            min_interval_seconds=min_interval_seconds,
            max_requests_per_minute=max_requests_per_minute,
        )
        self.session = ThrottledSession(rate_limiter)
        self.session.headers.update(
            {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
            }
        )
        self.session.default_timeout = int(timeout_seconds)
        # Configure SSL verification
        self.verify_ssl = verify_ssl
        if not verify_ssl:
            # Only suppress warnings for testing scenarios
            warnings.filterwarnings("ignore", message="Unverified HTTPS request")
        
        self.results = {}
        self.platform_detector = AdvancedPlatformDetector(self.session)
        self._last_platform_detection = {}
        
        # Advanced features
        self.enable_plugins = enable_plugins
        self.enable_parallel = enable_parallel

        # Reproducible scan profile metadata
        self.scan_profile = {
            "timeout_seconds": int(timeout_seconds),
            "verify_ssl": verify_ssl,
            "enable_plugins": enable_plugins,
            "enable_parallel": enable_parallel,
            "active_verification": bool(active_verification),
            "evidence_verification": bool(evidence_verification),
            "scan_depth": int(scan_depth),
            "fetch_external_js_assets": bool(fetch_external_js_assets),
            "max_external_js_assets": int(max_external_js_assets),
            "allow_third_party_js": bool(allow_third_party_js),
            "max_js_bytes": int(max_js_bytes),
            "min_interval_seconds": float(min_interval_seconds),
            "max_requests_per_minute": int(max_requests_per_minute),
        }
        
        if enable_plugins:
            self.plugin_manager = PluginManager()
        
        if enable_parallel:
            self.parallel_scanner = ParallelScanner()

    def scan_target(self, url):
        """Main scanning function for a target URL"""
        scan_id = f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:8]}"
        scan_profile_hash = hashlib.sha256(
            json.dumps(self.scan_profile, sort_keys=True).encode("utf-8")
        ).hexdigest()
        print(f"\n[+] Starting security scan for: {url}")

        target_results = {
            "scan_id": scan_id,
            "url": url,
            "timestamp": datetime.now().isoformat(),
            "platform_type": self.identify_platform(url),
            "vulnerabilities": [],
            "security_headers": {},
            "ssl_analysis": {},
            "information_disclosure": [],
            "authentication_issues": [],
            "authorization_issues": [],
            "data_exposure": [],
            "api_endpoints": [],
            "forms_analysis": [],
            "recommendations": [],
            "platform_detection": self._last_platform_detection or {},
            "scan_profile": self.scan_profile,
            "scan_profile_hash": scan_profile_hash,
            "dataset_version": os.environ.get("DATASET_VERSION", "N/A"),
            "git_commit": os.environ.get("GIT_COMMIT", "N/A"),
            "scan_warnings": [],
        }

        try:
            # Basic connectivity and platform identification
            response = self.session.get(
                url,
                timeout=self.scan_profile["timeout_seconds"],
                verify=self.verify_ssl,
            )
            target_results["status_code"] = response.status_code
            target_results["response_time"] = response.elapsed.total_seconds()

            # Security header analysis
            target_results["security_headers"] = self.analyze_security_headers(
                response.headers
            )

            # SSL/TLS analysis
            target_results["ssl_analysis"] = self.analyze_ssl(url)

            if not self._is_scannable_response(response):
                target_results["scan_warnings"].append({
                    "message": "Response not suitable for content analysis",
                    "status_code": response.status_code,
                    "content_type": response.headers.get("Content-Type", ""),
                })
                target_results["analysis_skipped"] = True
                target_results["verification_summary"] = {
                    "total_vulnerabilities": 0,
                    "verified_vulnerabilities": 0,
                    "high_confidence_verifications": 0,
                    "verification_rate": 0.0,
                    "disabled": True,
                }
                target_results["evidence_verification_summary"] = {
                    "total_vulnerabilities": 0,
                    "verified": 0,
                    "stale": 0,
                    "unverified": 0,
                    "failed": 0,
                    "live_checked": 0,
                    "verification_rate": 0.0,
                    "disabled": True,
                }
                report_generator = SecurityReportGenerator()
                target_results["executive_summary"] = report_generator.generate_executive_summary(
                    target_results
                )
                target_results["recommendations_matrix"] = report_generator.generate_recommendations_matrix([])
                return target_results

            # Content analysis based on platform type
            if target_results["platform_type"] == "bubble":
                target_results.update(self.analyze_bubble_app(url, response))
            elif target_results["platform_type"] == "outsystems":
                target_results.update(self.analyze_outsystems_app(url, response))
            elif target_results["platform_type"] == "airtable":
                target_results.update(self.analyze_airtable_app(url, response))
            elif target_results["platform_type"] == "shopify":
                target_results.update(self.analyze_shopify_app(url, response))
            elif target_results["platform_type"] == "webflow":
                target_results.update(self.analyze_webflow_app(url, response))
            elif target_results["platform_type"] == "wix":
                target_results.update(self.analyze_wix_app(url, response))
            elif target_results["platform_type"] == "mendix":
                target_results.update(self.analyze_mendix_app(url, response))
            else:
                target_results.update(self.analyze_generic_app(url, response))

            # Common vulnerability checks
            target_results["vulnerabilities"].extend(
                self.check_common_vulnerabilities(url, response)
            )

            # Normalize and verify vulnerabilities
            target_results["vulnerabilities"] = self._normalize_vulnerabilities(
                target_results.get("vulnerabilities", []), url
            )
            target_results["vulnerabilities"] = self._dedupe_vulnerabilities(
                target_results.get("vulnerabilities", [])
            )

            if self.scan_profile.get("active_verification", True):
                target_results["verification_summary"] = self._apply_active_verification(
                    target_results["vulnerabilities"]
                )
            else:
                target_results["verification_summary"] = {
                    "total_vulnerabilities": len(target_results["vulnerabilities"]),
                    "verified_vulnerabilities": 0,
                    "high_confidence_verifications": 0,
                    "verification_rate": 0.0,
                    "disabled": True,
                }

            if self.scan_profile.get("evidence_verification", True):
                try:
                    verified_vulns, evidence_summary = verify_vulnerabilities(
                        target_results["vulnerabilities"], self.session, url, response
                    )
                    target_results["vulnerabilities"] = verified_vulns
                    target_results["evidence_verification_summary"] = evidence_summary
                except Exception as exc:
                    target_results["scan_warnings"].append({
                        "message": "Evidence verification failed",
                        "error": str(exc),
                    })
                    target_results["evidence_verification_summary"] = {
                        "total_vulnerabilities": len(target_results["vulnerabilities"]),
                        "verified": 0,
                        "stale": 0,
                        "unverified": len(target_results["vulnerabilities"]),
                        "failed": len(target_results["vulnerabilities"]),
                        "live_checked": 0,
                        "verification_rate": 0.0,
                        "disabled": True,
                        "error": str(exc),
                    }
            else:
                target_results["evidence_verification_summary"] = {
                    "total_vulnerabilities": len(target_results["vulnerabilities"]),
                    "verified": 0,
                    "stale": 0,
                    "unverified": len(target_results["vulnerabilities"]),
                    "failed": 0,
                    "live_checked": 0,
                    "verification_rate": 0.0,
                    "disabled": True,
                }

            # Generate security recommendations
            target_results["recommendations"] = self.generate_recommendations(
                target_results
            )

            # Consistent executive summary and recommendations matrix
            report_generator = SecurityReportGenerator()
            target_results["executive_summary"] = report_generator.generate_executive_summary(
                target_results
            )
            target_results["recommendations_matrix"] = report_generator.generate_recommendations_matrix(
                target_results.get("vulnerabilities", [])
            )

        except requests.exceptions.RequestException as e:
            print(f"[-] Error scanning {url}: {e}")
            target_results["error"] = str(e)

        return target_results

    def enhanced_scan_target(self, url: str, use_plugins: bool = None, use_parallel: bool = None) -> ScanResult:
        """
        Enhanced scanning with plugins and parallel processing.
        
        Args:
            url: Target URL
            use_plugins: Whether to use plugins (default: instance setting)
            use_parallel: Whether to use parallel processing (default: instance setting)
            
        Returns:
            Enhanced scan result
        """
        use_plugins = use_plugins if use_plugins is not None else self.enable_plugins
        use_parallel = use_parallel if use_parallel is not None else self.enable_parallel
        
        print(f"\n[+] Starting enhanced security scan for: {url}")
        print(f"[+] Plugins: {'Enabled' if use_plugins else 'Disabled'}")
        print(f"[+] Parallel: {'Enabled' if use_parallel else 'Disabled'}")
        
        # Perform basic scan first
        basic_results = self.scan_target(url)
        
        # Convert to enhanced vulnerabilities
        enhanced_vulnerabilities = []
        for vuln in basic_results.get('vulnerabilities', []):
            enhanced_vuln = EnhancedVulnerability.from_basic_vulnerability(
                vuln, basic_results.get('platform_type', 'Unknown')
            )
            enhanced_vulnerabilities.append(enhanced_vuln)
        
        # Execute plugins if enabled
        plugin_results = {}
        if use_plugins and hasattr(self, 'plugin_manager'):
            print("[+] Executing plugins...")
            plugin_results = self.plugin_manager.execute_all_plugins(url, basic_results)
        
        # Create enhanced scan result
        scan_result = ScanResult(
            scan_id=f"enhanced_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            url=url,
            platform=basic_results.get('platform_type', 'Unknown'),
            timestamp=datetime.now().isoformat(),
            vulnerability_findings=enhanced_vulnerabilities,
            security_assessment={
                'risk_score': self._calculate_risk_score(enhanced_vulnerabilities),
                'severity_counts': self._get_severity_counts(enhanced_vulnerabilities),
                'platform_risks': self._assess_platform_risks(basic_results.get('platform_type', 'Unknown'))
            },
            compliance_summary=self._generate_compliance_summary(enhanced_vulnerabilities),
            scan_metadata={
                'scan_type': 'enhanced',
                'plugins_used': use_plugins,
                'parallel_used': use_parallel,
                'plugin_count': len(plugin_results) if plugin_results else 0
            },
            performance_metrics={
                'scan_duration': 0,  # Would be calculated in real implementation
                'vulnerability_count': len(enhanced_vulnerabilities),
                'plugin_results_count': len(plugin_results) if plugin_results else 0
            }
        )
        
        print(f"[+] Enhanced scan completed. Found {len(enhanced_vulnerabilities)} vulnerabilities")
        
        return scan_result
    
    def _calculate_risk_score(self, vulnerabilities: List[EnhancedVulnerability]) -> float:
        """Calculate overall risk score from vulnerabilities."""
        if not vulnerabilities:
            return 0.0
        
        total_cvss = sum(vuln.cvss_score for vuln in vulnerabilities)
        return total_cvss / len(vulnerabilities)
    
    def _get_severity_counts(self, vulnerabilities: List[EnhancedVulnerability]) -> Dict[str, int]:
        """Get vulnerability counts by severity."""
        counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'Info': 0}
        for vuln in vulnerabilities:
            if vuln.severity in counts:
                counts[vuln.severity] += 1
        return counts
    
    def _assess_platform_risks(self, platform: str) -> Dict[str, Any]:
        """Assess platform-specific risks."""
        platform_risks = {
            'bubble.io': {
                'common_issues': ['Workflow exposure', 'Privacy rules bypass', 'API key leakage'],
                'risk_level': 'Medium'
            },
            'outsystems': {
                'common_issues': ['REST API exposure', 'Screen action bypass', 'Entity leakage'],
                'risk_level': 'Medium'
            },
            'airtable.com': {
                'common_issues': ['Base ID exposure', 'API key exposure', 'Permission bypass'],
                'risk_level': 'Low'
            },
            'shopify': {
                'common_issues': ['Storefront token exposure', 'Public JSON endpoints'],
                'risk_level': 'Medium'
            },
            'webflow': {
                'common_issues': ['Public API endpoints', 'Form security gaps'],
                'risk_level': 'Low'
            },
            'wix': {
                'common_issues': ['Exposed API endpoints', 'Information disclosure'],
                'risk_level': 'Low'
            },
            'mendix': {
                'common_issues': ['Exposed REST endpoints', 'Access control issues'],
                'risk_level': 'Medium'
            },
            'generic': {
                'common_issues': ['Missing security headers', 'XSS', 'SQL Injection'],
                'risk_level': 'High'
            }
        }
        
        return platform_risks.get(platform, {'common_issues': [], 'risk_level': 'Unknown'})
    
    def _generate_compliance_summary(self, vulnerabilities: List[EnhancedVulnerability]) -> Dict[str, Any]:
        """Generate compliance framework summary."""
        compliance_coverage = {}
        total_vulns = len(vulnerabilities)
        
        frameworks = ['OWASP', 'NIST', 'ISO_27001', 'SOC2', 'PCI_DSS']
        for framework in frameworks:
            covered = sum(1 for vuln in vulnerabilities 
                        if vuln.compliance_mappings.get(framework))
            compliance_coverage[framework] = {
                'coverage_percentage': (covered / total_vulns * 100) if total_vulns > 0 else 0,
                'vulnerabilities_covered': covered,
                'total_vulnerabilities': total_vulns
            }
        
        return compliance_coverage

    def identify_platform(self, url):
        """Enhanced platform identification using advanced detection with confidence gating."""
        try:
            # Use advanced platform detection
            detection_result = self.platform_detector.detect_platform_advanced(url)
            self._last_platform_detection = detection_result
            
            # Apply confidence gating
            platform, confidence = self.platform_detector.get_primary_platform(detection_result)
            
            if platform and confidence >= self.platform_detector.MIN_CONFIDENCE_THRESHOLD:
                normalized = self._normalize_platform_type(platform)
                print(f"[+] Platform detected: {normalized} ({confidence}% confidence)")
                return normalized
            elif platform:
                print(f"[!] Platform detection uncertain: {platform} ({confidence}% confidence) - using generic scanner")
                return 'generic'
            else:
                # Fallback to basic detection
                return self._normalize_platform_type(self._basic_platform_identification(url))
                
        except Exception as e:
            print(f"[!] Platform detection failed: {e}")
            self._last_platform_detection = {"error": str(e), "detected_platforms": ["unknown"], "confidence_scores": {"unknown": 0}}
            return self._normalize_platform_type(self._basic_platform_identification(url))

    def _normalize_platform_type(self, platform: str) -> str:
        """Normalize detected platform names to scanner canonical labels."""
        if not platform:
            return "generic"
        platform_lower = platform.lower()
        alias_map = getattr(self.platform_detector, "platform_aliases", {}) or {}
        if platform_lower in alias_map:
            return alias_map[platform_lower]
        return platform_lower
    
    def _basic_platform_identification(self, url):
        """Fallback basic platform identification"""
        try:
            response = self.session.get(
                url,
                timeout=self.scan_profile.get("timeout_seconds", DEFAULT_REQUEST_TIMEOUT),
                verify=self.verify_ssl,
            )
            content = response.text.lower()
            
            if 'bubble.io' in content or '_bubble_page_' in content:
                return 'bubble'
            elif 'outsystems' in content or 'richwidgets' in content:
                return 'outsystems'
            elif 'airtable.com' in content or re.search(r'app[a-zA-Z0-9]{15}', content):
                return 'airtable'
            elif 'myshopify.com' in content or 'cdn.shopify.com' in content:
                return 'shopify'
            elif 'webflow' in content or 'data-wf-site' in content:
                return 'webflow'
            elif 'wixstatic.com' in content or 'parastorage.com' in content:
                return 'wix'
            elif 'mxclientsystem' in content or 'mendix' in content:
                return 'mendix'
            else:
                return 'generic'
        except:
            return 'generic'

    def _is_scannable_response(self, response: requests.Response) -> bool:
        if response is None:
            return False
        if response.status_code >= 400:
            return False
        content_type = response.headers.get("Content-Type", "").lower()
        if not content_type:
            return True
        return "text/html" in content_type or "application/xhtml+xml" in content_type

    def _normalize_severity(self, severity: str) -> str:
        if not severity:
            return "Info"
        sev_map = {k.lower(): k for k in SEVERITY_LEVELS.keys()}
        return sev_map.get(str(severity).lower(), "Info")

    def _normalize_confidence(self, confidence: str) -> str:
        if not confidence:
            return "Tentative"
        conf_map = {k.lower(): k for k in CONFIDENCE_LEVELS.keys()}
        return conf_map.get(str(confidence).lower(), "Tentative")

    def _normalize_vulnerabilities(self, vulnerabilities: List[Dict[str, Any]], url: str) -> List[Dict[str, Any]]:
        normalized: List[Dict[str, Any]] = []
        for vuln in vulnerabilities:
            v = vuln.copy() if isinstance(vuln, dict) else {"description": str(vuln)}
            v["type"] = v.get("type") or v.get("title") or "Unknown"
            v["severity"] = self._normalize_severity(v.get("severity", "Info"))
            v["confidence"] = self._normalize_confidence(v.get("confidence", "Tentative"))
            v.setdefault("description", "")
            v.setdefault("recommendation", "")
            v.setdefault("category", "General")
            v.setdefault("owasp", "N/A")
            v.setdefault("cwe", [])
            v.setdefault("url", url)
            v.setdefault("parameter", "")
            v.setdefault("timestamp", datetime.now().isoformat())
            if "evidence" not in v:
                v["evidence"] = ""
            if "verification" not in v or not isinstance(v.get("verification"), dict):
                v["verification"] = {
                    "verified": False,
                    "confidence": "tentative",
                    "method": "static_analysis",
                    "reason": "Not verified",
                }
            if "evidence_verification" not in v or not isinstance(v.get("evidence_verification"), dict):
                v["evidence_verification"] = {}
            normalized.append(v)
        return normalized

    def _dedupe_vulnerabilities(self, vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        deduped: List[Dict[str, Any]] = []
        seen = set()
        for vuln in vulnerabilities:
            key = self._make_vuln_key(vuln)
            if key in seen:
                continue
            seen.add(key)
            deduped.append(vuln)
        return deduped

    def _make_vuln_key(self, vuln: Dict[str, Any]) -> str:
        def _safe_json(value: Any) -> str:
            try:
                return json.dumps(value, sort_keys=True, default=str)
            except Exception:
                return str(value)

        evidence = vuln.get("evidence", "")
        if isinstance(evidence, list):
            evidence_key = [_safe_json(item) for item in evidence]
        else:
            evidence_key = _safe_json(evidence)

        return "|".join([
            str(vuln.get("type", "")),
            str(vuln.get("severity", "")),
            str(vuln.get("url", "")),
            str(vuln.get("parameter", "")),
            str(vuln.get("description", "")),
            _safe_json(evidence_key),
        ])

    def _summarize_verification(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, Any]:
        total = len(vulnerabilities)
        verified = 0
        high_confidence = 0
        for vuln in vulnerabilities:
            verification = vuln.get("verification", {}) or {}
            if verification.get("verified"):
                verified += 1
            conf = str(verification.get("confidence", "")).lower()
            if conf in {"high", "firm", "certain"}:
                high_confidence += 1
        rate = (verified / total * 100) if total else 0.0
        return {
            "total_vulnerabilities": total,
            "verified_vulnerabilities": verified,
            "high_confidence_verifications": high_confidence,
            "verification_rate": round(rate, 2),
        }

    def _apply_active_verification(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, Any]:
        verifier = VulnerabilityVerifier(self.session)
        if hasattr(verifier, "verification_timeout"):
            verifier.verification_timeout = self.scan_profile.get(
                "timeout_seconds", DEFAULT_REQUEST_TIMEOUT
            )
        for i, vuln in enumerate(vulnerabilities):
            verification = vuln.get("verification", {}) or {}
            if verification.get("method") not in {"static_analysis", "not_attempted", "pattern_match_only"}:
                continue
            result = verifier.verify_vulnerability(vuln)
            if isinstance(result, dict):
                result["confidence"] = self._normalize_confidence(result.get("confidence", vuln.get("confidence")))
                vulnerabilities[i]["verification"] = result
                if result.get("verified"):
                    vulnerabilities[i]["confidence"] = "Certain"
        return self._summarize_verification(vulnerabilities)

    def analyze_security_headers(self, headers):
        """Analyze HTTP security headers"""
        security_headers = {
            "X-Frame-Options": headers.get("X-Frame-Options", "Missing"),
            "X-XSS-Protection": headers.get("X-XSS-Protection", "Missing"),
            "X-Content-Type-Options": headers.get("X-Content-Type-Options", "Missing"),
            "Strict-Transport-Security": headers.get(
                "Strict-Transport-Security", "Missing"
            ),
            "Content-Security-Policy": headers.get(
                "Content-Security-Policy", "Missing"
            ),
            "Referrer-Policy": headers.get("Referrer-Policy", "Missing"),
            "Permissions-Policy": headers.get("Permissions-Policy", "Missing"),
            "X-Permitted-Cross-Domain-Policies": headers.get(
                "X-Permitted-Cross-Domain-Policies", "Missing"
            ),
        }

        # Evaluate security header quality
        security_score = 0
        for header, value in security_headers.items():
            if value != "Missing":
                security_score += 1

        security_headers["security_score"] = f"{security_score}/8"
        return security_headers

    def analyze_ssl(self, url):
        """Analyze SSL/TLS configuration"""
        ssl_info = {}

        try:
            parsed_url = urlparse(url)
            hostname = parsed_url.hostname
            port = parsed_url.port or (443 if parsed_url.scheme == "https" else 80)

            if parsed_url.scheme == "https":
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE

                with socket.create_connection((hostname, port), timeout=10) as sock:
                    with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                        cert = ssock.getpeercert()
                        ssl_info = {
                            "version": ssock.version(),
                            "cipher": ssock.cipher(),
                            "certificate_subject": cert.get("subject", []),
                            "certificate_issuer": cert.get("issuer", []),
                            "certificate_expiry": cert.get("notAfter", "Unknown"),
                            "certificate_san": cert.get("subjectAltName", []),
                        }
            else:
                ssl_info["error"] = "Not using HTTPS"

        except Exception as e:
            ssl_info["error"] = str(e)

        return ssl_info

    def analyze_bubble_app(self, url, response):
        """Specific analysis for Bubble.io applications with evidence verification."""
        print("[+] Analyzing Bubble.io application using BubbleAnalyzer...")
        soup = BeautifulSoup(response.content, "html.parser")
        analyzer = BubbleAnalyzer(self.session)
        self._apply_scan_profile_to_analyzer(analyzer)
        results = analyzer.analyze(url, response, soup)
        
        # Map BubbleAnalyzer findings to the format expected by scanner
        return {
            "bubble_specific": {
                "api_endpoints_found": results.get("api_endpoints", []),
                "workflow_exposure": results.get("workflow_patterns", []),
                "database_exposure": results.get("database_schemas", []),
                "privacy_rules": results.get("privacy_rules", []),
            },
            "vulnerabilities": results.get("vulnerabilities", []),
            "scan_warnings": getattr(analyzer, "scan_warnings", []),
        }

    def analyze_outsystems_app(self, url, response):
        """Specific analysis for OutSystems applications with evidence verification."""
        print("[+] Analyzing OutSystems application using OutSystemsAnalyzer...")
        soup = BeautifulSoup(response.content, "html.parser")
        analyzer = OutSystemsAnalyzer(self.session)
        self._apply_scan_profile_to_analyzer(analyzer)
        results = analyzer.analyze(url, response, soup)

        return {
            "outsystems_specific": {
                "rest_apis_found": results.get("rest_apis", []),
                "screen_actions_found": results.get("screen_actions", []),
                "entities": results.get("entities", []),
            },
            "vulnerabilities": results.get("vulnerabilities", []),
            "scan_warnings": getattr(analyzer, "scan_warnings", []),
        }

    def analyze_airtable_app(self, url, response):
        """Specific analysis for Airtable applications with evidence verification."""
        print("[+] Analyzing Airtable application using AirtableAnalyzer...")
        soup = BeautifulSoup(response.content, "html.parser")
        analyzer = AirtableAnalyzer(self.session)
        self._apply_scan_profile_to_analyzer(analyzer)
        results = analyzer.analyze(url, response, soup)

        return {
            "airtable_specific": {
                "base_id_exposure": results.get("base_ids", []),
                "api_key_exposure": results.get("api_keys", []),
                "table_structure_exposure": results.get("table_schemas", results.get("table_ids", [])),
            },
            "vulnerabilities": results.get("vulnerabilities", []),
            "scan_warnings": getattr(analyzer, "scan_warnings", []),
        }

    def analyze_generic_app(self, url, response):
        """Generic analysis for unknown platforms with evidence verification."""
        print("[+] Performing generic security analysis using GenericWebAnalyzer...")
        soup = BeautifulSoup(response.content, "html.parser")
        analyzer = GenericWebAnalyzer(self.session)
        self._apply_scan_profile_to_analyzer(analyzer)
        results = analyzer.analyze(url, response, soup)

        return {
            "generic_analysis": results.get("generic_findings", {}),
            "generic_specific": results.get("generic_findings", {}),
            "vulnerabilities": results.get("vulnerabilities", []),
            "scan_warnings": getattr(analyzer, "scan_warnings", []),
        }

    def analyze_shopify_app(self, url, response):
        """Shopify analysis with evidence verification."""
        print("[+] Analyzing Shopify application using ShopifyAnalyzer...")
        soup = BeautifulSoup(response.content, "html.parser")
        analyzer = ShopifyAnalyzer(self.session)
        self._apply_scan_profile_to_analyzer(analyzer)
        results = analyzer.analyze(url, response, soup)

        return {
            "shopify_specific": results.get("shopify_specific_findings", results.get("shopify_findings", {})),
            "vulnerabilities": results.get("vulnerabilities", []),
            "scan_warnings": getattr(analyzer, "scan_warnings", []),
        }

    def analyze_webflow_app(self, url, response):
        """Webflow analysis with evidence verification."""
        print("[+] Analyzing Webflow application using WebflowAnalyzer...")
        soup = BeautifulSoup(response.content, "html.parser")
        analyzer = WebflowAnalyzer(self.session)
        self._apply_scan_profile_to_analyzer(analyzer)
        results = analyzer.analyze(url, response, soup)

        return {
            "webflow_specific": results.get("webflow_specific_findings", results.get("webflow_findings", {})),
            "vulnerabilities": results.get("vulnerabilities", []),
            "scan_warnings": getattr(analyzer, "scan_warnings", []),
        }

    def analyze_wix_app(self, url, response):
        """Wix analysis with evidence verification."""
        print("[+] Analyzing Wix application using WixAnalyzer...")
        soup = BeautifulSoup(response.content, "html.parser")
        analyzer = WixAnalyzer(self.session)
        self._apply_scan_profile_to_analyzer(analyzer)
        results = analyzer.analyze(url, response, soup)

        return {
            "wix_specific": results.get("wix_specific_findings", results.get("wix_findings", {})),
            "vulnerabilities": results.get("vulnerabilities", []),
            "scan_warnings": getattr(analyzer, "scan_warnings", []),
        }

    def analyze_mendix_app(self, url, response):
        """Mendix analysis with evidence verification."""
        print("[+] Analyzing Mendix application using MendixAnalyzer...")
        soup = BeautifulSoup(response.content, "html.parser")
        analyzer = MendixAnalyzer(self.session)
        self._apply_scan_profile_to_analyzer(analyzer)
        results = analyzer.analyze(url, response, soup)

        return {
            "mendix_specific": results.get("mendix_specific_findings", results.get("mendix_findings", {})),
            "vulnerabilities": results.get("vulnerabilities", []),
            "scan_warnings": getattr(analyzer, "scan_warnings", []),
        }

    def check_common_vulnerabilities(self, url, response):
        """Check for common web vulnerabilities"""
        vulnerabilities = []

        # Check for common security issues
        soup = BeautifulSoup(response.content, "html.parser")

        # Check for mixed content
        if url.startswith("https://"):
            http_resources = soup.find_all(
                ["img", "script", "link"], src=re.compile(r"^http://")
            )
            if http_resources:
                vulnerabilities.append(
                    {
                        "type": "Mixed Content",
                        "severity": "Medium",
                        "description": f"Found {len(http_resources)} HTTP resources on HTTPS page",
                        "confidence": "Tentative",
                    }
                )

        # Check for inline JavaScript
        inline_scripts = soup.find_all("script", string=True)
        if len(inline_scripts) > 5:  # Arbitrary threshold
            vulnerabilities.append(
                {
                    "type": "Inline JavaScript",
                    "severity": "Low",
                    "description": f"Found {len(inline_scripts)} inline script blocks (potential CSP issues)",
                    "confidence": "Tentative",
                }
            )

        # Check for potential XSS in URL parameters
        parsed_url = urlparse(url)
        if parsed_url.query:
            vulnerabilities.append(
                {
                    "type": "URL Parameters",
                    "severity": "Low",
                    "description": "URL contains parameters that should be tested for XSS/injection",
                    "confidence": "Tentative",
                }
            )

        return vulnerabilities

    def _apply_scan_profile_to_analyzer(self, analyzer) -> None:
        """Apply scan profile settings to analyzer instances."""
        analyzer.fetch_external_js_assets = self.scan_profile.get("fetch_external_js_assets", True)
        analyzer.max_external_js_assets = self.scan_profile.get("max_external_js_assets", 8)
        analyzer.allow_third_party_js = self.scan_profile.get("allow_third_party_js", False)
        analyzer.max_js_bytes = self.scan_profile.get("max_js_bytes", 512 * 1024)
        analyzer.timeout_seconds = self.scan_profile.get("timeout_seconds", DEFAULT_REQUEST_TIMEOUT)
        analyzer.scan_depth = self.scan_profile.get("scan_depth", 1)
        analyzer.verify_ssl = self.scan_profile.get("verify_ssl", True)

    def update_scan_profile(self, **kwargs) -> None:
        """Update scan profile values for the current scanner instance."""
        for key, value in kwargs.items():
            if value is not None:
                self.scan_profile[key] = value
        if hasattr(self.session, "default_timeout"):
            try:
                self.session.default_timeout = int(self.scan_profile.get("timeout_seconds", DEFAULT_REQUEST_TIMEOUT))
            except (TypeError, ValueError):
                pass
        if hasattr(self, "platform_detector"):
            try:
                self.platform_detector.timeout_seconds = int(
                    self.scan_profile.get("timeout_seconds", DEFAULT_REQUEST_TIMEOUT)
                )
            except (TypeError, ValueError):
                pass
        if hasattr(self.session, "update_rate_limits"):
            self.session.update_rate_limits(
                min_interval_seconds=self.scan_profile.get("min_interval_seconds"),
                max_requests_per_minute=self.scan_profile.get("max_requests_per_minute"),
            )

    def check_bubble_vulnerabilities(self, url, soup):
        """Check for Bubble.io specific vulnerabilities"""
        vulnerabilities = []

        # Check for exposed workflow URLs
        workflow_pattern = re.compile(r"api/1\.1/wf/")
        if soup.find(string=workflow_pattern):
            vulnerabilities.append(
                {
                    "type": "Bubble Workflow Exposure",
                    "severity": "High",
                    "description": "Bubble workflow endpoints detected in client-side code",
                }
            )

        return vulnerabilities

    def check_outsystems_vulnerabilities(self, url, soup):
        """Check for OutSystems specific vulnerabilities"""
        vulnerabilities = []

        # Check for exposed REST APIs
        if soup.find(string=re.compile(r"/rest/")):
            vulnerabilities.append(
                {
                    "type": "OutSystems REST API Exposure",
                    "severity": "Medium",
                    "description": "REST API endpoints detected in client-side code",
                }
            )

        return vulnerabilities

    def check_airtable_vulnerabilities(self, url, soup):
        """Check for Airtable specific vulnerabilities"""
        vulnerabilities = []

        # Check for exposed base IDs
        if soup.find(string=re.compile(r"app[A-Za-z0-9]{14}")):
            vulnerabilities.append(
                {
                    "type": "Airtable Base ID Exposure",
                    "severity": "Medium",
                    "description": "Airtable base IDs detected in client-side code",
                }
            )

        return vulnerabilities

    def generate_recommendations(self, results):
        """Generate security recommendations based on findings"""
        recommendations = []

        # Security headers recommendations
        headers = results["security_headers"]
        missing_headers = [
            k for k, v in headers.items() if v == "Missing" and k != "security_score"
        ]

        if missing_headers:
            recommendations.append(
                {
                    "category": "Security Headers",
                    "priority": "High",
                    "description": f"Implement missing security headers: {', '.join(missing_headers)}",
                }
            )

        # SSL recommendations
        if "error" in results["ssl_analysis"]:
            recommendations.append(
                {
                    "category": "SSL/TLS",
                    "priority": "Critical",
                    "description": "Implement HTTPS with proper SSL/TLS configuration",
                }
            )

        # Platform-specific recommendations
        platform = results["platform_type"]
        if platform == "bubble":
            recommendations.extend(self.get_bubble_recommendations(results))
        elif platform == "outsystems":
            recommendations.extend(self.get_outsystems_recommendations(results))
        elif platform == "airtable":
            recommendations.extend(self.get_airtable_recommendations(results))

        return recommendations

    def get_bubble_recommendations(self, results):
        """Get Bubble.io specific recommendations"""
        recommendations = []

        if "bubble_specific" in results:
            bubble_data = results["bubble_specific"]

            if bubble_data["api_endpoints_found"]:
                recommendations.append(
                    {
                        "category": "Bubble Security",
                        "priority": "High",
                        "description": "Review privacy rules for exposed workflow APIs",
                    }
                )

        return recommendations

    def get_outsystems_recommendations(self, results):
        """Get OutSystems specific recommendations"""
        recommendations = []

        if "outsystems_specific" in results:
            os_data = results["outsystems_specific"]

            if os_data["rest_apis_found"]:
                recommendations.append(
                    {
                        "category": "OutSystems Security",
                        "priority": "High",
                        "description": "Implement proper authentication and authorization for REST APIs",
                    }
                )

        return recommendations

    def get_airtable_recommendations(self, results):
        """Get Airtable specific recommendations"""
        recommendations = []

        if "airtable_specific" in results:
            at_data = results["airtable_specific"]

            if at_data["base_id_exposure"]:
                recommendations.append(
                    {
                        "category": "Airtable Security",
                        "priority": "Medium",
                        "description": "Avoid exposing Airtable base IDs in client-side code",
                    }
                )

        return recommendations

    def generate_report(self, results, format="json"):
        """Generate security report in specified format"""
        if format == "json":
            return json.dumps(results, indent=2, ensure_ascii=False)
        elif format == "html":
            return self.generate_html_report(results)
        else:
            return self.generate_text_report(results)

    def generate_html_report(self, results):
        """Generate HTML security report"""
        structured_results = transform_results_for_professional_report(results)
        report_generator = ProfessionalReportGenerator()
        return report_generator.generate_html_content(structured_results)

    def generate_text_report(self, results):
        """Generate text-based security report"""
        report = []
        report.append("=" * 60)
        report.append("LOW-CODE PLATFORM SECURITY ANALYSIS REPORT")
        report.append("=" * 60)
        report.append(f"Target URL: {results.get('url', 'Unknown')}")
        report.append(
            f"Platform Type: {results.get('platform_type', 'Unknown').title()}"
        )
        report.append(f"Scan Timestamp: {results.get('timestamp', 'Unknown')}")
        report.append(f"Response Code: {results.get('status_code', 'Unknown')}")
        report.append("")

        # Security headers section
        report.append("-" * 40)
        report.append("SECURITY HEADERS ANALYSIS")
        report.append("-" * 40)
        headers = results.get("security_headers", {})
        for header, value in headers.items():
            if header != "security_score":
                report.append(f"{header}: {value}")
        report.append(f"Security Score: {headers.get('security_score', 'Unknown')}")
        report.append("")

        # Vulnerabilities section
        vulnerabilities = results.get("vulnerabilities", [])
        if vulnerabilities:
            report.append("-" * 40)
            report.append("VULNERABILITIES FOUND")
            report.append("-" * 40)
            for vuln in vulnerabilities:
                report.append(
                    f"[{vuln.get('severity', 'Unknown')}] {vuln.get('type', 'Unknown')}"
                )
                report.append(
                    f"Description: {vuln.get('description', 'No description')}"
                )
                report.append("")

        # Recommendations section
        recommendations = results.get("recommendations", [])
        if recommendations:
            report.append("-" * 40)
            report.append("SECURITY RECOMMENDATIONS")
            report.append("-" * 40)
            for rec in recommendations:
                report.append(
                    f"[{rec.get('priority', 'Unknown')}] {rec.get('category', 'Unknown')}"
                )
                report.append(
                    f"Recommendation: {rec.get('description', 'No description')}"
                )
                report.append("")

        return "\n".join(report)


def main():
    """Main function to run the security scanner"""
    scanner = LowCodeSecurityScanner()

    # Target URLs for analysis
    targets = [
        "https://amqmalawadhi-85850.bubbleapps.io/version-test/",
        "https://personal-7hwwkk2j-dev.outsystems.app/UST/",
        "https://airtable.com/app5oLkwSi8gaXUod/",
    ]

    print("Low-Code Platform Security Scanner")
    print("Bachelor Thesis: Comparative Security Analysis")
    print("=" * 50)

    all_results = []

    for target in targets:
        try:
            result = scanner.scan_target(target)
            all_results.append(result)

            # Generate and save individual reports
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            platform = result.get("platform_type", "unknown")

            # Save JSON report
            json_report = scanner.generate_report(result, "json")
            with open(
                f"security_report_{platform}_{timestamp}.json", "w", encoding="utf-8"
            ) as f:
                f.write(json_report)

            # Save text report
            text_report = scanner.generate_text_report(result)
            with open(
                f"security_report_{platform}_{timestamp}.txt", "w", encoding="utf-8"
            ) as f:
                f.write(text_report)

            print(f"[+] Completed scan for {target}")
            print(f"[+] Reports saved as security_report_{platform}_{timestamp}.*")

        except Exception as e:
            print(f"[-] Error scanning {target}: {e}")

        # Add delay between scans to be respectful
        time.sleep(2)

    # Generate comparative analysis
    if len(all_results) > 1:
        comparative_report = generate_comparative_analysis(all_results)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        with open(f"comparative_analysis_{timestamp}.json", "w", encoding="utf-8") as f:
            json.dump(comparative_report, f, indent=2, ensure_ascii=False)

        print(
            f"[+] Comparative analysis saved as comparative_analysis_{timestamp}.json"
        )

    print("\n[+] Security analysis complete!")


def generate_comparative_analysis(results):
    """Generate comparative analysis between platforms"""
    analysis = {
        "summary": {
            "total_targets": len(results),
            "platforms_analyzed": list(
                set([r.get("platform_type", "unknown") for r in results])
            ),
            "timestamp": datetime.now().isoformat(),
        },
        "security_comparison": {},
        "vulnerability_comparison": {},
        "recommendations_summary": {},
    }

    # Compare security headers across platforms
    for result in results:
        platform = result.get("platform_type", "unknown")
        headers = result.get("security_headers", {})

        analysis["security_comparison"][platform] = {
            "security_score": headers.get("security_score", "0/8"),
            "missing_headers": [
                k
                for k, v in headers.items()
                if v == "Missing" and k != "security_score"
            ],
        }

    # Compare vulnerabilities
    for result in results:
        platform = result.get("platform_type", "unknown")
        vulns = result.get("vulnerabilities", [])

        analysis["vulnerability_comparison"][platform] = {
            "total_vulnerabilities": len(vulns),
            "high_severity": len([v for v in vulns if v.get("severity") == "High"]),
            "medium_severity": len([v for v in vulns if v.get("severity") == "Medium"]),
            "low_severity": len([v for v in vulns if v.get("severity") == "Low"]),
        }

    return analysis


if __name__ == "__main__":
    main()
