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
import re
import socket
import ssl
import time
import warnings
from datetime import datetime
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup

from .analyzers import (
    AirtableAnalyzer,
    BubbleAnalyzer,
    GenericWebAnalyzer,
    OutSystemsAnalyzer,
    get_analyzer_for_platform,
    analyze_platform_security,
)
from .report_generator import ProfessionalReportGenerator
from .result_transformer import transform_results_for_professional_report

# Suppress SSL warnings for testing
warnings.filterwarnings("ignore", message="Unverified HTTPS request")


class LowCodeSecurityScanner:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update(
            {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
            }
        )
        self.results = {}

    def scan_target(self, url):
        """Main scanning function for a target URL"""
        print(f"\n[+] Starting security scan for: {url}")

        target_results = {
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
        }

        try:
            # Basic connectivity and platform identification
            response = self.session.get(url, timeout=10, verify=False)
            target_results["status_code"] = response.status_code
            target_results["response_time"] = response.elapsed.total_seconds()

            # Security header analysis
            target_results["security_headers"] = self.analyze_security_headers(
                response.headers
            )

            # SSL/TLS analysis
            target_results["ssl_analysis"] = self.analyze_ssl(url)

            # Content analysis based on platform type
            if target_results["platform_type"] == "bubble":
                target_results.update(self.analyze_bubble_app(url, response))
            elif target_results["platform_type"] == "outsystems":
                target_results.update(self.analyze_outsystems_app(url, response))
            elif target_results["platform_type"] == "airtable":
                target_results.update(self.analyze_airtable_app(url, response))
            else:
                target_results.update(self.analyze_generic_app(url, response))

            # Common vulnerability checks
            target_results["vulnerabilities"].extend(
                self.check_common_vulnerabilities(url, response)
            )

            # Generate security recommendations
            target_results["recommendations"] = self.generate_recommendations(
                target_results
            )

        except requests.exceptions.RequestException as e:
            print(f"[-] Error scanning {url}: {e}")
            target_results["error"] = str(e)

        return target_results

    def identify_platform(self, url):
        """Identify the low-code platform based on URL and response"""
        domain = urlparse(url).netloc.lower()

        if "bubble" in domain or "bubbleapps.io" in domain:
            return "bubble"
        elif "outsystems" in domain:
            return "outsystems"
        elif "airtable" in domain:
            return "airtable"
        else:
            return "unknown"

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
        """Specific analysis for Bubble.io applications"""
        print("[+] Analyzing Bubble.io application using BubbleAnalyzer...")
        soup = BeautifulSoup(response.content, "html.parser")
        analyzer = BubbleAnalyzer(self.session)
        results = analyzer.analyze(url, response, soup)

        # Perform active verification of found vulnerabilities
        analyzer.verify_vulnerabilities(url)

        # Map BubbleAnalyzer findings to the format expected by scanner
        return {
            "bubble_specific": {
                "api_endpoints_found": results.get("api_endpoints", []),
                "workflow_exposure": results.get("workflow_patterns", []),
                "database_exposure": results.get("database_schemas", []),
                "privacy_rules": results.get("privacy_rules", []),
            },
            "vulnerabilities": results.get("vulnerabilities", []),
        }

    def analyze_outsystems_app(self, url, response):
        """Specific analysis for OutSystems applications"""
        print("[+] Analyzing OutSystems application using OutSystemsAnalyzer...")
        soup = BeautifulSoup(response.content, "html.parser")
        analyzer = OutSystemsAnalyzer(self.session)
        results = analyzer.analyze(url, response, soup)

        # Perform active verification of found vulnerabilities
        analyzer.verify_vulnerabilities(url)

        return {
            "outsystems_specific": {
                "rest_apis_found": results.get("rest_apis", []),
                "screen_actions_found": results.get("screen_actions", []),
                "entities": results.get("entities", []),
            },
            "vulnerabilities": results.get("vulnerabilities", []),
        }

    def analyze_airtable_app(self, url, response):
        """Specific analysis for Airtable applications"""
        print("[+] Analyzing Airtable application using AirtableAnalyzer...")
        soup = BeautifulSoup(response.content, "html.parser")
        analyzer = AirtableAnalyzer(self.session)
        results = analyzer.analyze(url, response, soup)

        # Perform active verification of found vulnerabilities
        analyzer.verify_vulnerabilities(url)

        return {
            "airtable_specific": {
                "base_id_exposure": results.get("base_ids", []),
                "api_key_exposure": results.get("api_keys", []),
                "table_structure_exposure": results.get("table_ids", []),
            },
            "vulnerabilities": results.get("vulnerabilities", []),
        }

    def analyze_generic_app(self, url, response):
        """Generic analysis for unknown platforms"""
        print("[+] Performing generic security analysis using GenericWebAnalyzer...")
        soup = BeautifulSoup(response.content, "html.parser")
        analyzer = GenericWebAnalyzer(self.session)
        results = analyzer.analyze(url, response, soup)

        # Perform active verification of found vulnerabilities
        analyzer.verify_vulnerabilities(url)

        return {
            "generic_analysis": results.get("generic_findings", {}),
            "vulnerabilities": results.get("vulnerabilities", []),
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
                }
            )

        return vulnerabilities

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
