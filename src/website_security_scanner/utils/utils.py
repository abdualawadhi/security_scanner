#!/usr/bin/env python3
"""
Utility Functions for Low-Code Platform Security Scanner
Bachelor Thesis: Low-Code Platforms for E-commerce: Comparative Security Analysis

This module contains utility functions for report generation, data processing,
and common operations used throughout the security scanner.

Author: Bachelor Thesis Project
"""

import hashlib
import json
import re
import socket
import ssl
import urllib.parse
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

import requests
from bs4 import BeautifulSoup


class SecurityUtils:
    """Utility functions for security analysis"""

    @staticmethod
    def calculate_hash(content: str, algorithm: str = "sha256") -> str:
        """Calculate hash of content for fingerprinting"""
        if algorithm.lower() == "md5":
            return hashlib.md5(content.encode()).hexdigest()
        elif algorithm.lower() == "sha1":
            return hashlib.sha1(content.encode()).hexdigest()
        elif algorithm.lower() == "sha256":
            return hashlib.sha256(content.encode()).hexdigest()
        else:
            raise ValueError(f"Unsupported hash algorithm: {algorithm}")

    @staticmethod
    def extract_domain(url: str) -> str:
        """Extract domain from URL"""
        try:
            parsed = urllib.parse.urlparse(url)
            return parsed.netloc.lower()
        except Exception:
            return ""

    @staticmethod
    def is_valid_url(url: str) -> bool:
        """Validate if string is a valid URL"""
        try:
            result = urllib.parse.urlparse(url)
            return all([result.scheme, result.netloc])
        except Exception:
            return False

    @staticmethod
    def extract_emails(content: str) -> List[str]:
        """Extract email addresses from content"""
        email_pattern = r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"
        return re.findall(email_pattern, content)

    @staticmethod
    def extract_phone_numbers(content: str) -> List[str]:
        """Extract phone numbers from content"""
        phone_patterns = [
            r"\+?1?[-.\s]?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}",
            r"\+?[0-9]{1,4}[-.\s]?[0-9]{3,4}[-.\s]?[0-9]{3,4}[-.\s]?[0-9]{3,4}",
        ]

        phone_numbers = []
        for pattern in phone_patterns:
            matches = re.findall(pattern, content)
            phone_numbers.extend(matches)

        return list(set(phone_numbers))  # Remove duplicates

    @staticmethod
    def extract_ip_addresses(content: str) -> List[str]:
        """Extract IP addresses from content"""
        ip_pattern = r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"
        return re.findall(ip_pattern, content)

    @staticmethod
    def is_internal_ip(ip: str) -> bool:
        """Check if IP address is internal/private"""
        try:
            octets = [int(x) for x in ip.split(".")]

            # Private IP ranges
            if octets[0] == 10:
                return True
            elif octets[0] == 172 and 16 <= octets[1] <= 31:
                return True
            elif octets[0] == 192 and octets[1] == 168:
                return True
            elif ip == "127.0.0.1":
                return True

            return False
        except Exception:
            return False

    @staticmethod
    def check_port_open(host: str, port: int, timeout: float = 3.0) -> bool:
        """Check if a port is open on a host"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            return result == 0
        except Exception:
            return False

    @staticmethod
    def get_ssl_info(hostname: str, port: int = 443) -> Dict[str, Any]:
        """Get SSL certificate information"""
        ssl_info = {}

        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()

                    ssl_info = {
                        "version": ssock.version(),
                        "cipher": ssock.cipher(),
                        "certificate": {
                            "subject": dict(x[0] for x in cert.get("subject", [])),
                            "issuer": dict(x[0] for x in cert.get("issuer", [])),
                            "serial_number": cert.get("serialNumber", ""),
                            "not_before": cert.get("notBefore", ""),
                            "not_after": cert.get("notAfter", ""),
                            "subject_alt_names": [
                                x[1] for x in cert.get("subjectAltName", [])
                            ],
                        },
                    }

        except Exception as e:
            ssl_info["error"] = str(e)

        return ssl_info


class DataProcessor:
    """Data processing utilities for analysis results"""

    @staticmethod
    def normalize_vulnerability_data(
        vulnerabilities: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """Normalize vulnerability data structure"""
        normalized = []

        for vuln in vulnerabilities:
            normalized_vuln = {
                "id": SecurityUtils.calculate_hash(
                    f"{vuln.get('type', '')}{vuln.get('description', '')}"
                )[:8],
                "type": vuln.get("type", "Unknown"),
                "severity": vuln.get("severity", "Low"),
                "description": vuln.get("description", ""),
                "evidence": vuln.get("evidence", ""),
                "recommendation": vuln.get("recommendation", ""),
                "cve_references": vuln.get("cve_references", []),
                "owasp_category": DataProcessor.map_to_owasp_category(
                    vuln.get("type", "")
                ),
                "risk_score": DataProcessor.calculate_risk_score(vuln),
            }
            normalized.append(normalized_vuln)

        return normalized

    @staticmethod
    def map_to_owasp_category(vulnerability_type: str) -> str:
        """Map vulnerability type to OWASP Top 10 category"""
        mapping = {
            "SQL Injection": "A03:2021 - Injection",
            "XSS": "A03:2021 - Injection",
            "Cross-Site Scripting": "A03:2021 - Injection",
            "Authentication": "A07:2021 - Identification and Authentication Failures",
            "Session Management": "A07:2021 - Identification and Authentication Failures",
            "Authorization": "A01:2021 - Broken Access Control",
            "Access Control": "A01:2021 - Broken Access Control",
            "CSRF": "A01:2021 - Broken Access Control",
            "Security Headers": "A05:2021 - Security Misconfiguration",
            "SSL/TLS": "A02:2021 - Cryptographic Failures",
            "Information Disclosure": "A01:2021 - Broken Access Control",
            "API Security": "A09:2021 - Security Logging and Monitoring Failures",
            "Input Validation": "A03:2021 - Injection",
        }

        for key, category in mapping.items():
            if key.lower() in vulnerability_type.lower():
                return category

        return "A10:2021 - Server-Side Request Forgery (SSRF)"

    @staticmethod
    def calculate_risk_score(vulnerability: Dict[str, Any]) -> float:
        """Calculate numerical risk score for vulnerability"""
        severity_weights = {"Critical": 10.0, "High": 7.5, "Medium": 5.0, "Low": 2.5}

        base_score = severity_weights.get(vulnerability.get("severity", "Low"), 2.5)

        # Adjust based on evidence quality
        evidence = vulnerability.get("evidence", "")
        if len(evidence) > 100:
            base_score += 1.0
        elif len(evidence) > 50:
            base_score += 0.5

        # Cap at 10.0
        return min(base_score, 10.0)

    @staticmethod
    def aggregate_platform_data(results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Aggregate security data across platforms"""
        platforms = {}

        for result in results:
            if "error" in result:
                continue

            platform = result.get("platform_type", "unknown")
            if platform not in platforms:
                platforms[platform] = {
                    "applications": 0,
                    "total_vulnerabilities": 0,
                    "severity_distribution": {
                        "Critical": 0,
                        "High": 0,
                        "Medium": 0,
                        "Low": 0,
                    },
                    "common_issues": {},
                    "security_scores": [],
                    "avg_response_time": 0,
                }

            platforms[platform]["applications"] += 1

            # Process vulnerabilities
            vulns = result.get("vulnerabilities", [])
            platforms[platform]["total_vulnerabilities"] += len(vulns)

            for vuln in vulns:
                severity = vuln.get("severity", "Low")
                platforms[platform]["severity_distribution"][severity] += 1

                vuln_type = vuln.get("type", "Unknown")
                if vuln_type not in platforms[platform]["common_issues"]:
                    platforms[platform]["common_issues"][vuln_type] = 0
                platforms[platform]["common_issues"][vuln_type] += 1

            # Process security score
            headers = result.get("security_headers", {})
            if "security_score" in headers:
                try:
                    score_parts = headers["security_score"].split("/")
                    if len(score_parts) == 2:
                        score = int(score_parts[0]) / int(score_parts[1]) * 100
                        platforms[platform]["security_scores"].append(score)
                except Exception:
                    pass

            # Response time
            response_time = result.get("response_time", 0)
            if response_time > 0:
                platforms[platform]["avg_response_time"] += response_time

        # Calculate averages
        for platform_data in platforms.values():
            if platform_data["applications"] > 0:
                platform_data["avg_response_time"] /= platform_data["applications"]

                if platform_data["security_scores"]:
                    platform_data["avg_security_score"] = sum(
                        platform_data["security_scores"]
                    ) / len(platform_data["security_scores"])
                else:
                    platform_data["avg_security_score"] = 0

                platform_data["vulnerability_density"] = (
                    platform_data["total_vulnerabilities"]
                    / platform_data["applications"]
                )

        return platforms


class ReportGenerator:
    """Generate various types of reports from security scan results"""

    def __init__(self):
        self.templates = {
            "html": self._get_html_template(),
            "markdown": self._get_markdown_template(),
        }

    def generate_executive_summary(
        self, results: Union[Dict[str, Any], List[Dict[str, Any]]]
    ) -> Dict[str, Any]:
        """Generate executive summary from scan results"""
        if isinstance(results, dict):
            results = [results]

        summary = {
            "scan_overview": {
                "timestamp": datetime.now().isoformat(),
                "total_applications": len(results),
                "successful_scans": len([r for r in results if "error" not in r]),
                "failed_scans": len([r for r in results if "error" in r]),
            },
            "security_overview": {
                "total_vulnerabilities": 0,
                "critical_issues": 0,
                "high_severity_issues": 0,
                "platforms_analyzed": set(),
            },
            "risk_assessment": {
                "overall_risk_level": "Low",
                "immediate_attention_required": False,
                "compliance_concerns": [],
            },
            "key_findings": [],
            "recommendations": [],
        }

        all_vulns = []

        for result in results:
            if "error" in result:
                continue

            platform = result.get("platform_type", "unknown")
            summary["security_overview"]["platforms_analyzed"].add(platform)

            vulns = result.get("vulnerabilities", [])
            all_vulns.extend(vulns)

            for vuln in vulns:
                severity = vuln.get("severity", "Low")
                if severity == "Critical":
                    summary["security_overview"]["critical_issues"] += 1
                elif severity == "High":
                    summary["security_overview"]["high_severity_issues"] += 1

        summary["security_overview"]["total_vulnerabilities"] = len(all_vulns)
        summary["security_overview"]["platforms_analyzed"] = list(
            summary["security_overview"]["platforms_analyzed"]
        )

        # Determine overall risk level
        if summary["security_overview"]["critical_issues"] > 0:
            summary["risk_assessment"]["overall_risk_level"] = "Critical"
            summary["risk_assessment"]["immediate_attention_required"] = True
        elif summary["security_overview"]["high_severity_issues"] > 2:
            summary["risk_assessment"]["overall_risk_level"] = "High"
        elif summary["security_overview"]["total_vulnerabilities"] > 10:
            summary["risk_assessment"]["overall_risk_level"] = "Medium"

        # Generate key findings
        vuln_types = {}
        for vuln in all_vulns:
            vuln_type = vuln.get("type", "Unknown")
            if vuln_type not in vuln_types:
                vuln_types[vuln_type] = 0
            vuln_types[vuln_type] += 1

        # Top 5 most common vulnerability types
        top_vulns = sorted(vuln_types.items(), key=lambda x: x[1], reverse=True)[:5]
        for vuln_type, count in top_vulns:
            summary["key_findings"].append(f"{vuln_type}: {count} instances")

        # Generate high-level recommendations
        if summary["security_overview"]["critical_issues"] > 0:
            summary["recommendations"].append(
                "Address critical security vulnerabilities immediately"
            )

        if any("API" in vuln_type for vuln_type, _ in top_vulns):
            summary["recommendations"].append(
                "Implement proper API security controls and authentication"
            )

        if any("Header" in vuln_type for vuln_type, _ in top_vulns):
            summary["recommendations"].append(
                "Configure security headers to improve defense-in-depth"
            )

        return summary

    def generate_html_report(
        self,
        results: Union[Dict[str, Any], List[Dict[str, Any]]],
        title: str = "Security Analysis Report",
    ) -> str:
        """Generate HTML report from scan results"""
        if isinstance(results, dict):
            results = [results]

        # Process data for HTML template
        processed_results = []
        for result in results:
            if "error" not in result:
                processed_results.append(
                    {
                        "url": result.get("url", "Unknown"),
                        "platform": result.get("platform_type", "unknown").title(),
                        "vulnerabilities": DataProcessor.normalize_vulnerability_data(
                            result.get("vulnerabilities", [])
                        ),
                        "security_score": self._extract_security_score(result),
                        "headers": result.get("security_headers", {}),
                        "ssl_info": result.get("ssl_analysis", {}),
                    }
                )

        executive_summary = self.generate_executive_summary(results)

        # Generate HTML using template
        html_content = self.templates["html"].format(
            title=title,
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            executive_summary=json.dumps(executive_summary, indent=2),
            results=json.dumps(processed_results, indent=2),
            total_applications=len(processed_results),
            total_vulnerabilities=executive_summary["security_overview"][
                "total_vulnerabilities"
            ],
        )

        return html_content

    def generate_csv_report(
        self, results: Union[Dict[str, Any], List[Dict[str, Any]]]
    ) -> str:
        """Generate CSV report for data analysis"""
        if isinstance(results, dict):
            results = [results]

        csv_lines = []
        csv_lines.append(
            "URL,Platform,Vulnerability_Type,Severity,Description,OWASP_Category,Risk_Score"
        )

        for result in results:
            if "error" in result:
                continue

            url = result.get("url", "")
            platform = result.get("platform_type", "unknown")
            vulns = DataProcessor.normalize_vulnerability_data(
                result.get("vulnerabilities", [])
            )

            for vuln in vulns:
                csv_line = f'"{url}","{platform}","{vuln["type"]}","{vuln["severity"]}","{vuln["description"][:100]}","{vuln["owasp_category"]}",{vuln["risk_score"]}'
                csv_lines.append(csv_line)

        return "\n".join(csv_lines)

    def _extract_security_score(self, result: Dict[str, Any]) -> float:
        """Extract numeric security score from result"""
        headers = result.get("security_headers", {})
        if "security_score" in headers:
            try:
                score_parts = headers["security_score"].split("/")
                if len(score_parts) == 2:
                    return int(score_parts[0]) / int(score_parts[1]) * 100
            except Exception:
                pass
        return 0.0

    def _get_html_template(self) -> str:
        """Get HTML report template"""
        return """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title}</title>
    <style>
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 20px; background-color: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); overflow: hidden; }}
        .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; text-align: center; }}
        .header h1 {{ margin: 0; font-size: 2.5em; }}
        .header p {{ margin: 10px 0 0 0; font-size: 1.1em; opacity: 0.9; }}
        .summary {{ padding: 30px; background: #f8f9fa; border-bottom: 1px solid #e9ecef; }}
        .summary-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; }}
        .summary-card {{ background: white; padding: 20px; border-radius: 6px; text-align: center; border-left: 4px solid #667eea; }}
        .summary-card h3 {{ margin: 0 0 10px 0; color: #333; }}
        .summary-card .number {{ font-size: 2em; font-weight: bold; color: #667eea; }}
        .results {{ padding: 30px; }}
        .result-item {{ margin-bottom: 30px; padding: 25px; border: 1px solid #e9ecef; border-radius: 6px; background: #fefefe; }}
        .result-header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; }}
        .result-url {{ font-size: 1.2em; font-weight: bold; color: #333; }}
        .platform-badge {{ background: #667eea; color: white; padding: 4px 12px; border-radius: 20px; font-size: 0.9em; }}
        .vulnerability {{ margin: 10px 0; padding: 15px; border-left: 4px solid #ffc107; background: #fffbf0; border-radius: 0 4px 4px 0; }}
        .vulnerability.critical {{ border-left-color: #dc3545; background: #fff5f5; }}
        .vulnerability.high {{ border-left-color: #fd7e14; background: #fff8f0; }}
        .vulnerability.medium {{ border-left-color: #ffc107; background: #fffbf0; }}
        .vulnerability.low {{ border-left-color: #28a745; background: #f0fff4; }}
        .vulnerability h4 {{ margin: 0 0 8px 0; color: #333; }}
        .vulnerability p {{ margin: 0; color: #666; line-height: 1.5; }}
        .no-vulns {{ text-align: center; padding: 40px; color: #28a745; font-size: 1.1em; }}
        .timestamp {{ text-align: center; padding: 20px; color: #666; font-size: 0.9em; border-top: 1px solid #e9ecef; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>{title}</h1>
            <p>Low-Code Platform Security Analysis - Generated on {timestamp}</p>
        </div>

        <div class="summary">
            <div class="summary-grid">
                <div class="summary-card">
                    <h3>Applications Scanned</h3>
                    <div class="number">{total_applications}</div>
                </div>
                <div class="summary-card">
                    <h3>Total Vulnerabilities</h3>
                    <div class="number">{total_vulnerabilities}</div>
                </div>
            </div>
        </div>

        <div class="results">
            <!-- Results will be populated by JavaScript -->
        </div>

        <div class="timestamp">
            Report generated by Low-Code Platform Security Scanner<br>
            Bachelor Thesis: Comparative Security Analysis of Low-Code Platforms
        </div>
    </div>

    <script>
        const results = {results};
        const resultsContainer = document.querySelector('.results');

        if (results.length === 0) {{
            resultsContainer.innerHTML = '<div class="no-vulns">No results to display</div>';
        }} else {{
            results.forEach(result => {{
                const resultDiv = document.createElement('div');
                resultDiv.className = 'result-item';

                let vulnerabilitiesHtml = '';
                if (result.vulnerabilities.length === 0) {{
                    vulnerabilitiesHtml = '<div class="no-vulns">✅ No vulnerabilities found!</div>';
                }} else {{
                    result.vulnerabilities.forEach(vuln => {{
                        vulnerabilitiesHtml += `
                            <div class="vulnerability ${{vuln.severity.toLowerCase()}}">
                                <h4>${{vuln.type}} (${{vuln.severity}})</h4>
                                <p>${{vuln.description}}</p>
                                ${{vuln.recommendation ? `<p><strong>Recommendation:</strong> ${{vuln.recommendation}}</p>` : ''}}
                            </div>
                        `;
                    }});
                }}

                resultDiv.innerHTML = `
                    <div class="result-header">
                        <div class="result-url">${{result.url}}</div>
                        <div class="platform-badge">${{result.platform}}</div>
                    </div>
                    ${{vulnerabilitiesHtml}}
                `;

                resultsContainer.appendChild(resultDiv);
            }});
        }}
    </script>
</body>
</html>
        """

    def _get_markdown_template(self) -> str:
        """Get Markdown report template"""
        return """# {title}

**Generated:** {timestamp}
**Scanner:** Low-Code Platform Security Scanner
**Context:** Bachelor Thesis - Comparative Security Analysis of Low-Code Platforms

## Executive Summary

{executive_summary}

## Detailed Results

{detailed_results}

---

*This report was generated using automated security scanning tools. Manual verification of findings is recommended.*
"""


class FileUtils:
    """File operation utilities"""

    @staticmethod
    def ensure_directory(path: Union[str, Path]) -> Path:
        """Ensure directory exists, create if necessary"""
        path = Path(path)
        path.mkdir(parents=True, exist_ok=True)
        return path

    @staticmethod
    def safe_filename(filename: str) -> str:
        """Create safe filename by removing invalid characters"""
        # Remove invalid characters
        safe_chars = re.sub(r'[<>:"/\\|?*]', "_", filename)
        # Remove multiple underscores
        safe_chars = re.sub(r"_+", "_", safe_chars)
        # Trim and limit length
        return safe_chars.strip("_")[:200]

    @staticmethod
    def load_json_file(file_path: Union[str, Path]) -> Optional[Dict[str, Any]]:
        """Safely load JSON file"""
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return None

    @staticmethod
    def save_json_file(data: Any, file_path: Union[str, Path], indent: int = 2) -> bool:
        """Safely save data to JSON file"""
        try:
            path = Path(file_path)
            FileUtils.ensure_directory(path.parent)

            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=indent, ensure_ascii=False)
            return True
        except Exception:
            return False


# Export main utility classes
__all__ = ["SecurityUtils", "DataProcessor", "ReportGenerator", "FileUtils"]
