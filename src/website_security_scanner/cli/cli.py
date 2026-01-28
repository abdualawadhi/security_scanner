#!/usr/bin/env python3
"""
Command Line Interface for Low-Code Platform Security Scanner
Bachelor Thesis: Low-Code Platforms for E-commerce: Comparative Security Analysis

This CLI provides an easy-to-use interface for running security scans on low-code platforms.

Usage:
    python cli.py --url https://example.bubbleapps.io/app
    python cli.py --config config.yaml
    python cli.py --batch urls.txt
    python cli.py --comparative --output comparative_report.json

Author: Bachelor Thesis Project
"""

import argparse
import json
import os
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List
from urllib.parse import urlparse

import requests
import yaml
from colorama import Back, Fore, Style, init

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))
# Initialize colorama for cross-platform colored output
init()

from website_security_scanner.main import LowCodeSecurityScanner
from website_security_scanner.report_generator import ProfessionalReportGenerator


class SecurityScannerCLI:
    def __init__(self):
        self.scanner = LowCodeSecurityScanner()
        self.report_generator = ProfessionalReportGenerator()
        self.results = []

    def print_banner(self):
        """Print application banner"""
        banner = f"""
{Fore.CYAN}
╔═══════════════════════════════════════════════════════════════════════════════╗
║                     Low-Code Platform Security Scanner                        ║
║                                                                               ║
║         Bachelor Thesis: Comparative Security Analysis of Low-Code Platforms  ║
║                                                                               ║
║  Supported Platforms: Bubble.io │ OutSystems │ Airtable │ Generic Web Apps   ║
╚═══════════════════════════════════════════════════════════════════════════════╝
{Style.RESET_ALL}
"""
        print(banner)

    def print_status(self, message: str, status: str = "info"):
        """Print colored status messages"""
        colors = {
            "info": Fore.BLUE,
            "success": Fore.GREEN,
            "warning": Fore.YELLOW,
            "error": Fore.RED,
            "critical": Fore.MAGENTA,
        }

        icons = {
            "info": "ℹ",
            "success": "✓",
            "warning": "⚠",
            "error": "✗",
            "critical": "🔥",
        }

        color = colors.get(status, Fore.WHITE)
        icon = icons.get(status, "•")

        print(f"{color}[{icon}] {message}{Style.RESET_ALL}")

    def scan_single_url(self, url: str, output_format: str = "json") -> Dict[str, Any]:
        """Scan a single URL and return results"""
        self.print_status(f"Starting security scan for: {url}")

        try:
            start_time = time.time()
            result = self.scanner.scan_target(url)
            scan_time = time.time() - start_time

            result["scan_duration"] = round(scan_time, 2)

            # Print summary
            self.print_scan_summary(result)

            return result

        except Exception as e:
            self.print_status(f"Error scanning {url}: {str(e)}", "error")
            return {
                "url": url,
                "error": str(e),
                "timestamp": datetime.now().isoformat(),
            }

    def scan_batch_urls(
        self, urls: List[str], output_format: str = "json"
    ) -> List[Dict[str, Any]]:
        """Scan multiple URLs"""
        self.print_status(f"Starting batch scan of {len(urls)} URLs")

        results = []
        for i, url in enumerate(urls, 1):
            self.print_status(f"Scanning {i}/{len(urls)}: {url}")

            result = self.scan_single_url(url, output_format)
            results.append(result)

            # Add delay between scans to be respectful
            if i < len(urls):
                time.sleep(2)

        return results

    def print_scan_summary(self, result: Dict[str, Any]):
        """Print a summary of scan results"""
        url = result.get("url", "Unknown")
        platform = result.get("platform_type", "unknown").title()
        vulnerabilities = result.get("vulnerabilities", [])

        print(f"\n{Fore.CYAN}═══ Scan Summary for {url} ═══{Style.RESET_ALL}")
        print(f"Platform: {Fore.YELLOW}{platform}{Style.RESET_ALL}")
        print(f"Scan Duration: {result.get('scan_duration', 0):.2f}s")

        if "error" in result:
            self.print_status(f"Scan failed: {result['error']}", "error")
            return

        # Vulnerability summary
        severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        for vuln in vulnerabilities:
            severity = vuln.get("severity", "Low")
            severity_counts[severity] += 1

        total_vulns = sum(severity_counts.values())

        if total_vulns == 0:
            self.print_status("No vulnerabilities found!", "success")
        else:
            self.print_status(f"Found {total_vulns} vulnerabilities:", "warning")

            for severity, count in severity_counts.items():
                if count > 0:
                    color = {
                        "Critical": Fore.MAGENTA,
                        "High": Fore.RED,
                        "Medium": Fore.YELLOW,
                        "Low": Fore.BLUE,
                    }.get(severity, Fore.WHITE)

                    print(f"  {color}{severity}: {count}{Style.RESET_ALL}")

        # Security headers
        headers = result.get("security_headers", {})
        if headers:
            score = headers.get("security_score", "0/8")
            print(f"Security Headers Score: {score}")

        # SSL Analysis
        ssl_info = result.get("ssl_analysis", {})
        if ssl_info and "error" not in ssl_info:
            self.print_status("SSL/TLS configuration found", "success")
        elif ssl_info and "error" in ssl_info:
            self.print_status(f"SSL/TLS issues: {ssl_info['error']}", "warning")

        print()

    def save_results(self, results: Any, output_file: str, format: str = "json"):
        """Save results to file in specified format"""
        # Automatically save to reports directory if not already specified
        output_path = Path(output_file)
        if output_path.parent == Path('.'):
            output_path = Path("reports") / output_path
        
        output_path.parent.mkdir(parents=True, exist_ok=True)

        try:
            if format.lower() == "json":
                with open(output_path, "w", encoding="utf-8") as f:
                    json.dump(results, f, indent=2, ensure_ascii=False)

            elif format.lower() == "yaml":
                with open(output_path, "w", encoding="utf-8") as f:
                    yaml.dump(results, f, default_flow_style=False, allow_unicode=True)

            elif format.lower() == "txt":
                with open(output_path, "w", encoding="utf-8") as f:
                    if isinstance(results, list):
                        for result in results:
                            report = self.scanner.generate_text_report(result)
                            f.write(report + "\n" + "=" * 80 + "\n\n")
                    else:
                        report = self.scanner.generate_text_report(results)
                        f.write(report)

            self.print_status(f"Results saved to: {output_path}", "success")

        except Exception as e:
            self.print_status(f"Error saving results: {str(e)}", "error")

    def load_urls_from_file(self, file_path: str) -> List[str]:
        """Load URLs from a text file (one URL per line)"""
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                urls = [
                    line.strip()
                    for line in f
                    if line.strip() and not line.startswith("#")
                ]

            self.print_status(f"Loaded {len(urls)} URLs from {file_path}", "success")
            return urls

        except Exception as e:
            self.print_status(f"Error loading URLs from file: {str(e)}", "error")
            return []

    def load_config(self, config_path: str) -> Dict[str, Any]:
        """Load configuration from YAML file"""
        try:
            with open(config_path, "r", encoding="utf-8") as f:
                config = yaml.safe_load(f)

            self.print_status(f"Configuration loaded from {config_path}", "success")
            return config

        except Exception as e:
            self.print_status(f"Error loading configuration: {str(e)}", "error")
            return {}

    def run_comparative_analysis(self, results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Run comparative analysis across multiple platforms"""
        self.print_status("Generating comparative analysis...", "info")

        platforms = {}
        total_vulns = 0

        for result in results:
            if "error" in result:
                continue

            platform = result.get("platform_type", "unknown")
            vulns = result.get("vulnerabilities", [])

            if platform not in platforms:
                platforms[platform] = {
                    "urls": [],
                    "vulnerabilities": [],
                    "avg_severity": 0,
                    "security_scores": [],
                }

            platforms[platform]["urls"].append(result.get("url", ""))
            platforms[platform]["vulnerabilities"].extend(vulns)
            total_vulns += len(vulns)

            # Add security score if available
            headers = result.get("security_headers", {})
            if "security_score" in headers:
                score_parts = headers["security_score"].split("/")
                if len(score_parts) == 2:
                    score = int(score_parts[0]) / int(score_parts[1]) * 100
                    platforms[platform]["security_scores"].append(score)

        # Calculate averages and statistics
        for platform_data in platforms.values():
            vulns = platform_data["vulnerabilities"]
            severity_weights = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}

            if vulns:
                avg_severity = sum(
                    severity_weights.get(v.get("severity", "Low"), 1) for v in vulns
                ) / len(vulns)
                platform_data["avg_severity"] = round(avg_severity, 2)

            if platform_data["security_scores"]:
                platform_data["avg_security_score"] = round(
                    sum(platform_data["security_scores"])
                    / len(platform_data["security_scores"]),
                    2,
                )

        comparative_data = {
            "analysis_timestamp": datetime.now().isoformat(),
            "total_platforms": len(platforms),
            "total_urls_scanned": len(results),
            "total_vulnerabilities": total_vulns,
            "platform_breakdown": platforms,
            "summary": {
                "most_secure_platform": min(
                    platforms.keys(), key=lambda p: len(platforms[p]["vulnerabilities"])
                )
                if platforms
                else None,
                "least_secure_platform": max(
                    platforms.keys(), key=lambda p: len(platforms[p]["vulnerabilities"])
                )
                if platforms
                else None,
                "average_vulns_per_platform": round(total_vulns / len(platforms), 2)
                if platforms
                else 0,
            },
        }

        return comparative_data

    def print_comparative_summary(self, comparative_data: Dict[str, Any]):
        """Print summary of comparative analysis"""
        print(f"\n{Fore.CYAN}═══ Comparative Analysis Summary ═══{Style.RESET_ALL}")

        summary = comparative_data.get("summary", {})
        print(f"Total Platforms Analyzed: {comparative_data.get('total_platforms', 0)}")
        print(f"Total URLs Scanned: {comparative_data.get('total_urls_scanned', 0)}")
        print(
            f"Total Vulnerabilities Found: {comparative_data.get('total_vulnerabilities', 0)}"
        )

        if summary.get("most_secure_platform"):
            print(
                f"{Fore.GREEN}Most Secure Platform: {summary['most_secure_platform'].title()}{Style.RESET_ALL}"
            )

        if summary.get("least_secure_platform"):
            print(
                f"{Fore.RED}Least Secure Platform: {summary['least_secure_platform'].title()}{Style.RESET_ALL}"
            )

        print(
            f"Average Vulnerabilities per Platform: {summary.get('average_vulns_per_platform', 0)}"
        )

        # Platform breakdown
        platforms = comparative_data.get("platform_breakdown", {})
        for platform, data in platforms.items():
            vuln_count = len(data["vulnerabilities"])
            avg_score = data.get("avg_security_score", "N/A")
            print(f"\n{Fore.YELLOW}{platform.title()}:{Style.RESET_ALL}")
            print(f"  URLs: {len(data['urls'])}")
            print(f"  Vulnerabilities: {vuln_count}")
            print(f"  Avg Security Score: {avg_score}%")

    def enhance_scan_results(self, basic_results):
        """Enhance basic scan results with professional structure"""
        return {
            "scan_metadata": {
                "url": basic_results.get("url", ""),
                "timestamp": basic_results.get("timestamp", datetime.now().isoformat()),
                "scanner_version": "2.0-Professional",
                "scan_type": "Comprehensive Security Assessment",
                "status_code": basic_results.get("status_code", 0),
                "response_time": basic_results.get("response_time", 0)
            },
            "platform_analysis": {
                "platform_type": basic_results.get("platform_type", "unknown"),
                "technology_stack": [],
                "confidence_score": 0.9
            },
            "security_assessment": {
                "overall_score": self.calculate_score(basic_results),
                "risk_level": self.determine_risk(basic_results),
                "compliance_status": {"OWASP": "Partial", "NIST": "Partial"},
                "vulnerabilities": basic_results.get("vulnerabilities", []),
                "security_headers": basic_results.get("security_headers", {}),
                "ssl_tls_analysis": basic_results.get("ssl_analysis", {})
            },
            "executive_summary": self.generate_summary(basic_results)
        }

    def calculate_score(self, results):
        """Calculate security score"""
        score = 100
        vulns = results.get("vulnerabilities", [])
        for v in vulns:
            if v.get("severity") == "Critical": score -= 25
            elif v.get("severity") == "High": score -= 15
            elif v.get("severity") == "Medium": score -= 10
            elif v.get("severity") == "Low": score -= 5
        return max(0, score)

    def determine_risk(self, results):
        """Determine risk level"""
        score = self.calculate_score(results)
        if score >= 80: return "Low"
        elif score >= 60: return "Medium"
        elif score >= 40: return "High"
        else: return "Critical"

    def generate_summary(self, results):
        """Generate executive summary"""
        vulns = results.get("vulnerabilities", [])
        return {
            "critical_findings": len([v for v in vulns if v.get("severity") == "Critical"]),
            "high_risk_issues": len([v for v in vulns if v.get("severity") == "High"]),
            "medium_risk_issues": len([v for v in vulns if v.get("severity") == "Medium"]),
            "low_risk_issues": len([v for v in vulns if v.get("severity") == "Low"]),
            "immediate_actions_required": ["Review and remediate identified vulnerabilities"],
            "strategic_recommendations": ["Implement comprehensive security headers"]
        }

    def generate_enhanced_report(self, results, output_file):
        """Generate enhanced professional HTML report"""
        self.print_status("📊 Enhancing results...", "info")
        enhanced_results = self.enhance_scan_results(results)
        
        self.print_status("📄 Generating professional HTML report...", "info")
        html_path = self.report_generator.generate_report(enhanced_results, output_file)
        
        self.print_status(f"✅ Report generated: {html_path}", "success")
        self.print_status(f"🎯 Security Score: {enhanced_results['security_assessment']['overall_score']}/100", "info")
        self.print_status(f"⚠️  Risk Level: {enhanced_results['security_assessment']['risk_level']}", "info")
        
        return html_path


def main():
    parser = argparse.ArgumentParser(
        description="Low-Code Platform Security Scanner - Bachelor Thesis Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan a single URL
  python cli.py --url https://example.bubbleapps.io/app

  # Scan multiple URLs from file
  python cli.py --batch urls.txt

  # Use configuration file
  python cli.py --config config.yaml

  # Generate enhanced professional report
  python cli.py --url https://example.com --enhanced

  # Generate comparative analysis
  python cli.py --batch urls.txt --comparative --output reports/comparative.json

  # Specify output format
  python cli.py --url https://example.com --format txt --output report.txt

  # Verbose output with detailed vulnerability information
  python cli.py --url https://example.com --verbose
        """,
    )

    # Input options
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument("--url", "-u", help="Single URL to scan")
    input_group.add_argument(
        "--batch", "-b", help="File containing URLs to scan (one per line)"
    )
    input_group.add_argument("--config", "-c", help="Configuration file (YAML)")

    # Output options
    parser.add_argument("--output", "-o", help="Output file path (default: reports/)")
    parser.add_argument(
        "--format",
        "-f",
        choices=["json", "yaml", "txt", "html"],
        default="json",
        help="Output format (default: json)",
    )

    # Analysis options
    parser.add_argument(
        "--comparative",
        action="store_true",
        help="Generate comparative analysis across platforms",
    )
    parser.add_argument(
        "--enhanced",
        action="store_true",
        help="Generate enhanced professional HTML report with security scoring",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Verbose output with detailed information",
    )
    parser.add_argument(
        "--no-color", action="store_true", help="Disable colored output"
    )

    # Scanner options
    parser.add_argument(
        "--timeout",
        type=int,
        default=10,
        help="Request timeout in seconds (default: 10)",
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=2.0,
        help="Delay between requests in seconds (default: 2.0)",
    )
    parser.add_argument("--user-agent", help="Custom User-Agent string")

    args = parser.parse_args()

    # Disable colors if requested
    if args.no_color:
        init(strip=True, convert=False)

    cli = SecurityScannerCLI()

    # Configure scanner based on CLI options
    if args.user_agent:
        cli.scanner.session.headers.update({"User-Agent": args.user_agent})

    cli.print_banner()

    results = []

    try:
        if args.url:
            # Single URL scan
            result = cli.scan_single_url(args.url, args.format)
            results = [result]

        elif args.batch:
            # Batch URL scan
            urls = cli.load_urls_from_file(args.batch)
            if urls:
                results = cli.scan_batch_urls(urls, args.format)

        elif args.config:
            # Configuration-based scan
            config = cli.load_config(args.config)
            if config:
                targets = config.get("targets", {})
                all_urls = []

                for platform, urls in targets.items():
                    if isinstance(urls, list):
                        all_urls.extend(urls)

                if all_urls:
                    results = cli.scan_batch_urls(all_urls, args.format)

        # Generate enhanced report if requested
        if args.enhanced and len(results) == 1:
            # Enhanced reporting only works with single URL scans
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            if args.output:
                enhanced_filename = args.output
                if not enhanced_filename.endswith(".html"):
                    name, ext = (
                        enhanced_filename.rsplit(".", 1)
                        if "." in enhanced_filename
                        else (enhanced_filename, "")
                    )
                    enhanced_filename = f"{name}_enhanced.html"
            else:
                url = results[0].get("url", "scan")
                domain = urlparse(url).netloc.replace(":", "_")
                enhanced_filename = f"reports/enhanced_{domain}_{timestamp}.html"
            
            cli.generate_enhanced_report(results[0], enhanced_filename)

        # Generate comparative analysis if requested
        if args.comparative and len(results) > 1:
            comparative_data = cli.run_comparative_analysis(results)
            cli.print_comparative_summary(comparative_data)

            if args.output:
                # Save comparative analysis
                comparative_filename = args.output
                if not comparative_filename.endswith(f".{args.format}"):
                    name, ext = (
                        comparative_filename.rsplit(".", 1)
                        if "." in comparative_filename
                        else (comparative_filename, "")
                    )
                    comparative_filename = f"{name}_comparative.{args.format}"

                cli.save_results(comparative_data, comparative_filename, args.format)

        # Save individual results if output specified
        if results:
            if args.output:
                # Use specified output file
                if len(results) == 1:
                    cli.save_results(results[0], args.output, args.format)
                else:
                    cli.save_results(results, args.output, args.format)
            else:
                # Generate default output filename
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                if len(results) == 1:
                    # Single URL - use domain as filename
                    url = results[0].get("url", "scan")
                    domain = urlparse(url).netloc.replace(":", "_")
                    default_filename = f"scan_{domain}_{timestamp}.{args.format}"
                    cli.save_results(results[0], default_filename, args.format)
                    cli.print_status(f"Results saved to: reports/{default_filename}", "info")
                else:
                    # Multiple URLs - batch scan
                    default_filename = f"batch_scan_{timestamp}.{args.format}"
                    cli.save_results(results, default_filename, args.format)
                    cli.print_status(f"Results saved to: reports/{default_filename}", "info")

        # Print final summary
        if results:
            total_vulns = sum(
                len(r.get("vulnerabilities", [])) for r in results if "error" not in r
            )
            successful_scans = len([r for r in results if "error" not in r])
            failed_scans = len([r for r in results if "error" in r])

            print(f"\n{Fore.CYAN}═══ Final Summary ═══{Style.RESET_ALL}")
            cli.print_status(f"Successful scans: {successful_scans}", "success")
            if failed_scans > 0:
                cli.print_status(f"Failed scans: {failed_scans}", "warning")
            cli.print_status(f"Total vulnerabilities found: {total_vulns}", "info")

            if total_vulns == 0:
                cli.print_status(
                    "🎉 No vulnerabilities found across all scans!", "success"
                )
            elif total_vulns < 5:
                cli.print_status("Overall security posture appears good", "success")
            elif total_vulns < 15:
                cli.print_status(
                    "Some security concerns identified - review recommended", "warning"
                )
            else:
                cli.print_status(
                    "Multiple security issues found - immediate attention required",
                    "error",
                )

    except KeyboardInterrupt:
        cli.print_status("Scan interrupted by user", "warning")
        sys.exit(1)

    except Exception as e:
        cli.print_status(f"Unexpected error: {str(e)}", "error")
        if args.verbose:
            import traceback

            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
