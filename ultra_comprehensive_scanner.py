#!/usr/bin/env python3
"""
Ultra-Comprehensive Low-Code Platform Security Scanner CLI

Command-line interface for the advanced enterprise-grade security scanner
that detects vulnerabilities across 40+ low-code platforms with AI/ML capabilities,
real-time monitoring, and multi-framework compliance assessment.

Usage:
    python ultra_comprehensive_scanner.py <url> [options]

Examples:
    python ultra_comprehensive_scanner.py https://myapp.bubbleapps.io
    python ultra_comprehensive_scanner.py https://myapp.airtable.com --platform airtable --format html
    python ultra_comprehensive_scanner.py https://myapp.outsystems.com --profile enterprise --schedule 24
    python ultra_comprehensive_scanner.py https://myapp.bubbleapps.io --ml-enabled --monitor
"""

import argparse
import sys
import json
import time
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, Any
import threading
import signal

from src.website_security_scanner.analyzers.ultra_low_code_scanner import UltraLowCodePlatformScanner, ultra_scan_low_code_platform


class UltraScannerCLI:
    """Command-line interface for ultra-comprehensive scanner."""

    def __init__(self):
        self.scanner: Optional[UltraLowCodePlatformScanner] = None
        self.running = True

    def create_parser(self) -> argparse.ArgumentParser:
        """Create argument parser."""
        parser = argparse.ArgumentParser(
            description="🚀 Ultra-Comprehensive Low-Code Platform Security Scanner v3.0",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Examples:
  %(prog)s https://myapp.bubbleapps.io
  %(prog)s https://myapp.airtable.com --platform airtable --format html
  %(prog)s https://myapp.outsystems.com --profile enterprise --schedule 24
  %(prog)s https://myapp.bubbleapps.io --ml-enabled --monitor --compliance owasp_top_10,nist_800_53
            """
        )

        # Required arguments
        parser.add_argument(
            'url',
            help='Target URL to scan'
        )

        # Platform detection
        parser.add_argument(
            '--platform',
            '-p',
            help='Platform hint (bubble, airtable, outsystems, etc.)'
        )

        # Scan profiles
        parser.add_argument(
            '--profile',
            choices=['quick', 'standard', 'comprehensive', 'enterprise'],
            default='comprehensive',
            help='Scan profile (default: comprehensive)'
        )

        # Output options
        parser.add_argument(
            '--format',
            '-f',
            choices=['json', 'html', 'pdf', 'xml', 'yaml'],
            default='html',
            help='Output format (default: html)'
        )

        parser.add_argument(
            '--output',
            '-o',
            help='Output filename (auto-generated if not specified)'
        )

        # Advanced features
        parser.add_argument(
            '--ml-enabled',
            action='store_true',
            help='Enable AI/ML-powered detection (requires scikit-learn)'
        )

        parser.add_argument(
            '--parallel',
            action='store_true',
            default=True,
            help='Enable parallel scanning (default: enabled)'
        )

        parser.add_argument(
            '--compliance',
            help='Compliance frameworks (comma-separated: owasp_top_10,nist_800_53,iso_27001,soc_2,pci_dss,gdpr,hipaa)'
        )

        # Monitoring and scheduling
        parser.add_argument(
            '--monitor',
            action='store_true',
            help='Enable real-time monitoring mode'
        )

        parser.add_argument(
            '--schedule',
            type=int,
            help='Schedule recurring scans (interval in hours)'
        )

        # Configuration
        parser.add_argument(
            '--config',
            help='Path to configuration file'
        )

        parser.add_argument(
            '--workers',
            type=int,
            default=10,
            help='Number of worker threads (default: 10)'
        )

        parser.add_argument(
            '--timeout',
            type=int,
            default=30,
            help='Request timeout in seconds (default: 30)'
        )

        # Information options
        parser.add_argument(
            '--list-platforms',
            action='store_true',
            help='List all supported platforms and exit'
        )

        parser.add_argument(
            '--list-compliance',
            action='store_true',
            help='List all compliance frameworks and exit'
        )

        parser.add_argument(
            '--history',
            action='store_true',
            help='Show scan history and exit'
        )

        parser.add_argument(
            '--stats',
            action='store_true',
            help='Show platform statistics and exit'
        )

        # Verbosity
        parser.add_argument(
            '--verbose',
            '-v',
            action='store_true',
            help='Enable verbose output'
        )

        parser.add_argument(
            '--quiet',
            '-q',
            action='store_true',
            help='Quiet mode (minimal output)'
        )

        return parser

    def list_platforms(self):
        """List all supported platforms."""
        print("🔧 Ultra-Comprehensive Low-Code Platform Security Scanner")
        print("=" * 70)
        print("📋 Supported Platforms (40+ platforms across 8 categories):")
        print()

        categories = {}
        for platform, info in UltraLowCodePlatformScanner.SUPPORTED_PLATFORMS.items():
            category = info.get('category', 'other')
            if category not in categories:
                categories[category] = []
            categories[category].append((platform, info))

        for category, platforms in categories.items():
            print(f"🏗️  {category.upper().replace('_', ' ')} PLATFORMS:")
            for platform, info in platforms:
                enterprise = "⭐" if info.get('enterprise', False) else ""
                print(f"   • {platform} - {info['name']} {enterprise}")
                print(f"     Domains: {', '.join(info['domains'])}")
                print(f"     Indicators: {', '.join(info.get('indicators', []))}")
            print()

        print(f"📊 Total Platforms: {len(UltraLowCodePlatformScanner.SUPPORTED_PLATFORMS)}")
        print("⭐ = Enterprise-grade platform")

    def list_compliance_frameworks(self):
        """List all compliance frameworks."""
        print("🔧 Ultra-Comprehensive Low-Code Platform Security Scanner")
        print("=" * 70)
        print("📋 Supported Compliance Frameworks:")
        print()

        for framework_key, framework_info in UltraLowCodePlatformScanner.COMPLIANCE_FRAMEWORKS.items():
            print(f"🏛️  {framework_info['name']} ({framework_key})")
            print(f"   Description: {framework_info['description']}")
            print(f"   Categories: {len(framework_info['categories'])}")
            print(f"   Category List: {', '.join(framework_info['categories'][:5])}{'...' if len(framework_info['categories']) > 5 else ''}")
            print()

        print(f"📊 Total Frameworks: {len(UltraLowCodePlatformScanner.COMPLIANCE_FRAMEWORKS)}")

    def show_history(self, limit: int = 20):
        """Show scan history."""
        if not self.scanner:
            self.scanner = UltraLowCodePlatformScanner()

        print("🔧 Ultra-Comprehensive Low-Code Platform Security Scanner")
        print("=" * 70)
        print("📚 Scan History:")
        print()

        history = self.scanner.get_scan_history(limit=limit)

        if not history:
            print("No scan history found.")
            return

        for scan in history:
            status_emoji = {
                'completed': '✅',
                'failed': '❌',
                'running': '🔄'
            }.get(scan.get('status', 'unknown'), '❓')

            print(f"{status_emoji} {scan['id'][:8]} - {scan['url']}")
            print(f"   Started: {scan.get('start_time', 'Unknown')}")
            print(f"   Status: {scan.get('status', 'Unknown')}")
            print(f"   Vulnerabilities: {scan.get('vulnerability_count', 0)}")
            print(f"   Severity Score: {scan.get('severity_score', 0):.2f}")
            print(f"   Compliance Score: {scan.get('compliance_score', 0):.1f}%")
            print()

    def show_stats(self):
        """Show platform statistics."""
        if not self.scanner:
            self.scanner = UltraLowCodePlatformScanner()

        print("🔧 Ultra-Comprehensive Low-Code Platform Security Scanner")
        print("=" * 70)
        print("📊 Platform Statistics:")
        print()

        stats = self.scanner.get_platform_statistics()

        if not stats['platform_statistics']:
            print("No platform statistics available.")
            return

        for stat in stats['platform_statistics']:
            print(f"🏗️  {stat['platform']}")
            print(f"   Total Scans: {stat.get('total_scans', 0)}")
            print(f"   Avg Vulnerabilities: {stat.get('avg_vulnerabilities', 0):.1f}")
            print(f"   Avg Severity: {stat.get('avg_severity', 0):.2f}")
            print(f"   Last Scan: {stat.get('last_scan', 'Never')}")
            print()

    def run_scan(self, args):
        """Run the ultra-comprehensive scan."""
        print("🚀 Ultra-Comprehensive Low-Code Platform Security Scanner v3.0")
        print("=" * 70)
        print(f"🎯 Target URL: {args.url}")
        if args.platform:
            print(f"🔍 Platform Hint: {args.platform}")
        print(f"📊 Scan Profile: {args.profile}")
        print(f"📋 Output Format: {args.format}")
        print()

        # Configure scanner
        config = {
            'max_workers': args.workers,
            'timeout': args.timeout,
            'ml_enabled': args.ml_enabled,
            'parallel_scanning': args.parallel,
            'scan_depth': args.profile
        }

        if args.compliance:
            config['compliance_frameworks'] = [f.strip() for f in args.compliance.split(',')]

        # Initialize scanner
        self.scanner = UltraLowCodePlatformScanner(config=config)

        # Setup monitoring if requested
        if args.monitor:
            self.setup_monitoring(args.url, args.platform)

        # Setup scheduling if requested
        if args.schedule:
            self.setup_scheduling(args.url, args.schedule, args.platform)
            return  # Don't run immediate scan if scheduling

        # Run the scan
        start_time = time.time()

        try:
            if not args.quiet:
                print("🔄 Starting ultra-comprehensive scan...")
                print("   This may take several minutes depending on the target and profile...")
                print()

            results = self.scanner.ultra_comprehensive_scan(
                args.url,
                args.platform,
                args.profile
            )

            scan_time = time.time() - start_time

            # Display results summary
            self.display_scan_summary(results, scan_time)

            # Export results
            output_file = self.export_results(results, args)

            if not args.quiet:
                print(f"\n💾 Results exported to: {output_file}")

            # Schedule recurring scans if requested
            if args.schedule:
                print(f"\n⏰ Scheduled recurring scans every {args.schedule} hours")
                self.scanner.schedule_scan(args.url, args.schedule, args.platform)

                # Start scheduler in background
                scheduler_thread = threading.Thread(target=self.scanner.run_scheduler, daemon=True)
                scheduler_thread.start()

                print("Press Ctrl+C to stop monitoring...")
                try:
                    while self.running:
                        time.sleep(1)
                except KeyboardInterrupt:
                    print("\n⚠️  Monitoring stopped by user")

        except KeyboardInterrupt:
            print("\n⚠️  Scan interrupted by user")
        except Exception as e:
            print(f"\n❌ Error during scan: {str(e)}")
            if args.verbose:
                import traceback
                traceback.print_exc()

    def display_scan_summary(self, results: Dict, scan_time: float):
        """Display scan results summary."""
        metadata = results.get('scan_metadata', {})
        platform_detection = results.get('platform_detection', {})
        security_assessment = results.get('security_assessment', {})
        risk_summary = security_assessment.get('risk_summary', {})
        compliance = results.get('compliance_assessment', {})

        print("✅ Ultra-Comprehensive Scan Completed!")
        print(f"⏱️  Scan Time: {scan_time:.2f} seconds")
        print()

        # Platform detection
        platforms = platform_detection.get('detected_platforms', [])
        print(f"📊 Detected Platforms ({len(platforms)}):")
        if platforms:
            for platform in platforms:
                confidence = platform_detection.get('confidence_scores', {}).get(platform, 0)
                print(f"   • {platform} (confidence: {confidence:.1f})")
        else:
            print("   No platforms detected")
        print()

        # Security assessment
        print("🛡️  Security Assessment:")
        print(f"   Overall Level: {security_assessment.get('overall_security_level', 'Unknown')}")
        print(f"   Total Vulnerabilities: {risk_summary.get('total_vulnerabilities', 0)}")
        print(f"   Critical Issues: {risk_summary.get('critical_issues', 0)}")
        print(f"   High Risk Issues: {risk_summary.get('high_risk_issues', 0)}")
        print(f"   Medium Risk Issues: {risk_summary.get('medium_risk_issues', 0)}")
        print(f"   Low Risk Issues: {risk_summary.get('low_risk_issues', 0)}")
        print(f"   Average CVSS Score: {risk_summary.get('average_cvss_score', 0):.2f}")
        print()

        # Compliance overview
        if compliance:
            print("📋 Compliance Assessment:")
            for framework, data in compliance.items():
                compliance_score = data.get('overall_compliance', 0)
                compliant_cats = data.get('compliant_categories', 0)
                total_cats = data.get('total_categories', 0)
                print(f"   • {framework}: {compliance_score:.1f}% ({compliant_cats}/{total_cats} categories)")
            print()

        # Key recommendations
        recommendations = results.get('actionable_recommendations', [])[:3]
        if recommendations:
            print("🎯 Top Recommendations:")
            for i, rec in enumerate(recommendations, 1):
                print(f"   {i}. {rec.get('title', 'No title')}")
            print()

    def export_results(self, results: Dict, args) -> str:
        """Export scan results."""
        if args.output:
            filename = args.output
        else:
            # Auto-generate filename
            domain = args.url.replace('https://', '').replace('http://', '').replace('/', '_').replace('.', '_')
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"ultra_scan_{domain}_{timestamp}.{args.format}"

        self.scanner.export_results(results, filename, args.format)
        return filename

    def setup_monitoring(self, url: str, platform_hint: Optional[str]):
        """Setup real-time monitoring."""
        print("🔍 Real-time monitoring enabled")
        self.scanner.monitoring_targets.add(url)

    def setup_scheduling(self, url: str, interval_hours: int, platform_hint: Optional[str]):
        """Setup scan scheduling."""
        print(f"⏰ Scheduling recurring scans every {interval_hours} hours")
        self.scanner.schedule_scan(url, interval_hours, platform_hint)

    def signal_handler(self, signum, frame):
        """Handle interrupt signals."""
        print("\n⚠️  Received interrupt signal, shutting down gracefully...")
        self.running = False

    def main(self):
        """Main CLI entry point."""
        parser = self.create_parser()
        args = parser.parse_args()

        # Setup signal handlers
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)

        try:
            # Handle informational commands
            if args.list_platforms:
                self.list_platforms()
                return

            if args.list_compliance:
                self.list_compliance_frameworks()
                return

            if args.history:
                self.show_history()
                return

            if args.stats:
                self.show_stats()
                return

            # Run the scan
            if not args.url:
                parser.error("URL is required for scanning")

            self.run_scan(args)

        except Exception as e:
            print(f"❌ Fatal error: {str(e)}")
            if args.verbose:
                import traceback
                traceback.print_exc()
            sys.exit(1)


def main():
    """Entry point for the CLI."""
    cli = UltraScannerCLI()
    cli.main()


if __name__ == "__main__":
    main()