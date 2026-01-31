#!/usr/bin/env python3
"""
Comprehensive Low-Code Platform Security Scanner Script

A command-line interface for the comprehensive low-code platform security scanner.
This script provides an easy way to scan multiple low-code platforms for security vulnerabilities.

Usage:
    python comprehensive_low_code_scanner.py <url> [options]

Author: Bachelor Thesis Project - Low-Code Platforms Security Analysis
"""

import argparse
import json
import sys
import os
from datetime import datetime
from urllib.parse import urlparse

# Add the src directory to the path so we can import our modules
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from website_security_scanner.analyzers.low_code_scanner import LowCodePlatformScanner


def main():
    """Main function for the comprehensive low-code scanner CLI."""
    parser = argparse.ArgumentParser(
        description="Comprehensive Low-Code Platform Security Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python comprehensive_low_code_scanner.py https://myapp.bubbleapps.io
  python comprehensive_low_code_scanner.py https://myapp.outsystems.app --platform bubble
  python comprehensive_low_code_scanner.py https://myapp.com --output html --file results.html
  python comprehensive_low_code_scanner.py https://myapp.com --detect-only
        """
    )

    parser.add_argument('url', help='Target URL to scan')
    parser.add_argument(
        '--platform',
        '-p',
        help='Platform hint (bubble, outsystems, airtable, mern, etc.)'
    )
    parser.add_argument(
        '--output',
        '-o',
        choices=['json', 'html', 'text'],
        default='json',
        help='Output format (default: json)'
    )
    parser.add_argument(
        '--file',
        '-f',
        help='Output file path (default: auto-generated)'
    )
    parser.add_argument(
        '--detect-only',
        action='store_true',
        help='Only detect platform, do not perform full scan'
    )
    parser.add_argument(
        '--verbose',
        '-v',
        action='store_true',
        help='Verbose output'
    )
    parser.add_argument(
        '--list-platforms',
        action='store_true',
        help='List all supported platforms and exit'
    )

    args = parser.parse_args()

    # List supported platforms if requested
    if args.list_platforms:
        scanner = LowCodePlatformScanner()
        platforms = scanner.get_supported_platforms()

        print("Supported Low-Code Platforms:")
        print("=" * 40)
        for key, info in platforms.items():
            print(f"\n{key.upper()}:")
            print(f"  Name: {info['name']}")
            print(f"  Description: {info['description']}")
            print(f"  Domains: {', '.join(info['domains'])}")
        return

    # Validate URL
    try:
        parsed = urlparse(args.url)
        if not parsed.scheme or not parsed.netloc:
            print("Error: Invalid URL format. Please provide a valid URL (e.g., https://example.com)")
            return
    except Exception as e:
        print(f"Error: Invalid URL: {e}")
        return

    print("🔍 Comprehensive Low-Code Platform Security Scanner")
    print("=" * 60)
    print(f"Target URL: {args.url}")
    if args.platform:
        print(f"Platform Hint: {args.platform}")
    print(f"Output Format: {args.output}")
    print()

    try:
        # Initialize scanner
        scanner = LowCodePlatformScanner()

        if args.detect_only:
            # Platform detection only
            print("🔎 Detecting platform...")
            detection_results = scanner.detect_platform(args.url)

            print("\n📊 Platform Detection Results:")
            print("-" * 30)
            print(f"Detected Platforms: {', '.join(detection_results.get('detected_platforms', []))}")

            if detection_results.get('confidence_scores'):
                print("\nConfidence Scores:")
                for platform, score in detection_results['confidence_scores'].items():
                    print(".1f")

            if detection_results.get('recommendations'):
                print("\n💡 Platform-Specific Recommendations:")
                for rec in detection_results['recommendations'][:5]:  # Top 5
                    print(f"  • {rec}")

            return

        # Full comprehensive scan
        print("🔍 Starting comprehensive security scan...")
        print("This may take a few minutes depending on the target...")

        start_time = datetime.now()
        results = scanner.comprehensive_scan(args.url, args.platform)
        end_time = datetime.now()

        scan_duration = (end_time - start_time).total_seconds()

        # Display summary results
        print("\n✅ Scan completed!")
        print(f"Duration: {scan_duration:.1f} seconds")

        # Platform detection summary
        detection = results.get('platform_detection', {})
        platforms = detection.get('detected_platforms', [])
        print(f"\n📊 Detected Platforms: {', '.join(platforms) if platforms else 'None'}")

        # Security assessment summary
        assessment = results.get('security_assessment', {})
        security_level = assessment.get('overall_security_level', 'Unknown')
        risk_summary = assessment.get('risk_summary', {})

        print("\n🛡️  Security Assessment:")
        print(f"  Overall Security Level: {security_level}")
        print(f"  Total Vulnerabilities: {risk_summary.get('total_vulnerabilities', 0)}")
        print(f"  Critical Issues: {risk_summary.get('critical_issues', 0)}")
        print(f"  High Risk Issues: {risk_summary.get('high_risk_issues', 0)}")

        # OWASP Compliance
        compliance = assessment.get('compliance_status', {})
        print(f"  OWASP Compliance: {compliance.get('overall_compliance', 'Unknown')}")

        # Top vulnerabilities
        vulnerabilities = results.get('vulnerability_findings', [])
        if vulnerabilities:
            print("\n🚨 Top Vulnerabilities:")
            severity_order = {'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3, 'Info': 4}
            sorted_vulns = sorted(vulnerabilities, key=lambda v: severity_order.get(v.get('severity', 'Info'), 5))

            for i, vuln in enumerate(sorted_vulns[:5]):  # Top 5
                severity = vuln.get('severity', 'Info')
                vuln_type = vuln.get('type', 'Unknown')
                print(f"  {i+1}. [{severity}] {vuln_type}")

        # Top recommendations
        recommendations = results.get('recommendations', [])
        if recommendations:
            print("\n💡 Top Recommendations:")
            for i, rec in enumerate(recommendations[:3]):  # Top 3
                priority = rec.get('priority', 'Unknown')
                category = rec.get('category', 'Unknown')
                print(f"  {i+1}. [{priority}] {category}")

        # Generate output file
        if args.file:
            output_file = args.file
        else:
            # Auto-generate filename
            domain = urlparse(args.url).netloc.replace('.', '_')
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            output_file = f"low_code_scan_{domain}_{timestamp}.{args.output}"

        print(f"\n💾 Exporting results to: {output_file}")
        scanner.export_results(output_file, args.output)

        if args.output == 'html':
            print("🌐 Open the HTML file in your browser for a detailed report")

        print("\n🎯 Scan Summary:")
        print(f"   • Target: {args.url}")
        print(f"   • Platforms Detected: {len(platforms)}")
        print(f"   • Vulnerabilities Found: {len(vulnerabilities)}")
        print(f"   • Security Level: {security_level}")
        print(f"   • Report Saved: {output_file}")

    except KeyboardInterrupt:
        print("\n\n⚠️  Scan interrupted by user")
        return
    except Exception as e:
        print(f"\n❌ Error during scan: {str(e)}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return


if __name__ == "__main__":
    main()