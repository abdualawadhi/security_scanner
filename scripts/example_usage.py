#!/usr/bin/env python3
"""
Example Usage Script for Low-Code Platform Security Scanner
Bachelor Thesis: Low-Code Platforms for E-commerce: Comparative Security Analysis

This script demonstrates various ways to use the security scanner for analyzing
low-code platforms including Bubble.io, OutSystems, and Airtable applications.

Author: Bachelor Thesis Project
"""

import json
import time
from datetime import datetime
from pathlib import Path

from main import LowCodeSecurityScanner


def example_single_scan():
    """Example: Scanning a single URL"""
    print("=" * 60)
    print("Example 1: Single URL Security Scan")
    print("=" * 60)

    scanner = LowCodeSecurityScanner()

    # Example Bubble.io application
    url = "https://amqmalawadhi-85850.bubbleapps.io/version-test/"

    print(f"Scanning: {url}")

    try:
        result = scanner.scan_target(url)

        # Display summary
        print(f"Platform Type: {result.get('platform_type', 'Unknown').title()}")
        print(f"Status Code: {result.get('status_code', 'Unknown')}")
        print(f"Response Time: {result.get('response_time', 0):.2f}s")

        vulnerabilities = result.get("vulnerabilities", [])
        print(f"Vulnerabilities Found: {len(vulnerabilities)}")

        if vulnerabilities:
            print("\nTop 3 Vulnerabilities:")
            for i, vuln in enumerate(vulnerabilities[:3], 1):
                print(
                    f"  {i}. {vuln.get('type', 'Unknown')} ({vuln.get('severity', 'Low')})"
                )
                print(f"     {vuln.get('description', 'No description')[:80]}...")

        # Save detailed results
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = f"single_scan_result_{timestamp}.json"

        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2, ensure_ascii=False)

        print(f"\nDetailed results saved to: {output_file}")

    except Exception as e:
        print(f"Error during scan: {e}")


def example_batch_scan():
    """Example: Scanning multiple URLs"""
    print("\n" + "=" * 60)
    print("Example 2: Batch URL Security Scan")
    print("=" * 60)

    scanner = LowCodeSecurityScanner()

    # Example URLs for different platforms
    urls = [
        "https://amqmalawadhi-85850.bubbleapps.io/version-test/",
        "https://personal-7hwwkk2j-dev.outsystems.app/UST/",
        "https://airtable.com/app5oLkwSi8gaXUod/",
    ]

    results = []

    print(f"Scanning {len(urls)} URLs...")

    for i, url in enumerate(urls, 1):
        print(f"\nScanning {i}/{len(urls)}: {url}")

        try:
            result = scanner.scan_target(url)
            results.append(result)

            # Quick summary
            platform = result.get("platform_type", "unknown").title()
            vuln_count = len(result.get("vulnerabilities", []))
            print(f"  Platform: {platform}")
            print(f"  Vulnerabilities: {vuln_count}")

        except Exception as e:
            print(f"  Error: {e}")
            results.append(
                {"url": url, "error": str(e), "timestamp": datetime.now().isoformat()}
            )

        # Be respectful with delays
        if i < len(urls):
            print("  Waiting...")
            time.sleep(2)

    # Save batch results
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = f"batch_scan_results_{timestamp}.json"

    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)

    print(f"\nBatch results saved to: {output_file}")

    return results


def example_comparative_analysis(results=None):
    """Example: Comparative analysis across platforms"""
    print("\n" + "=" * 60)
    print("Example 3: Comparative Platform Analysis")
    print("=" * 60)

    if not results:
        print("No results provided, generating sample data...")
        return

    # Analyze results by platform
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
                "avg_security_score": 0,
            }

        platforms[platform]["urls"].append(result.get("url", ""))
        platforms[platform]["vulnerabilities"].extend(vulns)
        total_vulns += len(vulns)

    print("Platform Comparison Summary:")
    print("-" * 40)

    for platform, data in platforms.items():
        vuln_count = len(data["vulnerabilities"])
        url_count = len(data["urls"])

        print(f"\n{platform.title()} Platform:")
        print(f"  Applications Analyzed: {url_count}")
        print(f"  Total Vulnerabilities: {vuln_count}")
        print(
            f"  Average per App: {vuln_count / url_count:.1f}"
            if url_count > 0
            else "  Average per App: 0"
        )

        # Show severity breakdown
        severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        for vuln in data["vulnerabilities"]:
            severity = vuln.get("severity", "Low")
            severity_counts[severity] += 1

        if vuln_count > 0:
            print("  Severity Breakdown:")
            for severity, count in severity_counts.items():
                if count > 0:
                    percentage = (count / vuln_count) * 100
                    print(f"    {severity}: {count} ({percentage:.1f}%)")

    # Overall analysis
    print(f"\nOverall Analysis:")
    print(f"Total Vulnerabilities Found: {total_vulns}")

    if platforms:
        most_secure = min(
            platforms.keys(), key=lambda p: len(platforms[p]["vulnerabilities"])
        )
        least_secure = max(
            platforms.keys(), key=lambda p: len(platforms[p]["vulnerabilities"])
        )

        print(f"Most Secure Platform: {most_secure.title()}")
        print(f"Least Secure Platform: {least_secure.title()}")

    # Save comparative analysis
    comparative_data = {
        "analysis_timestamp": datetime.now().isoformat(),
        "platforms": platforms,
        "total_vulnerabilities": total_vulns,
        "summary": {
            "most_secure_platform": most_secure if platforms else None,
            "least_secure_platform": least_secure if platforms else None,
        },
    }

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = f"comparative_analysis_{timestamp}.json"

    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(comparative_data, f, indent=2, ensure_ascii=False)

    print(f"\nComparative analysis saved to: {output_file}")


def example_custom_analysis():
    """Example: Custom analysis with specific focus"""
    print("\n" + "=" * 60)
    print("Example 4: Custom Security Analysis")
    print("=" * 60)

    scanner = LowCodeSecurityScanner()

    # Focus on specific security aspects
    url = "https://amqmalawadhi-85850.bubbleapps.io/version-test/"

    print(f"Performing focused analysis on: {url}")
    print("Focus areas: API security, authentication, data exposure")

    try:
        result = scanner.scan_target(url)

        # Filter for specific vulnerability types
        api_vulns = []
        auth_vulns = []
        data_vulns = []

        for vuln in result.get("vulnerabilities", []):
            vuln_type = vuln.get("type", "").lower()

            if any(keyword in vuln_type for keyword in ["api", "endpoint", "workflow"]):
                api_vulns.append(vuln)
            elif any(keyword in vuln_type for keyword in ["auth", "session", "token"]):
                auth_vulns.append(vuln)
            elif any(
                keyword in vuln_type for keyword in ["data", "exposure", "disclosure"]
            ):
                data_vulns.append(vuln)

        print(f"\nFocused Analysis Results:")
        print(f"API Security Issues: {len(api_vulns)}")
        print(f"Authentication Issues: {len(auth_vulns)}")
        print(f"Data Exposure Issues: {len(data_vulns)}")

        # Detailed breakdown
        if api_vulns:
            print("\nAPI Security Concerns:")
            for vuln in api_vulns:
                print(
                    f"  - {vuln.get('type', 'Unknown')} ({vuln.get('severity', 'Low')})"
                )

        if auth_vulns:
            print("\nAuthentication Concerns:")
            for vuln in auth_vulns:
                print(
                    f"  - {vuln.get('type', 'Unknown')} ({vuln.get('severity', 'Low')})"
                )

        if data_vulns:
            print("\nData Exposure Concerns:")
            for vuln in data_vulns:
                print(
                    f"  - {vuln.get('type', 'Unknown')} ({vuln.get('severity', 'Low')})"
                )

        # Generate focused recommendations
        recommendations = []
        if api_vulns:
            recommendations.append(
                "Implement proper API authentication and access controls"
            )
        if auth_vulns:
            recommendations.append(
                "Review authentication mechanisms and session management"
            )
        if data_vulns:
            recommendations.append("Audit data exposure and implement privacy controls")

        if recommendations:
            print("\nKey Recommendations:")
            for i, rec in enumerate(recommendations, 1):
                print(f"  {i}. {rec}")
        else:
            print("\n✅ No major issues found in focused areas!")

    except Exception as e:
        print(f"Error during focused analysis: {e}")


def example_report_generation(results=None):
    """Example: Generating different report formats"""
    print("\n" + "=" * 60)
    print("Example 5: Report Generation")
    print("=" * 60)

    if not results:
        print("No results available for report generation")
        return

    scanner = LowCodeSecurityScanner()
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    print("Generating reports in multiple formats...")

    # Generate JSON report
    json_file = f"security_report_{timestamp}.json"
    with open(json_file, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    print(f"✓ JSON report: {json_file}")

    # Generate text reports for each result
    for i, result in enumerate(results):
        if "error" not in result:
            platform = result.get("platform_type", "unknown")
            text_report = scanner.generate_text_report(result)

            text_file = f"text_report_{platform}_{timestamp}_{i + 1}.txt"
            with open(text_file, "w", encoding="utf-8") as f:
                f.write(text_report)
            print(f"✓ Text report: {text_file}")

    # Generate summary report
    summary_file = f"summary_report_{timestamp}.txt"
    with open(summary_file, "w", encoding="utf-8") as f:
        f.write("SECURITY ANALYSIS SUMMARY REPORT\n")
        f.write("=" * 50 + "\n\n")
        f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Total Applications Scanned: {len(results)}\n\n")

        for result in results:
            if "error" not in result:
                url = result.get("url", "Unknown")
                platform = result.get("platform_type", "unknown").title()
                vuln_count = len(result.get("vulnerabilities", []))

                f.write(f"Application: {url}\n")
                f.write(f"Platform: {platform}\n")
                f.write(f"Vulnerabilities: {vuln_count}\n")
                f.write("-" * 30 + "\n")

    print(f"✓ Summary report: {summary_file}")


def main():
    """Main example execution"""
    print("Low-Code Platform Security Scanner - Example Usage")
    print("Bachelor Thesis: Comparative Security Analysis")
    print("=" * 60)

    print("\nThis script demonstrates various scanner capabilities:")
    print("1. Single URL scanning")
    print("2. Batch URL scanning")
    print("3. Comparative platform analysis")
    print("4. Custom focused analysis")
    print("5. Report generation")

    print("\n" + "⚠" * 3 + " IMPORTANT NOTES " + "⚠" * 3)
    print("- Only scan applications you own or have permission to test")
    print("- The scanner is respectful with delays between requests")
    print("- Results are saved to files for further analysis")
    print("- This is for educational/research purposes")
    print("⚠" * 25)

    try:
        # Run examples
        example_single_scan()

        batch_results = example_batch_scan()

        if batch_results:
            example_comparative_analysis(batch_results)
            example_report_generation(batch_results)

        example_custom_analysis()

        print("\n" + "=" * 60)
        print("All examples completed successfully!")
        print("Check the generated files for detailed results.")
        print("=" * 60)

    except KeyboardInterrupt:
        print("\nExamples interrupted by user")
    except Exception as e:
        print(f"\nError running examples: {e}")


if __name__ == "__main__":
    main()
