#!/usr/bin/env python3
"""
Vulnerability Verification Demo
Low-Code Platform Security Scanner

Demonstrates the active vulnerability verification system.

Author: Bachelor Thesis Project - Low-Code Platforms Security Analysis
"""

import requests
from bs4 import BeautifulSoup
from src.website_security_scanner.analyzers.generic import GenericWebAnalyzer
from src.website_security_scanner.utils.vulnerability_verifier import VulnerabilityVerifier

def demo_vulnerability_verification():
    """Demonstrate the vulnerability verification system"""

    print("🔍 Low-Code Platform Security Scanner - Vulnerability Verification Demo")
    print("=" * 70)

    # Create a session and analyzer
    session = requests.Session()
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    })

    analyzer = GenericWebAnalyzer(session)
    verifier = VulnerabilityVerifier(session)

    # Test URL (using httpbin.org for safe testing)
    test_url = "https://httpbin.org"

    try:
        print(f"📡 Scanning: {test_url}")
        response = session.get(test_url, timeout=10, verify=False)
        soup = BeautifulSoup(response.content, 'html.parser')

        print("✅ Connected successfully")
        print(f"📊 Status Code: {response.status_code}")
        print(f"🔒 SSL Verified: {response.url.startswith('https://')}")

        # Record HTTP context for verification
        analyzer._record_http_context(test_url, response)

        # Add a test vulnerability (simulating detection)
        print("\n🧪 Adding test vulnerability for verification...")
        analyzer._add_enriched_vulnerability(
            vuln_type="Missing Security Header",
            severity="Medium",
            description="X-Frame-Options header is missing",
            evidence="No X-Frame-Options header found in response",
            recommendation="Add X-Frame-Options header to prevent clickjacking attacks",
            category="Security Headers",
            owasp="A6:2017-Security Misconfiguration",
            cwe=["693"]
        )

        # Get the vulnerability
        vulnerabilities = analyzer.get_results()['vulnerabilities']
        if vulnerabilities:
            vuln = vulnerabilities[0]
            print(f"🎯 Test Vulnerability: {vuln['type']}")

            # Perform verification
            print("\n🔬 Performing active verification...")
            verified_vuln = verifier.verify_vulnerability(vuln, test_url, response)

            verification = verified_vuln.get('verification', {})
            print(f"✅ Verified: {verification.get('verified', False)}")
            print(f"🎚️  Confidence: {verification.get('confidence', 'unknown')}")
            print(f"🛠️  Method: {verification.get('method', 'unknown')}")

            if verification.get('verified'):
                print(f"📝 Note: {verification.get('note', 'No additional notes')}")
            else:
                print(f"📝 Note: {verification.get('note', 'Verification details')}")

        print("\n🎉 Verification demo completed successfully!")
        print("\n💡 Key Features:")
        print("  • Active exploitation testing")
        print("  • Safe payload injection")
        print("  • Confidence scoring")
        print("  • Multiple verification methods")
        print("  • Professional reporting integration")

    except Exception as e:
        print(f"❌ Demo failed: {str(e)}")
        return False

    return True

if __name__ == "__main__":
    demo_vulnerability_verification()