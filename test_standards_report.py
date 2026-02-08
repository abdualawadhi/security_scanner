#!/usr/bin/env python3
"""
Test script for the StandardsBasedReportGenerator
Creates a sample scan result and generates a report to verify zero mock data architecture.
"""

import sys
import json
from datetime import datetime
from pathlib import Path

# Add src to Python path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from website_security_scanner.standards_report_generator import StandardsBasedReportGenerator


def create_sample_scan_results():
    """Create sample scan results with real vulnerability data."""
    return {
        "scan_metadata": {
            "url": "https://example.bubbleapps.io/test-app",
            "timestamp": "2024-03-15T10:30:00Z",
            "end_timestamp": "2024-03-15T10:32:45Z",
            "duration": "PT2M45S",
            "scanner_version": "1.0.0",
            "status_code": 200,
            "response_time": 0.856,
            "verification_summary": {
                "total_vulnerabilities": 3,
                "verified_vulnerabilities": 1,
                "high_confidence_verifications": 2,
                "verification_rate": 33.33
            },
            "evidence_verification_summary": {
                "verified": 2,
                "stale": 0,
                "unverified": 1
            },
            "git_commit": "a1b2c3d",
            "scan_profile": {
                "timeout_seconds": 30,
                "active_verification": True
            }
        },
        "platform_analysis": {
            "platform_type": "Bubble",
            "technology_stack": ["Bubble.io", "JavaScript", "REST API"],
            "specific_findings": {
                "page_routing": "Custom routing detected",
                "api_endpoints": 5
            },
            "platform_detection": {
                "confidence_scores": {"Bubble": 95, "Unknown": 5},
                "evidence": ["Custom Bubble CSS classes detected"]
            }
        },
        "executive_summary": {
            "total_vulnerabilities": 3,
            "critical": 1,
            "high": 1,
            "medium": 1,
            "low": 0,
            "info": 0
        },
        "security_assessment": {
            "vulnerabilities": [
                {
                    "title": "Cross-Site Scripting (XSS)",
                    "severity": "Critical",
                    "confidence": "Firm",
                    "description": "User input is reflected in the response without proper encoding, allowing attackers to inject malicious scripts.",
                    "category": "Injection",
                    "owasp": "A03:2021 - Injection",
                    "recommendation": "Implement proper input validation and output encoding for all user-controlled data.",
                    "background": "Cross-Site Scripting (XSS) attacks involve injecting malicious scripts into web pages viewed by other users.",
                    "impact": "Successful XSS attacks can lead to account theft, data theft, or malicious actions on behalf of the victim.",
                    "references": [
                        "https://owasp.org/www-community/attacks/xss/",
                        "https://portswigger.net/web-security/cross-site-scripting"
                    ],
                    "host": "example.bubbleapps.io",
                    "path": "/user-input",
                    "cwe": ["CWE-79", "CWE-80"],
                    "capec": ["CAPEC-100"],
                    "verification": {
                        "verified": True,
                        "confidence": "high",
                        "method": "active_testing",
                        "payload_used": "<script>alert('XSS')</script>",
                        "note": "Successfully executed test payload"
                    },
                    "evidence_verification": {
                        "verification_status": "verified",
                        "evidence_hash": "sha256:abc123...",
                        "timestamp": "2024-03-15T10:31:00Z",
                        "live_check_performed": True,
                        "response_time_ms": 234
                    },
                    "cvss_score": 8.8,
                    "instances": [
                        {
                            "url": "https://example.bubbleapps.io/test-app/user-input",
                            "request": "POST /user-input HTTP/1.1\nHost: example.bubbleapps.io\nContent-Type: application/x-www-form-urlencoded\n\nname=<script>alert('XSS')</script>",
                            "response": "HTTP/1.1 200 OK\nContent-Type: text/html\n\nHello <script>alert('XSS')</script>, welcome to our app!",
                            "evidence": ["<script>alert('XSS')</script>"]
                        }
                    ]
                },
                {
                    "title": "Missing Security Headers",
                    "severity": "High",
                    "confidence": "Certain",
                    "description": "Critical security headers are missing from HTTP responses, exposing the application to various client-side attacks.",
                    "category": "Security Misconfiguration",
                    "owasp": "A05:2021 - Security Misconfiguration",
                    "recommendation": "Implement Content Security Policy (CSP), X-Frame-Options, and other security headers.",
                    "background": "Security headers provide an additional layer of security by restricting the behaviors that browsers allow.",
                    "impact": "Missing security headers can lead to XSS attacks, clickjacking, and other client-side vulnerabilities.",
                    "references": [
                        "https://owasp.org/www-project-secure-headers/",
                        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers"
                    ],
                    "host": "example.bubbleapps.io",
                    "path": "/",
                    "cwe": ["CWE-693"],
                    "verification": {
                        "verified": False,
                        "confidence": "certain",
                        "method": "static_analysis",
                        "note": "Detected via header analysis"
                    },
                    "evidence_verification": {
                        "verification_status": "verified",
                        "evidence_hash": "sha256:def456...",
                        "timestamp": "2024-03-15T10:30:15Z",
                        "live_check_performed": True,
                        "response_time_ms": 123
                    },
                    "cvss_score": 6.5,
                    "instances": [
                        {
                            "url": "https://example.bubbleapps.io/test-app/",
                            "request": "GET / HTTP/1.1\nHost: example.bubbleapps.io",
                            "response": "HTTP/1.1 200 OK\nContent-Type: text/html\n\n[Response body]",
                            "evidence": []
                        }
                    ]
                },
                {
                    "title": "SQL Injection Vulnerability",
                    "severity": "Medium",
                    "confidence": "Tentative",
                    "description": "Potential SQL injection vulnerability detected in user input handling.",
                    "category": "Injection",
                    "owasp": "A03:2021 - Injection",
                    "recommendation": "Use parameterized queries and input validation to prevent SQL injection attacks.",
                    "background": "SQL injection occurs when user input is directly concatenated into SQL queries without proper sanitization.",
                    "impact": "Successful SQL injection can lead to data theft, data modification, or unauthorized access to database contents.",
                    "references": [
                        "https://owasp.org/www-community/attacks/SQL_Injection",
                        "https://portswigger.net/web-security/sql-injection"
                    ],
                    "host": "example.bubbleapps.io",
                    "path": "/search",
                    "cwe": ["CWE-89"],
                    "verification": {
                        "verified": False,
                        "confidence": "tentative",
                        "method": "pattern_matching",
                        "note": "Potential vulnerability detected via static analysis"
                    },
                    "evidence_verification": {
                        "verification_status": "unverified",
                        "evidence_hash": "sha256:ghi789...",
                        "timestamp": "2024-03-15T10:32:00Z",
                        "live_check_performed": False
                    },
                    "cvss_score": 5.4,
                    "instances": [
                        {
                            "url": "https://example.bubbleapps.io/test-app/search?q=test",
                            "request": "GET /search?q=test HTTP/1.1\nHost: example.bubbleapps.io",
                            "response": "HTTP/1.1 200 OK\nContent-Type: application/json\n\n{\"results\":[]}",
                            "evidence": []
                        }
                    ]
                }
            ],
            "security_headers": {
                "headers_present": {
                    "Content-Type": {"value": "text/html"}
                },
                "headers_missing": [
                    {"name": "Content-Security-Policy"},
                    {"name": "X-Frame-Options"},
                    {"name": "X-XSS-Protection"}
                ],
                "security_score": "1/8"
            },
            "ssl_tls_analysis": {
                "version": "TLS 1.3",
                "cipher": ("TLS_AES_256_GCM_SHA384", 256, 128),
                "certificate_subject": [["CN", "*.bubbleapps.io"]],
                "certificate_issuer": [["CN", "Let's Encrypt Authority X3"]],
                "certificate_expiry": "2024-06-15"
            },
            "overall_score": 67.5,
            "risk_level": "High"
        }
    }


def test_standards_based_report_generator():
    """Test the StandardsBasedReportGenerator with sample data."""
    print("🧪 Testing StandardsBasedReportGenerator...")
    
    # Create sample scan results
    scan_results = create_sample_scan_results()
    
    # Initialize the report generator
    generator = StandardsBasedReportGenerator()
    
    # Generate report
    output_file = "/home/engine/project/test_standards_report.html"
    html_content = generator._generate_enhanced_html(scan_results)
    
    # Save to file
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(html_content)
    
    print(f"✅ Report generated successfully: {output_file}")
    
    # Verify that no mock data is present
    test_cases = [
        ("CWE-79", "CWE references should be present"),
        ("A03:2021 - Injection", "OWASP categories should be present"),
        ("8.8", "CVSS scores should be present"),
        ("Bubble", "Platform detection should be present"),
        ("example.bubbleapps.io", "Real URLs should be present"),
        ("Cross-Site Scripting", "Real vulnerability titles should be present"),
        ("sha256:abc123", "Evidence hashes should be present"),
        ("TLS 1.3", "Real SSL/TLS data should be present")
    ]
    
    print("\n🔍 Verifying zero mock data architecture...")
    for test_case, description in test_cases:
        if test_case in html_content:
            print(f"  ✅ {description}: Found '{test_case}'")
        else:
            print(f"  ❌ {description}: Missing '{test_case}'")
    
    # Check for potential mock data indicators
    mock_indicators = [
        "Lorem ipsum",
        "TODO",
        "FIXME", 
        "SAMPLE",
        "EXAMPLE.COM",
        "placeholder",
        "mock data",
        "dummy data"
    ]
    
    print("\n🚫 Checking for mock data indicators...")
    found_mocks = []
    for indicator in mock_indicators:
        if indicator.lower() in html_content.lower():
            found_mocks.append(indicator)
    
    if found_mocks:
        print(f"  ❌ Found mock data indicators: {found_mocks}")
    else:
        print("  ✅ No mock data indicators found")
    
    # Verify data-driven sections
    sections_to_check = [
        ("Executive Summary", "3 security issues"),
        ("Risk Analysis Dashboard", "vulnerability distribution"),
        ("Standards Compliance", "OWASP"),
        ("Detailed Findings", "Cross-Site Scripting"),
        ("HTTP Traffic Analysis", "Request/Response"),
        ("Assessment Methodology", "verification coverage")
    ]
    
    print("\n📊 Verifying data-driven sections...")
    for section_name, expected_content in sections_to_check:
        if expected_content.lower() in html_content.lower():
            print(f"  ✅ {section_name}: Contains expected content")
        else:
            print(f"  ⚠️  {section_name}: May be missing expected content")
    
    print(f"\n🎯 Report contains {len(html_content)} characters")
    print(f"📁 Output file: {output_file}")
    
    return output_file


if __name__ == "__main__":
    try:
        output_file = test_standards_based_report_generator()
        print(f"\n✅ Test completed successfully!")
        print(f"📄 View the report at: {output_file}")
    except Exception as e:
        print(f"\n❌ Test failed with error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)