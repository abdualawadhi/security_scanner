#!/usr/bin/env python3
"""
Compare Burp Suite vs Security Scanner vulnerabilities
"""

def compare_vulnerabilities():
    # Burp Suite results from our extraction
    burp_results = {
        'total_issues': 314,
        'high_severity': 9,
        'medium_severity': 14,
        'low_severity': 108,
        'info_severity': 183,
        'xss_count': 48,
        'sqli_count': 0,
        'csrf_count': 0,
        'path_traversal_count': 0,
        'detected_types': [
            'Cross-Site Scripting (XSS)',
            'Open Redirect',
            'Cryptographic Issues',
            'Session Management Issues',
            'Authentication Issues',
            'Authorization Issues',
            'Information Disclosure',
            'Cookie Security Issues'
        ]
    }
    
    # Security Scanner results from the scan output
    scanner_results = {
        'total_issues': 9,
        'high_severity': 2,
        'medium_severity': 2,
        'low_severity': 4,
        'info_severity': 1,  # Hidden HTTP/2
        'detected_vulnerabilities': [
            'Potential Secret in JavaScript (High)',
            'Potential Secret in JavaScript (High)',
            'Missing AJAX Security Headers (Low)',
            'Exposed Sensitive Endpoint (Low)',
            'Hidden HTTP/2 (Info)',
            'Cookie Scoped to Parent Domain (Low)',
            'DOM Data Manipulation (DOM-based) (Medium)',
            'Cloud Resource / AWS Key Exposure (Medium)'
        ],
        'platform_specific': True,
        'verification_enabled': True
    }
    
    print("=== VULNERABILITY DETECTION COMPARISON ===")
    print("Target: https://amqmalawadhi-85850.bubbleapps.io/version-test/\n")
    
    print("📊 OVERALL COMPARISON")
    print(f"{'Metric':<25} {'Burp Suite':<15} {'Security Scanner':<20} {'Difference'}")
    print("-" * 75)
    print(f"{'Total Issues':<25} {burp_results['total_issues']:<15} {scanner_results['total_issues']:<20} {burp_results['total_issues'] - scanner_results['total_issues']}")
    print(f"{'High Severity':<25} {burp_results['high_severity']:<15} {scanner_results['high_severity']:<20} {burp_results['high_severity'] - scanner_results['high_severity']}")
    print(f"{'Medium Severity':<25} {burp_results['medium_severity']:<15} {scanner_results['medium_severity']:<20} {burp_results['medium_severity'] - scanner_results['medium_severity']}")
    print(f"{'Low Severity':<25} {burp_results['low_severity']:<15} {scanner_results['low_severity']:<20} {burp_results['low_severity'] - scanner_results['low_severity']}")
    print(f"{'Info Severity':<25} {burp_results['info_severity']:<15} {scanner_results['info_severity']:<20} {burp_results['info_severity'] - scanner_results['info_severity']}")
    
    print(f"\n🎯 SPECIFIC VULNERABILITY TYPES")
    print(f"XSS:                    Burp: {burp_results['xss_count']:>3} | Scanner: 0")
    print(f"SQL Injection:           Burp: {burp_results['sqli_count']:>3} | Scanner: 0")
    print(f"CSRF:                   Burp: {burp_results['csrf_count']:>3} | Scanner: 0")
    print(f"Path Traversal:         Burp: {burp_results['path_traversal_count']:>3} | Scanner: 0")
    
    print(f"\n🔍 SECURITY SCANNER EXCLUSIVE FINDINGS")
    for vuln in scanner_results['detected_vulnerabilities']:
        print(f"  ✓ {vuln}")
    
    print(f"\n🔍 BURP SUITE EXCLUSIVE FINDINGS")
    for vuln_type in burp_results['detected_types']:
        print(f"  ✓ {vuln_type}")
    
    print(f"\n📈 ANALYSIS SUMMARY")
    print("BURP SUITE ADVANTAGES:")
    print("  • 35x more issues detected (314 vs 9)")
    print("  • Comprehensive XSS detection (48 instances)")
    print("  • Deep technical analysis")
    print("  • Industry-standard vulnerability coverage")
    
    print("\nSECURITY SCANNER ADVANTAGES:")
    print("  • Low-code platform specific detection")
    print("  • Bubble.io workflow analysis")
    print("  • JavaScript secret detection")
    print("  • DOM-based vulnerability detection")
    print("  • AWS/Cloud resource exposure detection")
    print("  • Active vulnerability verification")
    
    print("\n🎯 KEY DIFFERENCES:")
    print("1. SCOPE: Burp = General web apps | Scanner = Low-code platforms")
    print("2. DEPTH: Burp = Comprehensive technical | Scanner = Platform-specific")
    print("3. FOCUS: Burp = All vulnerability types | Scanner = Low-code risks")
    print("4. VERIFICATION: Burp = Passive detection | Scanner = Active testing")

if __name__ == "__main__":
    compare_vulnerabilities()
