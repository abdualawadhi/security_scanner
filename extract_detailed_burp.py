#!/usr/bin/env python3
"""
Extract detailed vulnerabilities from Burp Suite report
"""

import re
from bs4 import BeautifulSoup

def extract_detailed_vulnerabilities():
    with open('c:\\Users\\Ideapad\\Downloads\\security_scanner-main (1)\\Bursuite Reports\\Bubble.html', 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Extract vulnerability details using regex patterns
    vuln_patterns = [
        (r'Cross-site scripting.*?(\n.*?)*?Issue detail', 'Cross-Site Scripting (XSS)'),
        (r'SQL injection.*?(\n.*?)*?Issue detail', 'SQL Injection'),
        (r'CSRF.*?(\n.*?)*?Issue detail', 'CSRF'),
        (r'Path traversal.*?(\n.*?)*?Issue detail', 'Path Traversal'),
        (r'Open redirect.*?(\n.*?)*?Issue detail', 'Open Redirect'),
        (r'SSRF.*?(\n.*?)*?Issue detail', 'Server-Side Request Forgery (SSRF)'),
        (r'XXE.*?(\n.*?)*?Issue detail', 'XML External Entity (XXE)'),
        (r'Command injection.*?(\n.*?)*?Issue detail', 'Command Injection'),
        (r'Cryptographic.*?(\n.*?)*?Issue detail', 'Cryptographic Issues'),
        (r'Security headers.*?(\n.*?)*?Issue detail', 'Missing Security Headers'),
        (r'Session.*?(\n.*?)*?Issue detail', 'Session Management Issues'),
        (r'Authentication.*?(\n.*?)*?Issue detail', 'Authentication Issues'),
        (r'Authorization.*?(\n.*?)*?Issue detail', 'Authorization Issues'),
        (r'Information disclosure.*?(\n.*?)*?Issue detail', 'Information Disclosure'),
        (r'Cookie.*?(\n.*?)*?Issue detail', 'Cookie Security Issues'),
    ]
    
    found_vulns = []
    for pattern, vuln_type in vuln_patterns:
        matches = re.findall(pattern, content, re.IGNORECASE | re.DOTALL)
        if matches:
            found_vulns.append(vuln_type)
    
    # Extract severity counts more accurately
    high_severity = len(re.findall(r'high_(certain|firm|tentative)', content))
    medium_severity = len(re.findall(r'medium_(certain|firm|tentative)', content))
    low_severity = len(re.findall(r'low_(certain|firm|tentative)', content))
    info_severity = len(re.findall(r'info_(certain|firm|tentative)', content))
    
    # Look for specific vulnerability indicators
    xss_count = len(re.findall(r'Cross-site scripting|XSS', content, re.IGNORECASE))
    sqli_count = len(re.findall(r'SQL injection|SQLi', content, re.IGNORECASE))
    csrf_count = len(re.findall(r'CSRF|Cross-site request forgery', content, re.IGNORECASE))
    path_traversal_count = len(re.findall(r'Path traversal|Directory traversal', content, re.IGNORECASE))
    
    print("=== DETAILED BURP SUITE VULNERABILITY ANALYSIS ===")
    print(f"Total Issues: {high_severity + medium_severity + low_severity + info_severity}")
    print(f"High Severity: {high_severity}")
    print(f"Medium Severity: {medium_severity}")
    print(f"Low Severity: {low_severity}")
    print(f"Info Severity: {info_severity}")
    
    print(f"\n=== SPECIFIC VULNERABILITY COUNTS ===")
    print(f"Cross-Site Scripting (XSS): {xss_count}")
    print(f"SQL Injection: {sqli_count}")
    print(f"CSRF: {csrf_count}")
    print(f"Path Traversal: {path_traversal_count}")
    
    print(f"\n=== DETECTED VULNERABILITY TYPES ===")
    for vuln in found_vulns:
        print(f"✓ {vuln}")
    
    return {
        'total': high_severity + medium_severity + low_severity + info_severity,
        'high': high_severity,
        'medium': medium_severity, 
        'low': low_severity,
        'info': info_severity,
        'xss': xss_count,
        'sqli': sqli_count,
        'csrf': csrf_count,
        'path_traversal': path_traversal_count,
        'types': found_vulns
    }

if __name__ == "__main__":
    extract_detailed_vulnerabilities()
