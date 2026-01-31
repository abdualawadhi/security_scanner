#!/usr/bin/env python3
"""
Extract vulnerability data from security scanner HTML reports
"""

import re
import json
from pathlib import Path

def extract_scanner_vulnerabilities(html_file):
    """Extract vulnerability data from scanner HTML report"""
    with open(html_file, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Extract platform type
    platform_match = re.search(r'Platform Type</td><td>([^<]+)</td>', content)
    platform = platform_match.group(1) if platform_match else "Unknown"
    
    # Extract security level
    security_level_match = re.search(r'Security Level:</strong>.*?severity-([^"]+)"', content)
    security_level = security_level_match.group(1) if security_level_match else "Unknown"
    
    # Extract vulnerability counts
    vuln_counts = {
        'critical': len(re.findall(r'severity-critical', content)),
        'high': len(re.findall(r'severity-high', content)),
        'medium': len(re.findall(r'severity-medium', content)),
        'low': len(re.findall(r'severity-low', content)),
        'info': len(re.findall(r'severity-info', content))
    }
    
    # Extract vulnerability details
    vuln_details = []
    vuln_sections = re.findall(r'<td[^>]*>([^<]*(?:vulnerability|exposure|issue|secret)[^<]*)</td>', content, re.IGNORECASE)
    
    for vuln in vuln_sections:
        vuln = vuln.strip()
        if len(vuln) > 10:  # Filter out short matches
            vuln_details.append(vuln)
    
    # Also look for vulnerability patterns
    vuln_patterns = [
        r'Potential Secret in JavaScript',
        r'Missing.*Headers',
        r'Exposed.*Endpoint',
        r'DOM.*Manipulation',
        r'Cloud.*Resource',
        r'Authentication',
        r'Authorization',
        r'Session',
        r'CSRF',
        r'XSS',
        r'SQL.*Injection',
        r'Path.*Traversal',
        r'Open.*Redirect'
    ]
    
    detected_types = []
    for pattern in vuln_patterns:
        if re.search(pattern, content, re.IGNORECASE):
            detected_types.append(pattern)
    
    return {
        'platform': platform,
        'security_level': security_level,
        'vulnerability_counts': vuln_counts,
        'total_vulnerabilities': sum(vuln_counts.values()),
        'detected_types': detected_types,
        'vulnerability_details': vuln_details[:10]  # Limit to first 10
    }

def extract_burp_vulnerabilities(html_file):
    """Extract vulnerability data from Burp Suite HTML report"""
    with open(html_file, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Extract severity counts
    severity_counts = {
        'high': len(re.findall(r'high_(certain|firm|tentative)', content)),
        'medium': len(re.findall(r'medium_(certain|firm|tentative)', content)),
        'low': len(re.findall(r'low_(certain|firm|tentative)', content)),
        'info': len(re.findall(r'info_(certain|firm|tentative)', content))
    }
    
    # Extract specific vulnerability counts
    xss_count = len(re.findall(r'Cross-site scripting|XSS', content, re.IGNORECASE))
    sqli_count = len(re.findall(r'SQL injection|SQLi', content, re.IGNORECASE))
    csrf_count = len(re.findall(r'CSRF|Cross-site request forgery', content, re.IGNORECASE))
    path_traversal_count = len(re.findall(r'Path traversal|Directory traversal', content, re.IGNORECASE))
    
    # Extract vulnerability types
    vuln_types = [
        'Cross-Site Scripting (XSS)',
        'SQL Injection',
        'CSRF',
        'Path Traversal',
        'Open Redirect',
        'SSRF',
        'XXE',
        'Command Injection',
        'Cryptographic Issues',
        'Security Headers',
        'Session Management',
        'Authentication',
        'Authorization',
        'Information Disclosure',
        'Cookie Security'
    ]
    
    detected_types = []
    for vuln_type in vuln_types:
        if re.search(vuln_type.replace(' ', '.*'), content, re.IGNORECASE):
            detected_types.append(vuln_type)
    
    return {
        'total_vulnerabilities': sum(severity_counts.values()),
        'vulnerability_counts': severity_counts,
        'xss_count': xss_count,
        'sqli_count': sqli_count,
        'csrf_count': csrf_count,
        'path_traversal_count': path_traversal_count,
        'detected_types': detected_types
    }

def main():
    print("=== MULTI-PLATFORM VULNERABILITY COMPARISON ===\n")
    
    # Scanner reports
    outsystems_scanner = extract_scanner_vulnerabilities('c:\\Users\\Ideapad\\Downloads\\security_scanner-main (1)\\data\\reports\\scan_20260131_190533_0.html')
    airtable_scanner = extract_scanner_vulnerabilities('c:\\Users\\Ideapad\\Downloads\\security_scanner-main (1)\\data\\reports\\scan_20260131_190602_0.html')
    
    # Burp Suite reports
    outsystems_burp = extract_burp_vulnerabilities('c:\\Users\\Ideapad\\Downloads\\security_scanner-main (1)\\Bursuite Reports\\Outsystems.html')
    airtable_burp = extract_burp_vulnerabilities('c:\\Users\\Ideapad\\Downloads\\security_scanner-main (1)\\Bursuite Reports\\Aritable.html')
    
    print("📊 OUTSYSTEMS COMPARISON")
    print(f"Scanner: {outsystems_scanner['total_vulnerabilities']} issues | Security Level: {outsystems_scanner['security_level']}")
    print(f"Burp: {outsystems_burp['total_vulnerabilities']} issues")
    print(f"Gap: {outsystems_burp['total_vulnerabilities'] - outsystems_scanner['total_vulnerabilities']} issues")
    
    print(f"\n📊 AIRTABLE COMPARISON") 
    print(f"Scanner: {airtable_scanner['total_vulnerabilities']} issues | Security Level: {airtable_scanner['security_level']}")
    print(f"Burp: {airtable_burp['total_vulnerabilities']} issues")
    print(f"Gap: {airtable_burp['total_vulnerabilities'] - airtable_scanner['total_vulnerabilities']} issues")
    
    print(f"\n🎯 DETAILED BREAKDOWN")
    print("=" * 80)
    print(f"{'Platform':<12} {'Tool':<15} {'Total':<8} {'High':<6} {'Medium':<8} {'Low':<6} {'Info':<6}")
    print("-" * 80)
    print(f"{'OutSystems':<12} {'Scanner':<15} {outsystems_scanner['total_vulnerabilities']:<8} {outsystems_scanner['vulnerability_counts']['high']:<6} {outsystems_scanner['vulnerability_counts']['medium']:<8} {outsystems_scanner['vulnerability_counts']['low']:<6} {outsystems_scanner['vulnerability_counts']['info']:<6}")
    print(f"{'OutSystems':<12} {'Burp':<15} {outsystems_burp['total_vulnerabilities']:<8} {outsystems_burp['vulnerability_counts']['high']:<6} {outsystems_burp['vulnerability_counts']['medium']:<8} {outsystems_burp['vulnerability_counts']['low']:<6} {outsystems_burp['vulnerability_counts']['info']:<6}")
    print(f"{'Airtable':<12} {'Scanner':<15} {airtable_scanner['total_vulnerabilities']:<8} {airtable_scanner['vulnerability_counts']['high']:<6} {airtable_scanner['vulnerability_counts']['medium']:<8} {airtable_scanner['vulnerability_counts']['low']:<6} {airtable_scanner['vulnerability_counts']['info']:<6}")
    print(f"{'Airtable':<12} {'Burp':<15} {airtable_burp['total_vulnerabilities']:<8} {airtable_burp['vulnerability_counts']['high']:<6} {airtable_burp['vulnerability_counts']['medium']:<8} {airtable_burp['vulnerability_counts']['low']:<6} {airtable_burp['vulnerability_counts']['info']:<6}")
    
    print(f"\n🔍 SECURITY SCANNER EXCLUSIVE FINDINGS")
    print(f"OutSystems: {outsystems_scanner['detected_types']}")
    print(f"Airtable: {airtable_scanner['detected_types']}")
    
    print(f"\n🔍 BURP SUITE EXCLUSIVE FINDINGS")
    print(f"OutSystems XSS: {outsystems_burp['xss_count']}")
    print(f"OutSystems SQLi: {outsystems_burp['sqli_count']}")
    print(f"OutSystems CSRF: {outsystems_burp['csrf_count']}")
    print(f"Airtable XSS: {airtable_burp['xss_count']}")
    print(f"Airtable SQLi: {airtable_burp['sqli_count']}")
    print(f"Airtable CSRF: {airtable_burp['csrf_count']}")

if __name__ == "__main__":
    main()
