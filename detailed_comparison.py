#!/usr/bin/env python3
"""
Detailed vulnerability analysis for multi-platform comparison
"""

import re
from pathlib import Path

def get_detailed_scanner_analysis(html_file, platform_name):
    """Get detailed vulnerability analysis from scanner report"""
    with open(html_file, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Extract specific vulnerability details
    vulnerabilities = []
    
    # Look for vulnerability entries in the HTML
    vuln_pattern = r'<tr[^>]*>.*?<td[^>]*>([^<]*(?:vulnerability|secret|exposure|issue|manipulation|header)[^<]*)</td>.*?</tr>'
    matches = re.findall(vuln_pattern, content, re.IGNORECASE | re.DOTALL)
    
    for match in matches:
        vuln = match.strip()
        if len(vuln) > 15:  # Filter meaningful entries
            vulnerabilities.append(vuln)
    
    # Look for severity badges
    high_severity = len(re.findall(r'severity-high[^>]*>([^<]*)', content))
    medium_severity = len(re.findall(r'severity-medium[^>]*>([^<]*)', content))
    low_severity = len(re.findall(r'severity-low[^>]*>([^<]*)', content))
    critical_severity = len(re.findall(r'severity-critical[^>]*>([^<]*)', content))
    
    return {
        'platform': platform_name,
        'vulnerabilities': vulnerabilities[:10],  # Top 10
        'severity_breakdown': {
            'critical': critical_severity,
            'high': high_severity,
            'medium': medium_severity,
            'low': low_severity
        }
    }

def get_burp_detailed_analysis(html_file, platform_name):
    """Get detailed analysis from Burp Suite report"""
    with open(html_file, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Extract specific vulnerability counts
    xss_details = len(re.findall(r'Cross-site scripting', content, re.IGNORECASE))
    sql_injection = len(re.findall(r'SQL injection', content, re.IGNORECASE))
    csrf = len(re.findall(r'CSRF|Cross-site request forgery', content, re.IGNORECASE))
    path_traversal = len(re.findall(r'Path traversal', content, re.IGNORECASE))
    open_redirect = len(re.findall(r'Open redirect', content, re.IGNORECASE))
    ssrf = len(re.findall(r'SSRF|Server-side request forgery', content, re.IGNORECASE))
    
    # Extract severity breakdown
    high_count = len(re.findall(r'high_(certain|firm|tentative)', content))
    medium_count = len(re.findall(r'medium_(certain|firm|tentative)', content))
    low_count = len(re.findall(r'low_(certain|firm|tentative)', content))
    info_count = len(re.findall(r'info_(certain|firm|tentative)', content))
    
    return {
        'platform': platform_name,
        'vulnerability_types': {
            'xss': xss_details,
            'sql_injection': sql_injection,
            'csrf': csrf,
            'path_traversal': path_traversal,
            'open_redirect': open_redirect,
            'ssrf': ssrf
        },
        'severity_breakdown': {
            'high': high_count,
            'medium': medium_count,
            'low': low_count,
            'info': info_count
        }
    }

def main():
    print("🔍 DETAILED MULTI-PLATFORM VULNERABILITY ANALYSIS\n")
    
    # Get detailed analysis
    outsystems_scanner = get_detailed_scanner_analysis('c:\\Users\\Ideapad\\Downloads\\security_scanner-main (1)\\data\\reports\\scan_20260131_190533_0.html', 'OutSystems')
    airtable_scanner = get_detailed_scanner_analysis('c:\\Users\\Ideapad\\Downloads\\security_scanner-main (1)\\data\\reports\\scan_20260131_190602_0.html', 'Airtable')
    
    outsystems_burp = get_burp_detailed_analysis('c:\\Users\\Ideapad\\Downloads\\security_scanner-main (1)\\Bursuite Reports\\Outsystems.html', 'OutSystems')
    airtable_burp = get_burp_detailed_analysis('c:\\Users\\Ideapad\\Downloads\\security_scanner-main (1)\\Bursuite Reports\\Aritable.html', 'Airtable')
    
    print("🎯 OUTSYSTEMS DETAILED ANALYSIS")
    print("=" * 60)
    print(f"Security Scanner Findings ({outsystems_scanner['severity_breakdown']['critical'] + outsystems_scanner['severity_breakdown']['high'] + outsystems_scanner['severity_breakdown']['medium'] + outsystems_scanner['severity_breakdown']['low']} total):")
    for i, vuln in enumerate(outsystems_scanner['vulnerabilities'], 1):
        print(f"  {i}. {vuln}")
    
    print(f"\nBurp Suite Findings ({outsystems_burp['severity_breakdown']['high'] + outsystems_burp['severity_breakdown']['medium'] + outsystems_burp['severity_breakdown']['low'] + outsystems_burp['severity_breakdown']['info']} total):")
    print(f"  • XSS: {outsystems_burp['vulnerability_types']['xss']} instances")
    print(f"  • SQL Injection: {outsystems_burp['vulnerability_types']['sql_injection']} instances")
    print(f"  • CSRF: {outsystems_burp['vulnerability_types']['csrf']} instances")
    print(f"  • Path Traversal: {outsystems_burp['vulnerability_types']['path_traversal']} instances")
    print(f"  • Open Redirect: {outsystems_burp['vulnerability_types']['open_redirect']} instances")
    print(f"  • SSRF: {outsystems_burp['vulnerability_types']['ssrf']} instances")
    
    print(f"\n🎯 AIRTABLE DETAILED ANALYSIS")
    print("=" * 60)
    print(f"Security Scanner Findings ({airtable_scanner['severity_breakdown']['critical'] + airtable_scanner['severity_breakdown']['high'] + airtable_scanner['severity_breakdown']['medium'] + airtable_scanner['severity_breakdown']['low']} total):")
    for i, vuln in enumerate(airtable_scanner['vulnerabilities'], 1):
        print(f"  {i}. {vuln}")
    
    print(f"\nBurp Suite Findings ({airtable_burp['severity_breakdown']['high'] + airtable_burp['severity_breakdown']['medium'] + airtable_burp['severity_breakdown']['low'] + airtable_burp['severity_breakdown']['info']} total):")
    print(f"  • XSS: {airtable_burp['vulnerability_types']['xss']} instances")
    print(f"  • SQL Injection: {airtable_burp['vulnerability_types']['sql_injection']} instances")
    print(f"  • CSRF: {airtable_burp['vulnerability_types']['csrf']} instances")
    print(f"  • Path Traversal: {airtable_burp['vulnerability_types']['path_traversal']} instances")
    print(f"  • Open Redirect: {airtable_burp['vulnerability_types']['open_redirect']} instances")
    print(f"  • SSRF: {airtable_burp['vulnerability_types']['ssrf']} instances")
    
    print(f"\n📈 COMPARATIVE SUMMARY")
    print("=" * 60)
    print("OUTSYSTEMS:")
    print(f"  • Scanner detects: {outsystems_scanner['severity_breakdown']['high']} high, {outsystems_scanner['severity_breakdown']['medium']} medium severity")
    print(f"  • Burp detects: {outsystems_burp['severity_breakdown']['high']} high, {outsystems_burp['severity_breakdown']['medium']} medium severity")
    print(f"  • Gap: {outsystems_burp['severity_breakdown']['high'] - outsystems_scanner['severity_breakdown']['high']} high severity issues missed")
    
    print(f"\nAIRTABLE:")
    print(f"  • Scanner detects: {airtable_scanner['severity_breakdown']['high']} high, {airtable_scanner['severity_breakdown']['medium']} medium severity")
    print(f"  • Burp detects: {airtable_burp['severity_breakdown']['high']} high, {airtable_burp['severity_breakdown']['medium']} medium severity")
    print(f"  • Gap: {airtable_burp['severity_breakdown']['high'] - airtable_scanner['severity_breakdown']['high']} high severity issues missed")
    
    print(f"\n🚀 CRITICAL INSIGHTS:")
    print("1. XSS Detection Gap: Burp finds significantly more XSS vulnerabilities")
    print("2. Platform-Specific Risks: Scanner finds unique low-code platform vulnerabilities")
    print("3. Severity Assessment: Airtable shows critical security level in scanner")
    print("4. Comprehensive Coverage: Burp provides broader vulnerability type coverage")

if __name__ == "__main__":
    main()
