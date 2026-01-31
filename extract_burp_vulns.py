#!/usr/bin/env python3
"""
Extract vulnerabilities from Burp Suite report
"""

import re
from bs4 import BeautifulSoup

def extract_burp_vulnerabilities():
    with open('c:\\Users\\Ideapad\\Downloads\\security_scanner-main (1)\\Bursuite Reports\\Bubble.html', 'r', encoding='utf-8') as f:
        content = f.read()
    
    soup = BeautifulSoup(content, 'html.parser')
    
    # Find vulnerability titles
    vuln_titles = []
    for element in soup.find_all(class_='BODH1'):
        if element.get('id'):
            text = element.get_text().strip()
            # Extract vulnerability type from the text
            if 'https://' in text:
                continue  # Skip URLs
            if text and len(text) > 5:
                vuln_titles.append(text)
    
    # Look for severity indicators
    severity_pattern = r'high_certain|medium_certain|low_certain|info_certain'
    severities = re.findall(severity_pattern, content)
    
    # Count severities
    severity_counts = {
        'high': severities.count('high_certain'),
        'medium': severities.count('medium_certain'), 
        'low': severities.count('low_certain'),
        'info': severities.count('info_certain')
    }
    
    print("=== BURP SUITE VULNERABILITY SUMMARY ===")
    print(f"Total Issues Found: {sum(severity_counts.values())}")
    print(f"High Severity: {severity_counts['high']}")
    print(f"Medium Severity: {severity_counts['medium']}")
    print(f"Low Severity: {severity_counts['low']}")
    print(f"Info Severity: {severity_counts['info']}")
    
    print("\n=== VULNERABILITY TYPES ===")
    for i, title in enumerate(vuln_titles[:15], 1):
        print(f"{i}. {title}")
    
    return severity_counts, vuln_titles

if __name__ == "__main__":
    extract_burp_vulnerabilities()
