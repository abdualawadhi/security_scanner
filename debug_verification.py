#!/usr/bin/env python3
"""
Debug verification system - check what vulnerability types are being detected
"""

from src.website_security_scanner.verifier.vulnerability_verifier import VulnerabilityVerifier
import requests

def debug_verification():
    session = requests.Session()
    verifier = VulnerabilityVerifier(session)
    
    print("=== DEBUGGING VERIFICATION SYSTEM ===\n")
    
    # Test the exact vulnerability types from your scan
    test_vulnerabilities = [
        {
            'type': 'Airtable Base ID Exposure',
            'url': 'https://airtable.com/app5oLkwSi8gaXUod/',
            'description': 'Airtable Base ID exposed: appleLoginButtonOn',
            'severity': 'Medium'
        },
        {
            'type': 'Potential Secret in JavaScript',
            'url': 'https://airtable.com/app5oLkwSi8gaXUod/',
            'description': 'Potential secret found in JavaScript: c3c0305f30...',
            'severity': 'High'
        }
    ]
    
    print("Available verification methods:")
    for method_name in verifier.verification_methods.keys():
        print(f"  - {method_name}")
    
    print("\n" + "="*60 + "\n")
    
    for i, vuln in enumerate(test_vulnerabilities, 1):
        print(f"Test {i}: {vuln['type']}")
        print(f"URL: {vuln['url']}")
        print(f"Description: {vuln['description']}")
        
        # Check if method exists
        vuln_type = vuln['type'].lower()
        method = verifier.verification_methods.get(vuln_type)
        
        print(f"Method found: {'Yes' if method else 'No'}")
        print(f"Looking for: '{vuln_type}'")
        
        if method:
            print("✅ Verification method exists!")
            result = verifier.verify_vulnerability(vuln)
            print(f"Verification result: {result}")
        else:
            print("❌ No verification method found!")
            print("Available methods:")
            for available_method in verifier.verification_methods.keys():
                if vuln_type in available_method or available_method in vuln_type:
                    print(f"  - Close match: {available_method}")
        
        print("\n" + "-"*40 + "\n")

if __name__ == "__main__":
    debug_verification()
