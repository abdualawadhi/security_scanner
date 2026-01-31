#!/usr/bin/env python3
"""
Simple verification test
"""

from src.website_security_scanner.verifier.vulnerability_verifier import VulnerabilityVerifier
import requests

def test_verification():
    session = requests.Session()
    verifier = VulnerabilityVerifier(session)
    
    print("=== TESTING VERIFICATION ===\n")
    
    # Test Airtable Base ID Exposure
    print("1. Testing Airtable Base ID Exposure:")
    airtable_vuln = {
        'type': 'Airtable Base ID Exposure',
        'url': 'https://airtable.com/app5oLkwSi8gaXUod/',
        'description': 'Airtable Base ID exposed: appleLoginButtonOn',
        'severity': 'Medium'
    }
    
    result = verifier.verify_vulnerability(airtable_vuln)
    print(f"   Result: {result}")
    print(f"   Verified: {result.get('verified', 'N/A')}")
    print(f"   Reason: {result.get('reason', 'N/A')}")
    
    print("\n2. Testing Potential Secret in JavaScript:")
    secret_vuln = {
        'type': 'Potential Secret in JavaScript',
        'url': 'https://airtable.com/app5oLkwSi8gaXUod/',
        'description': 'Potential secret found in JavaScript: c3c0305f30a1b2c3d4e5f6789abcdef123456',
        'severity': 'High'
    }
    
    result = verifier.verify_vulnerability(secret_vuln)
    print(f"   Result: {result}")
    print(f"   Verified: {result.get('verified', 'N/A')}")
    print(f"   Reason: {result.get('reason', 'N/A')}")
    
    print("\n3. Testing unknown vulnerability type:")
    unknown_vuln = {
        'type': 'Unknown Vulnerability Type',
        'url': 'https://example.com',
        'description': 'Some unknown vulnerability',
        'severity': 'Medium'
    }
    
    result = verifier.verify_vulnerability(unknown_vuln)
    print(f"   Result: {result}")
    print(f"   Verified: {result.get('verified', 'N/A')}")
    print(f"   Reason: {result.get('reason', 'N/A')}")

if __name__ == "__main__":
    test_verification()
