#!/usr/bin/env python3
"""
Test the enhanced vulnerability verification system
"""

from src.website_security_scanner.verifier.vulnerability_verifier import VulnerabilityVerifier
import requests

def test_enhanced_verification():
    session = requests.Session()
    verifier = VulnerabilityVerifier(session)
    
    print("=== TESTING ENHANCED VERIFICATION SYSTEM ===\n")
    
    # Test Airtable Base ID Exposure verification
    print("🔍 Testing Airtable Base ID Exposure Verification")
    airtable_vuln = {
        'type': 'Airtable Base ID Exposure',
        'url': 'https://airtable.com/app5oLkwSi8gaXUod/',
        'description': 'Airtable Base ID exposed: app5oLkwSi8gaXUod',
        'severity': 'Medium'
    }
    
    result = verifier.verify_vulnerability(airtable_vuln)
    print(f"Verified: {result.get('verified', False)}")
    print(f"Confidence: {result.get('confidence', 'unknown')}")
    print(f"Method: {result.get('method', 'N/A')}")
    print(f"Evidence: {result.get('evidence', 'No evidence')}")
    if 'verification_details' in result:
        details = result['verification_details']
        print(f"Base ID: {details.get('base_id', 'N/A')}")
        print(f"Response Code: {details.get('response_code', 'N/A')}")
    
    print("\n" + "="*60 + "\n")
    
    # Test Potential Secret in JavaScript verification
    print("🔍 Testing Potential Secret in JavaScript Verification")
    secret_vuln = {
        'type': 'Potential Secret in JavaScript',
        'url': 'https://amqmalawadhi-85850.bubbleapps.io/version-test/',
        'description': 'Potential secret found in JavaScript: c3c0305f30a1b2c3d4e5f6789abcdef123456',
        'severity': 'High'
    }
    
    result = verifier.verify_vulnerability(secret_vuln)
    print(f"Verified: {result.get('verified', False)}")
    print(f"Confidence: {result.get('confidence', 'unknown')}")
    print(f"Method: {result.get('method', 'N/A')}")
    print(f"Evidence: {result.get('evidence', 'No evidence')}")
    if 'verification_details' in result:
        details = result['verification_details']
        print(f"Secret Type: {details.get('secret_type', 'N/A')}")
        print(f"Secret Length: {details.get('secret_length', 'N/A')}")
        if 'analysis' in details:
            analysis = details['analysis']
            print(f"Is Suspicious: {analysis.get('is_suspicious', False)}")
    
    print("\n" + "="*60 + "\n")
    
    # Test with actual Airtable data from your scan
    print("🔍 Testing with Real Airtable Base IDs from Your Scan")
    real_base_ids = [
        'appleLoginButtonOn',
        'ApplyToOnlyNewUser', 
        'appUnchunkedBundle',
        'AppTileConsolidati',
        'AppSpecificLoading'
    ]
    
    for base_id in real_base_ids[:3]:  # Test first 3
        test_vuln = {
            'type': 'Airtable Base ID Exposure',
            'url': 'https://airtable.com/',
            'description': f'Airtable Base ID exposed: {base_id}',
            'severity': 'Medium'
        }
        
        result = verifier.verify_vulnerability(test_vuln)
        print(f"Base ID: {base_id}")
        print(f"  Verified: {result.get('verified', False)}")
        print(f"  Confidence: {result.get('confidence', 'unknown')}")
        print(f"  Reason: {result.get('reason', 'No reason')}")
        print()

if __name__ == "__main__":
    test_enhanced_verification()
