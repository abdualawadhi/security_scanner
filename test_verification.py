#!/usr/bin/env python3
"""
Test script for vulnerability verification functionality
"""

from src.website_security_scanner.verifier.vulnerability_verifier import VulnerabilityVerifier
import requests

def test_verification():
    session = requests.Session()
    verifier = VulnerabilityVerifier(session)
    
    # Test different vulnerability types
    test_cases = [
        {'type': 'xss', 'url': 'https://amqmalawadhi-85850.bubbleapps.io/version-test/', 'parameter': 'q'},
        {'type': 'sql injection', 'url': 'https://amqmalawadhi-85850.bubbleapps.io/version-test/', 'parameter': 'id'},
        {'type': 'path traversal', 'url': 'https://amqmalawadhi-85850.bubbleapps.io/version-test/', 'parameter': 'file'},
        {'type': 'csrf', 'url': 'https://amqmalawadhi-85850.bubbleapps.io/version-test/'},
    ]
    
    print("=== VULNERABILITY VERIFICATION TEST ===\n")
    
    for i, test_case in enumerate(test_cases, 1):
        print(f"Test {i}: {test_case['type'].upper()}")
        result = verifier.verify_vulnerability(test_case)
        print(f"Verified: {result.get('verified', False)}")
        print(f"Confidence: {result.get('confidence', 'unknown')}")
        print(f"Reason: {result.get('reason', 'No reason provided')}")
        if 'payload' in result:
            print(f"Payload: {result['payload']}")
        print("---")

if __name__ == "__main__":
    test_verification()
