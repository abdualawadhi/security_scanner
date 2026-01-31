#!/usr/bin/env python3
"""
Debug the vulnerability type matching issue
"""

from src.website_security_scanner.verifier.vulnerability_verifier import VulnerabilityVerifier
import requests

def debug_type_matching():
    session = requests.Session()
    verifier = VulnerabilityVerifier(session)
    
    print("=== DEBUGGING VULNERABILITY TYPE MATCHING ===\n")
    
    # Test the exact vulnerability from the scan
    test_vuln = {
        'type': 'Airtable Base ID Exposure',
        'url': 'https://airtable.com/app5oLkwSi8gaXUod/',
        'description': 'Airtable Base ID exposed: appleLoginButtonOn',
        'severity': 'Medium'
    }
    
    print(f"Input vulnerability type: '{test_vuln['type']}'")
    print(f"Lowercase: '{test_vuln['type'].lower()}'")
    
    # Test the verification method lookup
    vuln_type = test_vuln['type'].lower()
    
    print(f"\nLooking for: '{vuln_type}'")
    
    # Check what methods are available
    verification_methods = {
        'xss': verifier.verify_xss,
        'cross-site scripting': verifier.verify_xss,
        'sql injection': verifier.verify_sql_injection,
        'command injection': verifier.verify_command_injection,
        'path traversal': verifier.verify_path_traversal,
        'directory traversal': verifier.verify_path_traversal,
        'ssrf': verifier.verify_ssrf,
        'open redirect': verifier.verify_open_redirect,
        'xxe': verifier.verify_xxe,
        'csrf': verifier.verify_csrf,
        'airtable base id exposure': verifier.verify_airtable_base_id_exposure,
        'potential secret in javascript': verifier.verify_potential_secret_in_javascript,
    }
    
    print("\nAvailable methods:")
    for method_name in verification_methods.keys():
        print(f"  - '{method_name}'")
    
    print(f"\nDirect lookup result:")
    method = verification_methods.get(vuln_type)
    print(f"Method found: {method is not None}")
    
    if method:
        print("✅ Method exists! Testing verification...")
        result = verifier.verify_vulnerability(test_vuln)
        print(f"Result: {result}")
    else:
        print("❌ Method not found!")
        print("Checking for partial matches...")
        
        for method_name in verification_methods.keys():
            if vuln_type in method_name or method_name in vuln_type:
                print(f"  Partial match: '{method_name}'")

if __name__ == "__main__":
    debug_type_matching()
