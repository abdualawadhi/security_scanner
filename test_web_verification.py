#!/usr/bin/env python3
"""
Test verification via web API
"""

import requests
import json

def test_web_verification():
    """Test the web interface verification"""
    
    # Start a scan with verification enabled
    scan_data = {
        "url": "https://airtable.com/app5oLkwSi8gaXUod/",
        "verify_vulnerabilities": True
    }
    
    try:
        response = requests.post(
            "http://localhost:8080/api/scan/single",
            headers={"Content-Type": "application/json"},
            json=scan_data
        )
        
        if response.status_code == 200:
            result = response.json()
            scan_id = result.get('scan_id')
            print(f"✅ Scan started successfully with ID: {scan_id}")
            print(f"✅ Verification enabled: {scan_data['verify_vulnerabilities']}")
            
            # Wait a bit and check the results
            import time
            time.sleep(15)  # Wait for scan to complete
            
            # Check scan results
            results_response = requests.get(f"http://localhost:8080/api/scan/{scan_id}/results")
            if results_response.status_code == 200:
                results = results_response.json()
                
                vulnerabilities = results.get('vulnerabilities', [])
                print(f"\n📊 Found {len(vulnerabilities)} vulnerabilities")
                
                # Check first few vulnerabilities for verification data
                for i, vuln in enumerate(vulnerabilities[:5]):
                    print(f"\n{i+1}. {vuln.get('type', 'Unknown')}")
                    print(f"   Severity: {vuln.get('severity', 'Unknown')}")
                    
                    # Check verification data
                    verification = vuln.get('verification', {})
                    if verification:
                        print(f"   ✅ Verified: {verification.get('verified', 'Unknown')}")
                        print(f"   📋 Evidence: {verification.get('evidence', 'No evidence')}")
                        print(f"   🔧 Method: {verification.get('method', 'Unknown')}")
                    else:
                        print(f"   ❌ No verification data found")
                    
                    # Also check direct verification field
                    if 'verified' in vuln:
                        print(f"   📌 Direct verified field: {vuln['verified']}")
                        
            else:
                print(f"❌ Failed to get scan results: {results_response.status_code}")
                
        else:
            print(f"❌ Failed to start scan: {response.status_code}")
            print(f"Response: {response.text}")
            
    except Exception as e:
        print(f"❌ Error: {e}")

if __name__ == "__main__":
    test_web_verification()
