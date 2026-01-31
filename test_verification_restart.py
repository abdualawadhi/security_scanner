#!/usr/bin/env python3
"""
Test verification after server restart
"""

import requests
import time

def test_verification_restart():
    """Test verification after restarting the server"""
    
    # Start scan
    response = requests.post('http://localhost:8080/api/scan/single', json={
        'url': 'https://airtable.com/app5oLkwSi8gaXUod/',
        'verify_vulnerabilities': True
    })
    
    if response.status_code == 200:
        scan_id = response.json()['scan_id']
        print(f'✅ Scan started: {scan_id}')
        
        # Wait for completion
        for i in range(30):  # Wait up to 30 seconds
            time.sleep(1)
            try:
                result_response = requests.get(f'http://localhost:8080/api/scan/{scan_id}/results')
                if result_response.status_code == 200:
                    results = result_response.json()
                    vulns = results.get('vulnerabilities', [])
                    print(f'✅ Scan completed! Found {len(vulns)} vulnerabilities')
                    
                    # Check first few vulnerabilities for verification
                    for j, vuln in enumerate(vulns[:3]):
                        print(f'\n{j+1}. {vuln.get("type", "Unknown")}')
                        print(f'   Severity: {vuln.get("severity", "Unknown")}')
                        
                        # Check verification data
                        verification = vuln.get('verification', {})
                        if verification:
                            print(f'   ✅ Verification data found:')
                            print(f'      Verified: {verification.get("verified", "Unknown")}')
                            print(f'      Evidence: {verification.get("evidence", "No evidence")}')
                            print(f'      Method: {verification.get("method", "Unknown")}')
                        else:
                            print(f'   ❌ No verification data')
                        
                        # Check verification reason
                        reason = vuln.get('verification_reason', '')
                        if reason:
                            print(f'   📋 Reason: {reason}')
                        
                        # Check direct verified field
                        if 'verified' in vuln:
                            print(f'   📌 Direct verified: {vuln["verified"]}')
                    
                    break
            except Exception as e:
                print(f'Waiting... ({i+1}/30)')
                continue
        else:
            print('❌ Scan did not complete in time')
    else:
        print(f'❌ Failed to start scan: {response.status_code}')
        print(f'Response: {response.text}')

if __name__ == "__main__":
    test_verification_restart()
