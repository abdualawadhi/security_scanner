"""
Transforms raw scan results into a structured format for professional reporting.
"""

from datetime import datetime

def transform_results_for_professional_report(raw_results):
    """
    Transforms the raw scan data from the scanner into a format suitable for the
    ProfessionalReportGenerator.
    
    Args:
        raw_results (dict): The raw results from the LowCodeSecurityScanner.

    Returns:
        dict: A structured dictionary for professional reporting.
    """
    
    # Map raw vulnerabilities to the detailed format
    vulnerabilities = []
    for vuln in raw_results.get('vulnerabilities', []):
        vulnerabilities.append({
            "title": vuln.get("type", "Unnamed Vulnerability"),
            "severity": vuln.get("severity", "info"),
            "confidence": vuln.get("confidence", "tentative"),
            "description": vuln.get("description", "No details available."),
            "host": raw_results.get('url'),
            "path": urlparse(raw_results.get('url')).path,
            "cwe": vuln.get('cwe', []),
            "capec": vuln.get('capec', []),
            "instances": [{
                "url": raw_results.get('url'),
                "request": vuln.get('request'),
                "response": vuln.get('response'),
                "evidence": vuln.get('evidence', [])
            }]
        })

    # Basic transformation for security headers
    headers_present = {}
    headers_missing = []
    raw_headers = raw_results.get("security_headers", {})
    for header, value in raw_headers.items():
        if header != "security_score":
            if value == "Missing":
                headers_missing.append({"name": header})
            else:
                headers_present[header] = {"value": value}

    # Assemble the structured data
    structured_data = {
        "scan_metadata": {
            "url": raw_results.get("url"),
            "timestamp": raw_results.get("timestamp"),
            "end_timestamp": datetime.now().isoformat(),  # Assuming scan ends now
            "duration": str(datetime.now() - datetime.fromisoformat(raw_results.get("timestamp"))),
            "scanner_version": "1.0-professional",
            "status_code": raw_results.get("status_code"),
            "response_time": raw_results.get("response_time"),
        },
        "platform_analysis": {
            "platform_type": raw_results.get("platform_type", "unknown"),
            "technology_stack": [],  # This might need more logic to populate
            "specific_findings": raw_results.get(f'{raw_results.get("platform_type")}_specific', {}),
        },
        "executive_summary": {
            "total_vulnerabilities": len(vulnerabilities),
            "high": sum(1 for v in vulnerabilities if v['severity'].lower() == 'high'),
            "medium": sum(1 for v in vulnerabilities if v['severity'].lower() == 'medium'),
            "low": sum(1 for v in vulnerabilities if v['severity'].lower() == 'low'),
        },
        "security_assessment": {
            "vulnerabilities": vulnerabilities,
            "security_headers": {
                "headers_present": headers_present,
                "headers_missing": headers_missing,
                "recommendations": raw_results.get("recommendations", []),
            },
            "ssl_tls_analysis": raw_results.get("ssl_analysis", {}),
            # Add other assessment areas if needed
        },
    }
    
    return structured_data

from urllib.parse import urlparse
