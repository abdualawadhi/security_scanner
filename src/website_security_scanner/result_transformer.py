"""
Transforms raw scan results into a structured format for professional reporting.
"""

from datetime import datetime
from urllib.parse import urlparse


def calculate_risk_level(vulnerabilities):
    """Calculate risk level based on vulnerability counts"""
    critical = sum(1 for v in vulnerabilities if v['severity'].lower() == 'critical')
    high = sum(1 for v in vulnerabilities if v['severity'].lower() == 'high')
    medium = sum(1 for v in vulnerabilities if v['severity'].lower() == 'medium')
    
    if critical > 0 or high > 10:
        return "Critical"
    elif high > 5 or medium > 10:
        return "High"
    elif medium > 3 or high > 0:
        return "Medium"
    else:
        return "Low"


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
    base_url = raw_results.get('url')
    parsed = urlparse(base_url) if base_url else None

    for vuln in raw_results.get('vulnerabilities', []):
        # Prefer analyzer-provided instances; otherwise build a single instance
        instances = vuln.get("instances")
        if not instances:
            instances = [{
                "url": base_url,
                "request": vuln.get("request"),
                "response": vuln.get("response"),
                "evidence": vuln.get("evidence", []),
            }]

        vulnerabilities.append({
            "title": vuln.get("type", "Unnamed Vulnerability"),
            "severity": vuln.get("severity", "info"),
            "confidence": vuln.get("confidence", "tentative"),
            "description": vuln.get("description", "No details available."),
            # New enriched fields for background, impact and external references
            "background": vuln.get("background"),
            "impact": vuln.get("impact"),
            "references": vuln.get("references", []),
            # Normalized host/path for better reporting
            "host": parsed.hostname if parsed else base_url,
            "path": parsed.path if parsed else "/",
            "cwe": vuln.get('cwe', []),
            "capec": vuln.get('capec', []),
            "instances": instances,
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
            "overall_score": raw_results.get("security_score", 100),
            "risk_level": calculate_risk_level(vulnerabilities),
            # Add other assessment areas if needed
        },
    }
    
    return structured_data

from urllib.parse import urlparse
