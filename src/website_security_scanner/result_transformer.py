"""
Transforms raw scan results into a structured format for professional reporting.
"""

from datetime import datetime
from typing import Any, List
from urllib.parse import urlparse

from .utils.confidence_scoring import compute_confidence_score


def _normalize_evidence(evidence: Any) -> List[Any]:
    if evidence is None:
        return []
    if isinstance(evidence, list):
        return evidence
    return [evidence]


def _normalize_severity(severity: Any) -> str:
    if not severity:
        return "Info"
    sev = str(severity).lower()
    if sev in {"critical", "high", "medium", "low"}:
        return sev.title()
    if sev in {"info", "information"}:
        return "Info"
    return "Info"


def _safe_duration(start_timestamp: Any) -> str:
    if not start_timestamp:
        return "N/A"
    try:
        start_dt = datetime.fromisoformat(str(start_timestamp))
        return str(datetime.now() - start_dt)
    except Exception:
        return "N/A"


def calculate_risk_level(vulnerabilities):
    """Calculate risk level using weighted severity and confidence."""
    if not vulnerabilities:
        return "Low"

    severity_weights = {
        'critical': 10.0,
        'high': 7.5,
        'medium': 5.0,
        'low': 2.5,
        'info': 1.0
    }

    confidence_multipliers = {
        'certain': 1.0,
        'firm': 0.8,
        'tentative': 0.5
    }

    total_score = 0.0
    max_possible_score = 0.0

    for vuln in vulnerabilities:
        severity = vuln.get('severity', 'info').lower()
        confidence = vuln.get('confidence', 'tentative').lower()
        if severity in severity_weights and confidence in confidence_multipliers:
            weight = severity_weights[severity]
            total_score += weight * confidence_multipliers[confidence]
            max_possible_score += weight * 1.0

    normalized_score = 0.0
    if max_possible_score > 0:
        normalized_score = min(100.0, (total_score / max_possible_score) * 100)

    if normalized_score >= 80:
        return "Critical"
    elif normalized_score >= 60:
        return "High"
    elif normalized_score >= 40:
        return "Medium"
    elif normalized_score >= 20:
        return "Low"
    else:
        return "Minimal"


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
        evidence_list = _normalize_evidence(vuln.get("evidence"))
        # Prefer analyzer-provided instances; otherwise build a single instance
        instances = vuln.get("instances")
        if not instances:
            instances = [{
                "url": base_url,
                "request": vuln.get("request"),
                "response": vuln.get("response"),
                "evidence": evidence_list,
            }]

        vulnerabilities.append({
            "title": vuln.get("type", "Unnamed Vulnerability"),
            "severity": _normalize_severity(vuln.get("severity", "info")),
            "confidence": vuln.get("confidence", "tentative"),
            "description": vuln.get("description", "No details available."),
            "category": vuln.get("category", "General"),
            "owasp": vuln.get("owasp", vuln.get("owasp_category", "N/A")),
            "recommendation": vuln.get("recommendation", ""),
            "evidence": evidence_list,
            # New enriched fields for background, impact and external references
            "background": vuln.get("background"),
            "impact": vuln.get("impact"),
            "references": vuln.get("references", []),
            # Normalized host/path for better reporting
            "host": parsed.hostname if parsed else base_url,
            "path": parsed.path if parsed else "/",
            "cwe": vuln.get('cwe', []),
            "capec": vuln.get('capec', []),
            "verification": vuln.get("verification", {}),
            "evidence_verification": vuln.get("evidence_verification", {}),
            "platform": raw_results.get("platform_type", "unknown"),
            **compute_confidence_score(vuln),
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
    platform = raw_results.get("platform_type", "unknown")
    specific_findings = (
        raw_results.get(f"{platform}_specific")
        or raw_results.get(f"{platform}_specific_findings")
    )
    if platform == "generic":
        specific_findings = specific_findings or raw_results.get("generic_analysis") or raw_results.get("generic_findings")

    structured_data = {
        "scan_metadata": {
            "url": raw_results.get("url"),
            "timestamp": raw_results.get("timestamp"),
            "end_timestamp": datetime.now().isoformat(),  # Assuming scan ends now
            "duration": _safe_duration(raw_results.get("timestamp")),
            "scanner_version": "1.0-professional",
            "status_code": raw_results.get("status_code"),
            "response_time": raw_results.get("response_time"),
            "verification_summary": raw_results.get("verification_summary", {}),
            "evidence_verification_summary": raw_results.get("evidence_verification_summary", {}),
            "scan_warnings": raw_results.get("scan_warnings", []),
            "scan_profile": raw_results.get("scan_profile", {}),
            "scan_profile_hash": raw_results.get("scan_profile_hash", "N/A"),
            "dataset_version": raw_results.get("dataset_version", "N/A"),
            "git_commit": raw_results.get("git_commit", "N/A"),
        },
        "platform_analysis": {
            "platform_type": platform,
            "technology_stack": [],  # This might need more logic to populate
            "specific_findings": specific_findings or {},
            "platform_detection": raw_results.get("platform_detection", {}),
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
                "security_score": raw_results.get("security_headers", {}).get("security_score"),
                "raw_headers": raw_results.get("security_headers", {}),
            },
            "ssl_tls_analysis": raw_results.get("ssl_analysis", {}),
            "overall_score": raw_results.get("security_score", 100),
            "risk_level": calculate_risk_level(vulnerabilities),
            # Add other assessment areas if needed
        },
    }
    
    return structured_data
