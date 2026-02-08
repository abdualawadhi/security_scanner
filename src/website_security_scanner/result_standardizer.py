"""
Centralized standardizer for security scan results, scoring, and risk assessment.
Provides consistent normalization and calculations across CLI, Web, and Reporting interfaces.
"""

from typing import Dict, List, Any, Union
import math

# Standard severity order
SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Info"]

# Severity weights for scoring (higher = more severe)
SEVERITY_WEIGHTS = {
    'critical': 10.0,
    'high': 7.5,
    'medium': 5.0,
    'low': 2.5,
    'info': 0.0
}

# Confidence multipliers for scoring
CONFIDENCE_MULTIPLIERS = {
    'certain': 1.0,
    'firm': 0.8,
    'tentative': 0.5
}

def normalize_severity(severity: Any) -> str:
    """Standardize severity labels to Title Case."""
    if not severity:
        return "Info"
    sev = str(severity).lower().strip()
    if sev in {"critical", "high", "medium", "low"}:
        return sev.title()
    if sev in {"info", "information", "informational"}:
        return "Info"
    return "Info"

def calculate_overall_score(vulnerabilities: List[Dict[str, Any]]) -> float:
    """
    Calculate an overall security score from 0-100.
    
    The score represents the 'vulnerability density' or 'security risk level'.
    0 = Perfect (no vulnerabilities)
    100 = Critical (high density of severe, verified vulnerabilities)
    
    NOTE: This is a 'risk score', where higher means MORE risk.
    """
    if not vulnerabilities:
        return 0.0

    total_weighted_risk = 0.0
    
    # We want a formula that reflects both the count and severity
    # but doesn't grow linearly forever. We use a sigmoid-like approach
    # or a capped sum.
    
    for vuln in vulnerabilities:
        sev = normalize_severity(vuln.get('severity', 'info')).lower()
        conf = str(vuln.get('confidence', 'tentative')).lower()
        
        weight = SEVERITY_WEIGHTS.get(sev, 0.0)
        multiplier = CONFIDENCE_MULTIPLIERS.get(conf, 0.5)
        
        total_weighted_risk += weight * multiplier

    # Logarithmic scaling to map to 0-100
    # A single Critical Certain vulnerability (10.0) should be around 40-50
    # Multiple vulnerabilities should push it towards 100
    if total_weighted_risk == 0:
        return 0.0
        
    # score = 100 * (1 - e^(-total_weighted_risk / 20))
    # With /20: 
    #   Risk 10 (1 Critical) -> 39.3
    #   Risk 20 (2 Critical) -> 63.2
    #   Risk 50 (5 Critical) -> 91.8
    score = 100 * (1 - math.exp(-total_weighted_risk / 25.0))
    
    return round(score, 2)

def calculate_risk_level(score: float) -> str:
    """
    Map a 0-100 score to a human-readable risk level.
    Higher score = Higher risk.
    """
    if score >= 80:
        return "Critical"
    elif score >= 60:
        return "High"
    elif score >= 40:
        return "Medium"
    elif score >= 20:
        return "Low"
    elif score > 0:
        return "Minimal"
    else:
        return "None"

def normalize_vulnerability(vuln: Dict[str, Any]) -> Dict[str, Any]:
    """Ensure a vulnerability has all standard fields and normalized values."""
    vuln['severity'] = normalize_severity(vuln.get('severity', 'Info'))
    vuln['confidence'] = str(vuln.get('confidence', 'tentative')).lower()
    if vuln['confidence'] not in CONFIDENCE_MULTIPLIERS:
        vuln['confidence'] = 'tentative'
    
    return vuln

def normalize_scan_results(results: Dict[str, Any]) -> Dict[str, Any]:
    """
    Transform and normalize an entire scan result object.
    Updates vulnerabilities, calculates real scores, and preserves metadata.
    """
    # 1. Normalize vulnerabilities
    vulnerabilities = results.get('vulnerabilities', [])
    normalized_vulns = [normalize_vulnerability(v) for v in vulnerabilities]
    results['vulnerabilities'] = normalized_vulns
    
    # 2. Calculate actual scores
    overall_score = calculate_overall_score(normalized_vulns)
    results['security_score'] = overall_score
    results['risk_level'] = calculate_risk_level(overall_score)
    
    # 3. Ensure executive summary is updated if present
    if 'executive_summary' in results:
        results['executive_summary']['total_vulnerabilities'] = len(normalized_vulns)
        results['executive_summary']['critical'] = sum(1 for v in normalized_vulns if v['severity'] == 'Critical')
        results['executive_summary']['high'] = sum(1 for v in normalized_vulns if v['severity'] == 'High')
        results['executive_summary']['medium'] = sum(1 for v in normalized_vulns if v['severity'] == 'Medium')
        results['executive_summary']['low'] = sum(1 for v in normalized_vulns if v['severity'] == 'Low')
        results['executive_summary']['info'] = sum(1 for v in normalized_vulns if v['severity'] == 'Info')
        
    return results
