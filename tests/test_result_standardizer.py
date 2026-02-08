import pytest
import math
from website_security_scanner.result_standardizer import (
    normalize_severity,
    calculate_overall_score,
    calculate_risk_level,
    normalize_vulnerability,
    normalize_scan_results
)

def test_normalize_severity():
    assert normalize_severity("critical") == "Critical"
    assert normalize_severity("CRITICAL") == "Critical"
    assert normalize_severity("High") == "High"
    assert normalize_severity("medium") == "Medium"
    assert normalize_severity("low") == "Low"
    assert normalize_severity("info") == "Info"
    assert normalize_severity("information") == "Info"
    assert normalize_severity(None) == "Info"
    assert normalize_severity("") == "Info"
    assert normalize_severity("unknown") == "Info"

def test_calculate_overall_score_empty():
    assert calculate_overall_score([]) == 0.0

def test_calculate_overall_score_single_critical():
    vulns = [{'severity': 'Critical', 'confidence': 'certain'}]
    score = calculate_overall_score(vulns)
    # total_weighted_risk = 10.0 * 1.0 = 10.0
    # score = 100 * (1 - exp(-10.0/25.0)) = 100 * (1 - exp(-0.4)) = 100 * (1 - 0.67032) = 32.968
    assert math.isclose(score, 32.97, rel_tol=1e-2)

def test_calculate_risk_level():
    assert calculate_risk_level(0) == "None"
    assert calculate_risk_level(10) == "Minimal"
    assert calculate_risk_level(30) == "Low"
    assert calculate_risk_level(50) == "Medium"
    assert calculate_risk_level(70) == "High"
    assert calculate_risk_level(90) == "Critical"

def test_normalize_vulnerability():
    vuln = {'severity': 'high', 'confidence': 'FIRm'}
    normalized = normalize_vulnerability(vuln)
    assert normalized['severity'] == "High"
    assert normalized['confidence'] == "firm"

def test_normalize_scan_results():
    results = {
        'vulnerabilities': [
            {'severity': 'critical', 'confidence': 'certain'},
            {'severity': 'high', 'confidence': 'firm'}
        ],
        'executive_summary': {}
    }
    normalized = normalize_scan_results(results)
    assert normalized['security_score'] > 0
    assert normalized['risk_level'] != "None"
    assert normalized['executive_summary']['total_vulnerabilities'] == 2
    assert normalized['executive_summary']['critical'] == 1
    assert normalized['executive_summary']['high'] == 1
    assert normalized['vulnerabilities'][0]['severity'] == "Critical"
