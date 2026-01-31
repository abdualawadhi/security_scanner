#!/usr/bin/env python3
"""
Test script for enhanced vulnerability detection
Verifies that the new XSS, SQLi, CSRF, and Open Redirect detectors work correctly.
"""

import sys
import os

# Add the src directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

import requests
from bs4 import BeautifulSoup
from website_security_scanner.analyzers.outsystems import OutSystemsAnalyzer
from website_security_scanner.analyzers.airtable import AirtableAnalyzer
from website_security_scanner.analyzers.bubble import BubbleAnalyzer


def test_detector_imports():
    """Test that all detectors are properly imported"""
    print("Testing detector imports...")
    
    try:
        from website_security_scanner.analyzers.vulnerability_detection import (
            XSSDetector,
            SQLInjectionDetector,
            CSRFDetector,
            OpenRedirectDetector,
        )
        print("✓ All vulnerability detectors imported successfully")
        return True
    except Exception as e:
        print(f"✗ Failed to import detectors: {e}")
        return False


def test_outsystems_analyzer():
    """Test OutSystems analyzer with new detectors"""
    print("\nTesting OutSystems analyzer...")
    
    try:
        session = requests.Session()
        analyzer = OutSystemsAnalyzer(session)
        
        # Check that detectors are initialized
        assert hasattr(analyzer, 'xss_detector'), "XSSDetector not initialized"
        assert hasattr(analyzer, 'sqli_detector'), "SQLInjectionDetector not initialized"
        assert hasattr(analyzer, 'csrf_detector'), "CSRFDetector not initialized"
        assert hasattr(analyzer, 'redirect_detector'), "OpenRedirectDetector not initialized"
        
        print("✓ OutSystems analyzer initialized with all detectors")
        return True
    except Exception as e:
        print(f"✗ OutSystems analyzer test failed: {e}")
        return False


def test_airtable_analyzer():
    """Test Airtable analyzer with new detectors"""
    print("\nTesting Airtable analyzer...")
    
    try:
        session = requests.Session()
        analyzer = AirtableAnalyzer(session)
        
        # Check that detectors are initialized
        assert hasattr(analyzer, 'xss_detector'), "XSSDetector not initialized"
        assert hasattr(analyzer, 'sqli_detector'), "SQLInjectionDetector not initialized"
        assert hasattr(analyzer, 'csrf_detector'), "CSRFDetector not initialized"
        assert hasattr(analyzer, 'redirect_detector'), "OpenRedirectDetector not initialized"
        
        print("✓ Airtable analyzer initialized with all detectors")
        return True
    except Exception as e:
        print(f"✗ Airtable analyzer test failed: {e}")
        return False


def test_bubble_analyzer():
    """Test Bubble analyzer with new detectors"""
    print("\nTesting Bubble analyzer...")
    
    try:
        session = requests.Session()
        analyzer = BubbleAnalyzer(session)
        
        # Check that detectors are initialized
        assert hasattr(analyzer, 'xss_detector'), "XSSDetector not initialized"
        assert hasattr(analyzer, 'sqli_detector'), "SQLInjectionDetector not initialized"
        assert hasattr(analyzer, 'csrf_detector'), "CSRFDetector not initialized"
        assert hasattr(analyzer, 'redirect_detector'), "OpenRedirectDetector not initialized"
        
        print("✓ Bubble analyzer initialized with all detectors")
        return True
    except Exception as e:
        print(f"✗ Bubble analyzer test failed: {e}")
        return False


def test_xss_detector():
    """Test XSS detector with a mock response"""
    print("\nTesting XSS Detector...")
    
    try:
        from website_security_scanner.analyzers.vulnerability_detection import XSSDetector
        
        session = requests.Session()
        detector = XSSDetector(session)
        
        # Verify detector attributes
        assert hasattr(detector, 'REFLECTED_PAYLOADS'), "Missing REFLECTED_PAYLOADS"
        assert hasattr(detector, 'DOM_PAYLOADS'), "Missing DOM_PAYLOADS"
        assert hasattr(detector, 'detect_reflected_xss'), "Missing detect_reflected_xss method"
        assert hasattr(detector, 'detect_dom_xss'), "Missing detect_dom_xss method"
        
        # Check payload counts
        assert len(detector.REFLECTED_PAYLOADS) > 20, "Insufficient XSS payloads"
        assert len(detector.DOM_PAYLOADS) > 0, "Missing DOM XSS payloads"
        
        print(f"✓ XSS Detector loaded with {len(detector.REFLECTED_PAYLOADS)} reflected payloads and {len(detector.DOM_PAYLOADS)} DOM payloads")
        return True
    except Exception as e:
        print(f"✗ XSS detector test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_sqli_detector():
    """Test SQL Injection detector"""
    print("\nTesting SQL Injection Detector...")
    
    try:
        from website_security_scanner.analyzers.vulnerability_detection import SQLInjectionDetector
        
        session = requests.Session()
        detector = SQLInjectionDetector(session)
        
        # Verify detector attributes
        assert hasattr(detector, 'SQLI_PAYLOADS'), "Missing SQLI_PAYLOADS"
        assert hasattr(detector, 'SQL_ERROR_PATTERNS'), "Missing SQL_ERROR_PATTERNS"
        assert hasattr(detector, 'detect_sql_injection'), "Missing detect_sql_injection method"
        
        # Check payload counts
        assert len(detector.SQLI_PAYLOADS) > 10, "Insufficient SQLi payloads"
        assert len(detector.SQL_ERROR_PATTERNS) > 0, "Missing SQL error patterns"
        
        print(f"✓ SQL Injection Detector loaded with {len(detector.SQLI_PAYLOADS)} payloads and {len(detector.SQL_ERROR_PATTERNS)} error patterns")
        return True
    except Exception as e:
        print(f"✗ SQL Injection detector test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_csrf_detector():
    """Test CSRF detector"""
    print("\nTesting CSRF Detector...")
    
    try:
        from website_security_scanner.analyzers.vulnerability_detection import CSRFDetector
        
        session = requests.Session()
        detector = CSRFDetector(session)
        
        # Verify detector attributes
        assert hasattr(detector, 'CSRF_TOKEN_PATTERNS'), "Missing CSRF_TOKEN_PATTERNS"
        assert hasattr(detector, 'STATE_CHANGING_METHODS'), "Missing STATE_CHANGING_METHODS"
        assert hasattr(detector, 'detect_csrf'), "Missing detect_csrf method"
        
        # Check configuration
        assert len(detector.CSRF_TOKEN_PATTERNS) > 0, "Missing CSRF token patterns"
        assert len(detector.STATE_CHANGING_METHODS) > 0, "Missing state-changing methods"
        
        print(f"✓ CSRF Detector loaded with {len(detector.CSRF_TOKEN_PATTERNS)} token patterns and {len(detector.STATE_CHANGING_METHODS)} state-changing methods")
        return True
    except Exception as e:
        print(f"✗ CSRF detector test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_open_redirect_detector():
    """Test Open Redirect detector"""
    print("\nTesting Open Redirect Detector...")
    
    try:
        from website_security_scanner.analyzers.vulnerability_detection import OpenRedirectDetector
        
        session = requests.Session()
        detector = OpenRedirectDetector(session)
        
        # Verify detector attributes
        assert hasattr(detector, 'REDIRECT_PAYLOADS'), "Missing REDIRECT_PAYLOADS"
        assert hasattr(detector, 'detect_open_redirect'), "Missing detect_open_redirect method"
        
        # Check payload counts
        assert len(detector.REDIRECT_PAYLOADS) > 5, "Insufficient redirect payloads"
        
        print(f"✓ Open Redirect Detector loaded with {len(detector.REDIRECT_PAYLOADS)} payloads")
        return True
    except Exception as e:
        print(f"✗ Open Redirect detector test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def run_all_tests():
    """Run all tests and report results"""
    print("=" * 70)
    print("ENHANCED VULNERABILITY DETECTION TEST SUITE")
    print("=" * 70)
    
    tests = [
        test_detector_imports,
        test_outsystems_analyzer,
        test_airtable_analyzer,
        test_bubble_analyzer,
        test_xss_detector,
        test_sqli_detector,
        test_csrf_detector,
        test_open_redirect_detector,
    ]
    
    results = []
    for test in tests:
        results.append(test())
    
    print("\n" + "=" * 70)
    print("TEST SUMMARY")
    print("=" * 70)
    
    passed = sum(results)
    total = len(results)
    
    print(f"Passed: {passed}/{total}")
    print(f"Failed: {total - passed}/{total}")
    
    if passed == total:
        print("\n✓ All tests passed! Enhanced vulnerability detection is ready.")
        return 0
    else:
        print(f"\n✗ {total - passed} test(s) failed. Please review the errors above.")
        return 1


if __name__ == "__main__":
    sys.exit(run_all_tests())
