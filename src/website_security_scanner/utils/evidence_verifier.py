#!/usr/bin/env python3
"""
Live Evidence Verification System
Low-Code Platform Security Scanner

Provides real-time evidence verification with cryptographic hashing,
timestamping, and stale evidence detection for professional-grade
vulnerability reporting.

Author: Bachelor Thesis Project - Low-Code Platforms Security Analysis
"""

import hashlib
import json
import re
import time
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse, parse_qs

import requests

from ..utils.logger import get_logger

logger = get_logger('evidence_verifier')


class EvidenceVerifier:
    """
    Verifies vulnerability evidence in real-time with cryptographic hashing
    and timestamping to ensure evidence integrity and freshness.
    """
    
    # Evidence is considered stale after this duration
    STALE_THRESHOLD_HOURS = 24
    
    # Verification confidence levels
    CONFIDENCE_VERIFIED = "verified"
    CONFIDENCE_STALE = "stale"
    CONFIDENCE_UNVERIFIED = "unverified"
    CONFIDENCE_FAILED = "failed"
    
    def __init__(self, session: requests.Session, timeout: int = 10):
        """
        Initialize evidence verifier.
        
        Args:
            session: Configured requests session
            timeout: Request timeout in seconds
        """
        self.session = session
        self.timeout = timeout
        self._verification_cache: Dict[str, Dict] = {}
    
    def verify_evidence(
        self,
        vulnerability: Dict[str, Any],
        url: str,
        original_response: Optional[requests.Response] = None
    ) -> Dict[str, Any]:
        """
        Verify evidence for a vulnerability in real-time.
        
        Args:
            vulnerability: Vulnerability dictionary containing evidence
            url: Target URL
            original_response: Original HTTP response (optional)
            
        Returns:
            Enhanced vulnerability with verification metadata
        """
        vuln_copy = vulnerability.copy()
        evidence = vuln_copy.get('evidence', '')
        vuln_type = vuln_copy.get('type', '')
        
        # Generate evidence hash
        evidence_hash = self._hash_evidence(evidence, url, vuln_type)
        
        # Create verification record
        verification_record = {
            'evidence_hash': evidence_hash,
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'url': url,
            'verification_status': self.CONFIDENCE_UNVERIFIED,
            'verification_method': 'static_analysis',
            'stale': False,
            'rechecked': False,
            'live_check_performed': False,
            'verification_state': 'Unverified',
        }
        
        # Attempt live verification for certain vulnerability types
        if self._should_attempt_live_verification(vuln_type):
            live_result = self._perform_live_verification(
                vuln_type, vulnerability, url, original_response
            )
            verification_record.update(live_result)
        
        # Check if evidence is stale (based on cache or age)
        if self._is_evidence_stale(url, evidence_hash, vuln_copy.get('timestamp')):
            verification_record['stale'] = True
            verification_record['verification_status'] = self.CONFIDENCE_STALE

        # Derive explicit verification state for reporting
        verification_record['verification_state'] = self._derive_verification_state(
            verification_record, evidence
        )
        
        # Add verification metadata to vulnerability
        vuln_copy['evidence_verification'] = verification_record
        
        # Cache the verification result
        self._cache_verification(url, evidence_hash, verification_record)
        
        return vuln_copy

    def _derive_verification_state(self, record: Dict[str, Any], evidence: Any) -> str:
        """Map verification results to explicit states."""
        status = record.get('verification_status')
        if status == self.CONFIDENCE_VERIFIED:
            return 'Confirmed'
        if status == self.CONFIDENCE_STALE:
            return 'Stale'
        if record.get('live_check_performed'):
            return 'Unverified'
        # Static analysis only
        if evidence:
            return 'Probable'
        return 'Unverified'
    
    def _hash_evidence(self, evidence: Any, url: str, vuln_type: str) -> str:
        """
        Create a cryptographic hash of the evidence.
        
        Args:
            evidence: Evidence data (string or dict)
            url: Target URL
            vuln_type: Type of vulnerability
            
        Returns:
            SHA-256 hash string
        """
        # Normalize evidence to string
        if isinstance(evidence, dict):
            evidence_str = json.dumps(evidence, sort_keys=True)
        elif isinstance(evidence, list):
            evidence_str = json.dumps(evidence, sort_keys=True)
        else:
            evidence_str = str(evidence)
        
        # Create hash from combined data
        hash_input = f"{url}|{vuln_type}|{evidence_str}"
        return hashlib.sha256(hash_input.encode('utf-8')).hexdigest()[:32]
    
    def _should_attempt_live_verification(self, vuln_type: str) -> bool:
        """
        Determine if live verification should be attempted for this vulnerability type.
        
        Args:
            vuln_type: Type of vulnerability
            
        Returns:
            True if live verification should be attempted
        """
        # Only attempt live verification for certain types
        live_verifiable_types = [
            'XSS', 'Cross-Site Scripting',
            'SQL Injection',
            'Open Redirect',
            'Missing Security Header',
            'Missing Content Security Policy',
            'Missing Clickjacking Protection',
            'Missing HSTS Header',
            'Cacheable HTTPS Response',
            'Session Token in URL',
            'Reflected Input',
            'Information Disclosure',
        ]
        
        vuln_type_lower = vuln_type.lower()
        return any(vt.lower() in vuln_type_lower for vt in live_verifiable_types)
    
    def _perform_live_verification(
        self,
        vuln_type: str,
        vulnerability: Dict[str, Any],
        url: str,
        original_response: Optional[requests.Response]
    ) -> Dict[str, Any]:
        """
        Perform live verification by re-requesting the resource.
        
        Args:
            vuln_type: Type of vulnerability
            vulnerability: Vulnerability dictionary
            url: Target URL
            original_response: Original response
            
        Returns:
            Verification result dictionary
        """
        result = {
            'live_check_performed': True,
            'rechecked': True,
        }
        
        try:
            # Make fresh request
            response = self.session.get(url, timeout=self.timeout, allow_redirects=True)
            result['status_code'] = response.status_code
            result['response_time_ms'] = int(response.elapsed.total_seconds() * 1000)
            
            # Type-specific verification
            if 'XSS' in vuln_type or 'Cross-Site Scripting' in vuln_type or 'Reflected Input' in vuln_type:
                verified = self._verify_reflected_xss(url, response, vulnerability)
            elif 'SQL Injection' in vuln_type:
                verified = self._verify_sql_injection(url, response, vulnerability)
            elif 'Open Redirect' in vuln_type:
                verified = self._verify_open_redirect(url, response, vulnerability)
            elif 'Missing Security Header' in vuln_type or 'Missing Content Security Policy' in vuln_type:
                verified = self._verify_security_headers(url, response, vulnerability)
            elif 'Session Token' in vuln_type:
                verified = self._verify_session_token_in_url(url, response, vulnerability)
            elif 'Cacheable HTTPS' in vuln_type:
                verified = self._verify_cacheable_https(url, response, vulnerability)
            elif 'Information Disclosure' in vuln_type:
                verified = self._verify_information_disclosure(url, response, vulnerability)
            else:
                # Generic verification - check if evidence still present
                verified = self._verify_evidence_still_present(
                    response, vulnerability.get('evidence', '')
                )
            
            result['verification_status'] = (
                self.CONFIDENCE_VERIFIED if verified else self.CONFIDENCE_UNVERIFIED
            )
            result['verification_method'] = 'live_recheck'
            
        except requests.RequestException as e:
            logger.debug(f"Live verification failed for {url}: {e}")
            result['verification_status'] = self.CONFIDENCE_FAILED
            result['verification_error'] = str(e)
            result['verification_method'] = 'live_recheck_failed'
        
        return result
    
    def _verify_reflected_xss(
        self, url: str, response: requests.Response, vulnerability: Dict
    ) -> bool:
        """Verify reflected XSS vulnerability."""
        # Check if original evidence pattern is still in response
        evidence = vulnerability.get('evidence', '')
        if isinstance(evidence, str) and evidence:
            # Extract parameter from evidence
            param_match = re.search(r'Parameter:\s*([^\s,]+)', evidence)
            if param_match:
                param = param_match.group(1)
                parsed = urlparse(url)
                params = parse_qs(parsed.query)
                if param in params:
                    # Parameter still in URL, check if reflected
                    return self._check_parameter_reflection(url, response, param)
        
        # Fallback: check if evidence pattern still exists
        return self._verify_evidence_still_present(response, evidence)
    
    def _verify_sql_injection(
        self, url: str, response: requests.Response, vulnerability: Dict
    ) -> bool:
        """Verify SQL injection vulnerability."""
        # Check for SQL error patterns in response
        sql_error_patterns = [
            r'sql syntax',
            r'mysql.*error',
            r'postgresql.*error',
            r'oracle.*error',
            r'odbc.*error',
            r'sqlite.*error',
        ]
        
        response_text = response.text.lower()
        return any(re.search(p, response_text, re.IGNORECASE) for p in sql_error_patterns)
    
    def _verify_open_redirect(
        self, url: str, response: requests.Response, vulnerability: Dict
    ) -> bool:
        """Verify open redirect vulnerability."""
        # Check if redirect parameters are still present
        evidence = vulnerability.get('evidence', '')
        if isinstance(evidence, str):
            param_match = re.search(r'Parameter:\s*(\w+)', evidence)
            if param_match:
                param = param_match.group(1)
                parsed = urlparse(url)
                params = parse_qs(parsed.query)
                return param in params
        return False
    
    def _verify_security_headers(
        self, url: str, response: requests.Response, vulnerability: Dict
    ) -> bool:
        """Verify missing security header vulnerability."""
        vuln_type = vulnerability.get('type', '').lower()
        headers = response.headers
        
        header_checks = {
            'content security policy': 'Content-Security-Policy',
            'csp': 'Content-Security-Policy',
            'x-frame-options': 'X-Frame-Options',
            'clickjacking': 'X-Frame-Options',
            'hsts': 'Strict-Transport-Security',
            'strict-transport-security': 'Strict-Transport-Security',
            'x-content-type-options': 'X-Content-Type-Options',
            'referrer-policy': 'Referrer-Policy',
        }
        
        for key, header_name in header_checks.items():
            if key in vuln_type:
                return header_name not in headers
        
        return True  # Default to verified if we can't determine
    
    def _verify_session_token_in_url(
        self, url: str, response: requests.Response, vulnerability: Dict
    ) -> bool:
        """Verify session token in URL vulnerability."""
        parsed = urlparse(url)
        sensitive_params = [
            'session', 'token', 'sid', 'sessionid', 'session_id',
            'session_code', 'state', 'nonce', 'auth_token', 'code',
            'access_token', 'id_token', 'refresh_token'
        ]
        
        query = parsed.query.lower()
        return any(f"{param}=" in query for param in sensitive_params)
    
    def _verify_cacheable_https(
        self, url: str, response: requests.Response, vulnerability: Dict
    ) -> bool:
        """Verify cacheable HTTPS response vulnerability."""
        if not url.lower().startswith('https://'):
            return False
        
        cache_control = response.headers.get('Cache-Control', '').lower()
        pragma = response.headers.get('Pragma', '').lower()
        
        has_no_store = 'no-store' in cache_control
        has_no_cache = 'no-cache' in cache_control or 'no-cache' in pragma
        is_private = 'private' in cache_control
        
        return not (has_no_store or has_no_cache or is_private)
    
    def _verify_information_disclosure(
        self, url: str, response: requests.Response, vulnerability: Dict
    ) -> bool:
        """Verify information disclosure vulnerability."""
        evidence = vulnerability.get('evidence', '')
        if isinstance(evidence, dict) and 'pattern' in evidence:
            pattern = evidence['pattern']
            return bool(re.search(pattern, response.text, re.IGNORECASE))
        return self._verify_evidence_still_present(response, evidence)
    
    def _check_parameter_reflection(
        self, url: str, response: requests.Response, param: str
    ) -> bool:
        """Check if a URL parameter value is reflected in the response."""
        from urllib.parse import parse_qs, urlparse
        
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        if param in params:
            for value in params[param]:
                if value and len(value) > 2 and value in response.text:
                    return True
        return False
    
    def _verify_evidence_still_present(
        self, response: requests.Response, evidence: Any
    ) -> bool:
        """
        Check if evidence pattern is still present in response.
        
        Args:
            response: HTTP response
            evidence: Evidence to search for
            
        Returns:
            True if evidence still present
        """
        if not evidence:
            return False
        
        response_text = response.text
        
        if isinstance(evidence, dict):
            # Handle structured evidence
            if 'pattern' in evidence:
                pattern = evidence['pattern']
                try:
                    return bool(re.search(pattern, response_text, re.IGNORECASE))
                except re.error:
                    return False
            elif 'text' in evidence:
                return evidence['text'] in response_text
        elif isinstance(evidence, str):
            # Simple string match
            if len(evidence) > 50:
                # For long evidence, check if a significant portion matches
                return evidence[:100] in response_text or evidence[-100:] in response_text
            return evidence in response_text
        
        return False
    
    def _is_evidence_stale(self, url: str, evidence_hash: str, vuln_timestamp: Optional[str] = None) -> bool:
        """
        Check if evidence is stale based on cache age.
        
        Args:
            url: Target URL
            evidence_hash: Hash of the evidence
            
        Returns:
            True if evidence is considered stale
        """
        # Check explicit vulnerability timestamp if available
        if vuln_timestamp:
            try:
                timestamp = datetime.fromisoformat(vuln_timestamp.replace('Z', '+00:00'))
                age = datetime.utcnow() - timestamp.replace(tzinfo=None)
                if age > timedelta(hours=self.STALE_THRESHOLD_HOURS):
                    return True
            except (ValueError, TypeError):
                pass

        cache_key = f"{url}:{evidence_hash}"
        cached = self._verification_cache.get(cache_key)
        
        if not cached:
            return False  # No cache, consider fresh
        
        try:
            timestamp = datetime.fromisoformat(cached['timestamp'].replace('Z', '+00:00'))
            age = datetime.utcnow() - timestamp.replace(tzinfo=None)
            return age > timedelta(hours=self.STALE_THRESHOLD_HOURS)
        except (ValueError, KeyError):
            return False
    
    def _cache_verification(self, url: str, evidence_hash: str, record: Dict):
        """
        Cache verification result.
        
        Args:
            url: Target URL
            evidence_hash: Hash of evidence
            record: Verification record
        """
        cache_key = f"{url}:{evidence_hash}"
        self._verification_cache[cache_key] = record
    
    def get_verification_summary(self, vulnerabilities: List[Dict]) -> Dict[str, Any]:
        """
        Generate summary of verification status across vulnerabilities.
        
        Args:
            vulnerabilities: List of vulnerabilities with verification
            
        Returns:
            Summary dictionary
        """
        total = len(vulnerabilities)
        verified = 0
        stale = 0
        unverified = 0
        failed = 0
        live_checked = 0
        
        for vuln in vulnerabilities:
            verification = vuln.get('evidence_verification', {})
            status = verification.get('verification_status', 'unverified')
            
            if verification.get('live_check_performed'):
                live_checked += 1
            
            if status == self.CONFIDENCE_VERIFIED:
                verified += 1
            elif status == self.CONFIDENCE_STALE:
                stale += 1
            elif status == self.CONFIDENCE_FAILED:
                failed += 1
            else:
                unverified += 1
        
        return {
            'total_vulnerabilities': total,
            'verified': verified,
            'stale': stale,
            'unverified': unverified,
            'failed': failed,
            'live_checked': live_checked,
            'verification_rate': round((verified / total * 100), 2) if total > 0 else 0,
        }


def verify_vulnerabilities(
    vulnerabilities: List[Dict],
    session: requests.Session,
    url: str,
    original_response: Optional[requests.Response] = None
) -> Tuple[List[Dict], Dict]:
    """
    Convenience function to verify multiple vulnerabilities.
    
    Args:
        vulnerabilities: List of vulnerabilities to verify
        session: Requests session
        url: Target URL
        original_response: Original HTTP response
        
    Returns:
        Tuple of (verified_vulnerabilities, summary)
    """
    verifier = EvidenceVerifier(session)
    verified_vulns = []
    
    for vuln in vulnerabilities:
        verified_vuln = verifier.verify_evidence(vuln, url, original_response)
        verified_vulns.append(verified_vuln)
    
    summary = verifier.get_verification_summary(verified_vulns)
    return verified_vulns, summary
