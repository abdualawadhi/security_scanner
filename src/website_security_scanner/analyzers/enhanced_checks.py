#!/usr/bin/env python3
"""
Enhanced Security Checks

Additional security checks extracted from the New folder analyzers
to provide comprehensive vulnerability detection capabilities.

Author: Bachelor Thesis Project - Low-Code Platforms Security Analysis
"""

import re
import requests
from typing import Dict, Any, List
from urllib.parse import urlparse
import ssl
import socket
from bs4 import BeautifulSoup


class EnhancedSecurityChecks:
    """
    Collection of enhanced security checks for comprehensive vulnerability detection.
    """
    
    def __init__(self, session: requests.Session):
        self.session = session
    
    def check_stripe_public_keys(self, js_content: str, url: str) -> List[Dict[str, Any]]:
        """Detect exposed Stripe publishable keys."""
        patterns = [
            r"pk_live_[0-9a-zA-Z]{16,}",
            r"pk_test_[0-9a-zA-Z]{16,}",
            r"stripe_public_key_live\"?\s*[:=]\s*\"(pk_[^\"]+)\"",
        ]
        
        findings = []
        matches = set()
        
        for pattern in patterns:
            for match in re.findall(pattern, js_content, re.IGNORECASE):
                key = match if isinstance(match, str) else "".join(match)
                if key:
                    matches.add(key)
        
        for key in sorted(matches):
            severity = "Medium" if key.startswith("pk_test_") else "High"
            findings.append({
                'type': 'Stripe Public Key Exposure',
                'severity': severity,
                'description': 'Stripe publishable key exposed in client-side JavaScript.',
                'evidence': key,
                'url': url,
                'category': 'Information Disclosure',
                'owasp': 'A02:2021 - Cryptographic Failures',
                'cwe': ['CWE-295'],
                'recommendation': 'Remove hardcoded payment keys from client-side code. Load publishable keys from secure configuration and monitor for misuse.'
            })
        
        return findings
    
    def check_http2_support(self, url: str) -> List[Dict[str, Any]]:
        """Check for HTTP/2 protocol support (Hidden HTTP/2)."""
        findings = []
        
        try:
            parsed = urlparse(url)
            hostname = parsed.hostname
            
            if hostname:
                # Check HTTP/2 support via ALPN
                context = ssl.create_default_context()
                context.set_alpn_protocols(['h2', 'http/1.1'])
                
                with socket.create_connection((hostname, 443), timeout=10) as sock:
                    with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                        alpn_protocol = ssock.selected_alpn_protocol()
                        
                        if alpn_protocol == 'h2':
                            findings.append({
                                'type': 'Hidden HTTP/2 Info',
                                'severity': 'Info',
                                'description': 'Origin advertises HTTP/2 (h2) via ALPN; ensure HTTP/2-specific hardening (HPACK/DoS controls, reverse-proxy config).',
                                'evidence': f'ALPN Protocol: {alpn_protocol}',
                                'url': url,
                                'category': 'Protocol Security',
                                'owasp': 'A05:2021 - Security Misconfiguration',
                                'cwe': ['CWE-16'],
                                'recommendation': 'Implement HTTP/2-specific security controls including HPACK compression limits, DoS protection, and proper reverse-proxy configuration.'
                            })
        
        except Exception:
            # Connection failed, skip check
            pass
        
        return findings
    
    def check_cloud_resources(self, content: str, url: str) -> List[Dict[str, Any]]:
        """Check for cloud resource exposure."""
        findings = []
        
        # Cloud service patterns
        cloud_patterns = {
            'AWS S3': [
                r's3\.amazonaws\.com/[a-zA-Z0-9\-]+',
                r'["\']([a-zA-Z0-9\-]+)\.s3\.amazonaws\.com["\']',
                r'aws_access_key_id["\']?\s*[:=]\s*["\']([A-Z0-9]{20})["\']',
                r'aws_secret_access_key["\']?\s*[:=]\s*["\']([a-zA-Z0-9+/]{40})["\']'
            ],
            'Google Cloud': [
                r'googleapis\.com/[a-zA-Z0-9\-]+',
                r'["\']([a-zA-Z0-9\-]+)@developer\.gserviceaccount\.com["\']',
                r'["\']([A-Za-z0-9_-]{25,})\.googleusercontent\.com["\']'
            ],
            'Azure': [
                r'azure\.net/[a-zA-Z0-9\-]+',
                r'["\']([a-zA-Z0-9\-]+)\.blob\.core\.windows\.net["\']',
                r'["\']([a-zA-Z0-9\-]+)\.azurewebsites\.net["\']'
            ],
            'Cloudflare': [
                r'cloudflare\.com/[a-zA-Z0-9\-]+',
                r'["\']([a-zA-Z0-9]{32})\.cloudflare\.com["\']'
            ]
        }
        
        for service, patterns in cloud_patterns.items():
            for pattern in patterns:
                matches = re.findall(pattern, content, re.IGNORECASE)
                for match in matches:
                    resource = match if isinstance(match, str) else "".join(match)
                    if resource:
                        severity = "High" if 'key' in pattern.lower() else "Medium"
                        findings.append({
                            'type': f'{service} Resource Exposure',
                            'severity': severity,
                            'description': f'{service} resource exposed in client-side code.',
                            'evidence': resource,
                            'url': url,
                            'category': 'Information Disclosure',
                            'owasp': 'A05:2021 - Security Misconfiguration',
                            'cwe': ['CWE-200'],
                            'recommendation': f'Remove hardcoded {service} credentials from client-side code. Use secure configuration management and implement proper access controls.'
                        })
        
        return findings
    
    def check_request_url_override(self, url: str) -> List[Dict[str, Any]]:
        """Check for request URL override vulnerabilities."""
        findings = []
        
        try:
            # Validate URL format first
            parsed = urlparse(url)
            if not parsed.scheme or not parsed.netloc:
                return findings  # Return empty list for malformed URLs
            
            test_payload = "test_override"
            
            # Test with various URL override techniques
            test_urls = [
                f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{test_payload}=1",
                f"{parsed.scheme}://{parsed.netloc}{parsed.path}#{test_payload}",
                f"{parsed.scheme}://{parsed.netloc}/{test_payload}{parsed.path}"
            ]
            
            for test_url in test_urls:
                try:
                    response = self.session.get(test_url, timeout=10)
                    
                    # Check if the server responded with the same content
                    # This indicates potential URL override vulnerability
                    if response.status_code == 200:
                        findings.append({
                            'type': 'Request URL Override',
                            'severity': 'Medium',
                            'description': 'Application may be vulnerable to request URL override attacks.',
                            'evidence': f'Test URL: {test_url}',
                            'url': url,
                            'category': 'Input Validation',
                            'owasp': 'A03:2021 - Injection',
                            'cwe': ['CWE-20'],
                            'recommendation': 'Implement proper URL validation and canonicalization. Reject requests with unexpected URL structures.'
                        })
                        break  # One finding is enough
                        
                except Exception:
                    continue
        
        except Exception as e:
            # Log error but don't crash the scan
            pass
        
        return findings
    
    def check_cookie_domain_scoping(self, response: requests.Response, url: str) -> List[Dict[str, Any]]:
        """Check for cookie domain scoping issues."""
        findings = []
        
        set_cookie_headers = response.headers.get('Set-Cookie', '')
        if set_cookie_headers:
            parsed_url = urlparse(url)
            current_domain = parsed_url.netloc
            
            # Check for cookies with overly broad domain scope
            cookies = set_cookie_headers.split(',')
            for cookie in cookies:
                cookie_parts = cookie.split(';')
                cookie_name = cookie_parts[0].split('=')[0].strip() if '=' in cookie_parts[0] else cookie_parts[0].strip()
                
                for part in cookie_parts[1:]:
                    part = part.strip()
                    if part.lower().startswith('domain='):
                        domain = part[7:].strip()
                        
                        # Check if domain is too broad
                        if domain.startswith('.') and len(domain.split('.')) <= 2:
                            findings.append({
                                'type': 'Cookie Domain Scoping Issue',
                                'severity': 'Medium',
                                'description': f'Cookie {cookie_name} has overly broad domain scope.',
                                'evidence': f'Domain: {domain}',
                                'url': url,
                                'category': 'Session Management',
                                'owasp': 'A07:2021 - Identification and Authentication Failures',
                                'cwe': ['CWE-1007'],
                                'recommendation': 'Set appropriate domain scope for cookies. Avoid using top-level domains unless absolutely necessary.'
                            })
        
        return findings
    
    def check_secret_uncached_url_input(self, url: str, response: requests.Response) -> List[Dict[str, Any]]:
        """Check for secret uncached URL input vulnerabilities."""
        findings = []
        
        try:
            # Validate URL format first
            parsed = urlparse(url)
            if not parsed.scheme or not parsed.netloc:
                return findings  # Return empty list for malformed URLs
            
            query_params = parse_qs(parsed.query)
            
            # Check for potential secrets in URL parameters
            secret_patterns = [
                ('token', r'[a-zA-Z0-9_-]{20,}'),
                ('key', r'[a-zA-Z0-9_-]{20,}'),
                ('secret', r'[a-zA-Z0-9_-]{20,}'),
                ('password', r'[a-zA-Z0-9_-]{10,}'),
                ('api_key', r'[a-zA-Z0-9_-]{20,}'),
                ('access_token', r'[a-zA-Z0-9._-]{20,}')
            ]
            
            for param_name, pattern in secret_patterns:
                if param_name in query_params:
                    values = query_params[param_name]
                    for value in values:
                        if re.match(pattern, value):
                            findings.append({
                                'type': 'Secret in URL Parameter',
                                'severity': 'High',
                                'description': f'Potential secret exposed in URL parameter: {param_name}',
                                'evidence': f'{param_name}={value[:10]}...',
                                'url': url,
                                'category': 'Information Disclosure',
                                'owasp': 'A09:2021 - Security Logging and Monitoring Failures',
                                'cwe': ['CWE-200'],
                                'recommendation': 'Avoid passing secrets in URL parameters. Use POST requests with proper authentication headers instead.'
                            })
        
        except Exception as e:
            # Log error but don't crash the scan
            pass
        
        return findings
    
    def check_dom_data_manipulation(self, js_content: str) -> List[Dict[str, Any]]:
        """Check for DOM data manipulation vulnerabilities."""
        findings = []
        
        # Look for dangerous DOM manipulation patterns
        dangerous_patterns = [
            (r'document\.write\s*\(\s*[^)]*\+[^)]*\)', 'Dynamic document.write with concatenation'),
            (r'innerHTML\s*=\s*[^;]*\+[^;]*', 'innerHTML with concatenation'),
            (r'outerHTML\s*=\s*[^;]*\+[^;]*', 'outerHTML with concatenation'),
            (r'eval\s*\(\s*[^)]*\+[^)]*\)', 'eval with concatenation'),
            (r'setTimeout\s*\(\s*["\'][^"\']*["\']\s*\+[^)]*\)', 'setTimeout with string concatenation'),
            (r'setInterval\s*\(\s*["\'][^"\']*["\']\s*\+[^)]*\)', 'setInterval with string concatenation')
        ]
        
        for pattern, description in dangerous_patterns:
            matches = re.findall(pattern, js_content, re.IGNORECASE)
            if matches:
                findings.append({
                    'type': 'DOM Data Manipulation',
                    'severity': 'High',
                    'description': f'DOM manipulation vulnerability: {description}',
                    'evidence': f'Pattern: {pattern}',
                    'url': 'client-side',
                    'category': 'Cross-Site Scripting',
                    'owasp': 'A03:2021 - Injection',
                    'cwe': ['CWE-79'],
                    'recommendation': 'Avoid string concatenation in DOM manipulation. Use safe methods like textContent, createElement, or proper sanitization.'
                })
        
        return findings
    
    def check_secret_input_header_reflection(self, url: str) -> List[Dict[str, Any]]:
        """Check for secret input header reflection vulnerabilities."""
        findings = []
        
        try:
            # Test with secret-like headers
            test_headers = {
                'X-Secret-Key': 'test_secret_value_12345',
                'X-Auth-Token': 'test_auth_token_67890',
                'X-API-Key': 'test_api_key_abcde'
            }
            
            for header_name, header_value in test_headers.items():
                try:
                    response = self.session.get(url, headers=test_headers, timeout=10)
                    
                    # Check if the secret value is reflected in the response
                    if header_value in response.text:
                        findings.append({
                            'type': 'Secret Input Header Reflection',
                            'severity': 'Medium',
                            'description': f'Secret input reflected in response for header: {header_name}',
                            'evidence': f'Header: {header_name} reflected in response',
                            'url': url,
                            'category': 'Information Disclosure',
                            'owasp': 'A05:2021 - Security Misconfiguration',
                            'cwe': ['CWE-200'],
                            'recommendation': 'Ensure that secret input headers are not reflected in responses. Sanitize all user input before including in output.'
                        })
                        
                except Exception:
                    continue
        
        except Exception:
            pass
        
        return findings


def parse_qs(query_string):
    """Parse query string into dictionary (simplified implementation)."""
    params = {}
    if not query_string:
        return params
    
    pairs = query_string.split('&')
    for pair in pairs:
        if '=' in pair:
            key, value = pair.split('=', 1)
            key = key.strip()
            value = value.strip()
            
            if key in params:
                params[key].append(value)
            else:
                params[key] = [value]
    
    return params
