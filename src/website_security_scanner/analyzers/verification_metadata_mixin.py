#!/usr/bin/env python3
"""
Verification Metadata Mixin

Provides standardized metadata passing for vulnerability verification
across all platform analyzers.

Author: Bachelor Thesis Project - Low-Code Platforms Security Analysis
"""

from typing import Dict, Any, Optional
from urllib.parse import urlparse, urlunparse


class VerificationMetadataMixin:
    """
    Mixin class to standardize verification metadata passing.
    
    Ensures all analyzers provide consistent metadata for the
    vulnerability verification system.
    """
    
    def _add_verification_metadata(self, vulnerability: Dict[str, Any], 
                                 url: str, parameter: Optional[str] = None,
                                 **kwargs) -> Dict[str, Any]:
        """
        Add standardized verification metadata to vulnerability.
        
        Args:
            vulnerability: Vulnerability dictionary to enhance
            url: Target URL where vulnerability was found
            parameter: Parameter name (if applicable)
            **kwargs: Additional metadata fields
            
        Returns:
            Enhanced vulnerability dictionary
        """
        # Base metadata
        metadata = {
            'url': self._sanitize_url(url),
            'parameter': parameter or '',
        }
        
        # Add optional metadata
        optional_fields = [
            'method', 'evidence_type', 'context', 'payload',
            'response_code', 'headers', 'body_snippet'
        ]
        
        for field in optional_fields:
            if field in kwargs:
                metadata[field] = kwargs[field]
        
        # Add to vulnerability
        vulnerability['verification_metadata'] = metadata
        
        # Also add top-level fields for backward compatibility
        if parameter:
            vulnerability['parameter'] = parameter
        vulnerability['url'] = metadata['url']
        
        return vulnerability
    
    def _sanitize_url(self, url: str) -> str:
        """
        Sanitize URL for safe logging and verification.
        
        Args:
            url: URL to sanitize
            
        Returns:
            Sanitized URL
        """
        try:
            parsed = urlparse(url)
            
            # Remove sensitive query parameters
            if parsed.query:
                # Keep parameter names but remove values for sensitive params
                sensitive_params = [
                    'token', 'key', 'password', 'secret', 'auth',
                    'session', 'sid', 'api_key', 'access_token'
                ]
                
                from urllib.parse import parse_qs, urlencode
                query_params = parse_qs(parsed.query)
                
                sanitized_params = {}
                for param, values in query_params.items():
                    if any(sensitive in param.lower() for sensitive in sensitive_params):
                        sanitized_params[param] = ['[REDACTED]']
                    else:
                        sanitized_params[param] = values
                
                sanitized_query = urlencode(sanitized_params, doseq=True)
                return urlunparse((
                    parsed.scheme, parsed.netloc, parsed.path,
                    parsed.params, sanitized_query, parsed.fragment
                ))
            
            return url
            
        except Exception:
            # If sanitization fails, return a safe version
            parsed = urlparse(url)
            return f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    
    def _create_standard_vulnerability(self, vuln_type: str, severity: str,
                                     title: str, description: str,
                                     url: str, parameter: Optional[str] = None,
                                     **kwargs) -> Dict[str, Any]:
        """
        Create a standardized vulnerability dictionary with verification metadata.
        
        Args:
            vuln_type: Type of vulnerability
            severity: Severity level
            title: Vulnerability title
            description: Vulnerability description
            url: Target URL
            parameter: Parameter name (if applicable)
            **kwargs: Additional vulnerability fields
            
        Returns:
            Standardized vulnerability dictionary
        """
        vulnerability = {
            'type': vuln_type,
            'severity': severity,
            'title': title,
            'description': description,
            'confidence': 'tentative',
        }
        
        # Add standard fields
        standard_fields = [
            'category', 'owasp', 'cwe', 'background', 'impact',
            'references', 'recommendation', 'evidence'
        ]
        
        for field in standard_fields:
            if field in kwargs:
                vulnerability[field] = kwargs[field]
        
        # Add verification metadata
        self._add_verification_metadata(
            vulnerability, url, parameter, **kwargs
        )
        
        return vulnerability
    
    def _extract_parameter_from_context(self, context: str, url: str) -> Optional[str]:
        """
        Extract parameter name from context or URL.
        
        Args:
            context: Context string containing parameter information
            url: URL where vulnerability was found
            
        Returns:
            Parameter name if found, None otherwise
        """
        # Try to extract from context first
        if context:
            import re
            # Look for "Parameter: X" patterns
            param_match = re.search(r'parameter[:\s]+([^\s,]+)', context, re.IGNORECASE)
            if param_match:
                return param_match.group(1)
        
        # Try to extract from URL query parameters
        try:
            from urllib.parse import parse_qs
            parsed = urlparse(url)
            if parsed.query:
                params = parse_qs(parsed.query)
                if params:
                    # Return the first parameter name
                    return list(params.keys())[0]
        except Exception:
            pass
        
        return None
