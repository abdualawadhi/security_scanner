#!/usr/bin/env python3
"""
Advanced Secret Detection Utility

Provides sophisticated secret detection with entropy analysis,
pattern matching, and false positive reduction.

Author: Bachelor Thesis Project - Low-Code Platforms Security Analysis
"""

import re
import math
import string
from typing import Dict, List, Tuple, Optional, Any


class SecretDetector:
    """
    Advanced secret detection with multiple analysis techniques.
    """
    
    def __init__(self):
        # Known false positive patterns
        self.false_positive_patterns = [
            r'^[a-f0-9]{32}$',  # MD5 hashes (often used for non-secret purposes)
            r'^test_.*$',       # Test values
            r'^example_.*$',    # Example values
            r'^demo_.*$',       # Demo values
            r'^sample_.*$',     # Sample values
            r'^xxx.*$',         # Placeholder values
            r'^yyy.*$',         # Placeholder values
            r'^\d{4}-\d{4}-\d{4}-\d{4}$',  # Credit card test numbers
            r'^\*+$',           # Masked values
            r'^\d{10,}x\d{4,}$', # Bubble session-style IDs (e.g., 1769871767269x623725)
        ]
        
        # High-confidence secret patterns
        self.secret_patterns = {
            'api_key': [
                r'(?i)api[_-]?key["\']?\s*[:=]\s*["\']([a-zA-Z0-9_-]{20,})["\']',
                r'(?i)apikey["\']?\s*[:=]\s*["\']([a-zA-Z0-9_-]{20,})["\']',
                r'(?i)key["\']?\s*[:=]\s*["\']([a-zA-Z0-9_-]{20,})["\']',
            ],
            'jwt_token': [
                r'["\']([a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)["\']',
            ],
            'bearer_token': [
                r'(?i)bearer\s+([a-zA-Z0-9_-]{20,})',
                r'(?i)authorization["\']?\s*[:=]\s*["\']bearer\s+([a-zA-Z0-9_-]{20,})["\']',
            ],
            'database_url': [
                r'(?i)database[_-]?url["\']?\s*[:=]\s*["\']([^"\']{20,})["\']',
                r'(?i)connection[_-]?string["\']?\s*[:=]\s*["\']([^"\']{20,})["\']',
            ],
            'private_key': [
                r'-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----',
                r'-----BEGIN\s+EC\s+PRIVATE\s+KEY-----',
                r'-----BEGIN\s+OPENSSH\s+PRIVATE\s+KEY-----',
            ],
            'aws_secret': [
                r'(?i)aws[_-]?secret[_-]?access[_-]?key["\']?\s*[:=]\s*["\']([a-zA-Z0-9/+=]{40})["\']',
                r'(?i)aws[_-]?access[_-]?key[_-]?id["\']?\s*[:=]\s*["\']([A-Z0-9]{20})["\']',
            ],
            'github_token': [
                r'(?i)github[_-]?token["\']?\s*[:=]\s*["\']([a-zA-Z0-9_]{40})["\']',
                r'ghp_[a-zA-Z0-9]{36}',
            ],
            'airtable_key': [
                r'(?i)airtable[_-]?api[_-]?key["\']?\s*[:=]\s*["\'](key[a-zA-Z0-9]{14,})["\']',
                r'key[a-zA-Z0-9]{14,}',
            ],
        }
        
        # Context indicators that suggest a real secret
        self.secret_context_indicators = [
            'password', 'secret', 'token', 'key', 'auth', 'credential',
            'private', 'confidential', 'sensitive', 'secure'
        ]
        
        # Context indicators that suggest a false positive
        self.false_positive_context_indicators = [
            'example', 'test', 'demo', 'sample', 'placeholder', 'mock',
            'fake', 'dummy', 'template', 'documentation', 'tutorial'
        ]

        # Platform-specific allow/deny lists (regex patterns)
        self.platform_denylist_patterns = {
            'webflow': [
                r'data-wf-(site|page)',
                r'webflow\.js',
            ],
            'shopify': [
                r'gid://shopify/',
                r'"id"\s*:\s*\d{6,}',
            ],
            'wix': [
                r'wixBiSession',
                r'wixRenderer',
            ],
            'mendix': [
                r'mxclientsystem',
                r'mxui',
            ],
            'bubble': [
                r'\d{10,}x\d{4,}',
                r'bubbleapps\.io',
                r'workflow_session',
            ],
        }
        self.platform_allowlist_types = {'private_key', 'aws_secret', 'github_token'}
    
    def detect_secrets(self, content: str, url: str = '') -> List[Dict[str, Any]]:
        """
        Detect secrets in content using multiple analysis techniques.
        
        Args:
            content: Content to analyze
            url: URL where content was found (for context)
            
        Returns:
            List of detected secrets with metadata
        """
        secrets = []
        
        # Pattern-based detection
        pattern_secrets = self._detect_by_patterns(content)
        secrets.extend(pattern_secrets)
        
        # High-entropy string detection
        entropy_secrets = self._detect_by_entropy(content)
        secrets.extend(entropy_secrets)
        
        # Filter and rank secrets
        filtered_secrets = self._filter_and_rank_secrets(secrets, url)
        
        return filtered_secrets
    
    def _detect_by_patterns(self, content: str) -> List[Dict[str, Any]]:
        """Detect secrets using known patterns."""
        secrets = []
        
        for secret_type, patterns in self.secret_patterns.items():
            for pattern in patterns:
                matches = re.finditer(pattern, content, re.IGNORECASE)
                for match in matches:
                    # Extract the secret value (handle different group structures)
                    if match.groups():
                        secret_value = match.group(1) if match.group(1) else match.group(0)
                    else:
                        secret_value = match.group(0)
                    
                    # Get context around the match
                    start = max(0, match.start() - 50)
                    end = min(len(content), match.end() + 50)
                    context = content[start:end].strip()
                    
                    secret_info = {
                        'type': secret_type,
                        'value': secret_value,
                        'pattern': pattern,
                        'context': context,
                        'start_pos': match.start(),
                        'end_pos': match.end(),
                        'confidence': self._calculate_pattern_confidence(secret_type, secret_value, context),
                        'detection_method': 'pattern'
                    }
                    
                    secrets.append(secret_info)
        
        return secrets
    
    def _detect_by_entropy(self, content: str) -> List[Dict[str, Any]]:
        """Detect high-entropy strings that might be secrets."""
        secrets = []
        
        # Find strings that look like they might be secrets
        # Look for quoted strings, base64-like strings, etc.
        string_patterns = [
            r'["\']([a-zA-Z0-9+/=_-]{20,})["\']',  # Quoted strings
            r'([a-zA-Z0-9]{32,})',  # Long alphanumeric strings
        ]
        
        for pattern in string_patterns:
            matches = re.finditer(pattern, content)
            for match in matches:
                secret_value = match.group(1)
                
                # Skip if it's clearly not a secret
                if self._is_likely_false_positive_string(secret_value):
                    continue
                
                # Calculate entropy
                entropy = self._calculate_entropy(secret_value)
                
                # Only consider high-entropy strings
                if entropy < 4.5:  # Threshold for high entropy
                    continue
                
                # Get context
                start = max(0, match.start() - 50)
                end = min(len(content), match.end() + 50)
                context = content[start:end].strip()
                
                secret_info = {
                    'type': 'high_entropy_string',
                    'value': secret_value,
                    'pattern': pattern,
                    'context': context,
                    'start_pos': match.start(),
                    'end_pos': match.end(),
                    'entropy': entropy,
                    'confidence': self._calculate_entropy_confidence(secret_value, context, entropy),
                    'detection_method': 'entropy'
                }
                
                secrets.append(secret_info)
        
        return secrets
    
    def _calculate_entropy(self, string: str) -> float:
        """Calculate Shannon entropy of a string."""
        if not string:
            return 0
        
        # Count character frequencies
        char_counts = {}
        for char in string:
            char_counts[char] = char_counts.get(char, 0) + 1
        
        # Calculate entropy
        entropy = 0
        string_len = len(string)
        
        for count in char_counts.values():
            probability = count / string_len
            entropy -= probability * math.log2(probability)
        
        return entropy
    
    def _calculate_pattern_confidence(self, secret_type: str, secret_value: str, context: str) -> str:
        """Calculate confidence level for pattern-based detection."""
        confidence_score = 0.5  # Base confidence
        
        # High-confidence types
        if secret_type in ['private_key', 'aws_secret', 'github_token']:
            confidence_score += 0.3
        
        # Check context indicators
        context_lower = context.lower()
        
        # Positive indicators
        for indicator in self.secret_context_indicators:
            if indicator in context_lower:
                confidence_score += 0.1
        
        # Negative indicators
        for indicator in self.false_positive_context_indicators:
            if indicator in context_lower:
                confidence_score -= 0.2
        
        # Length and complexity
        if len(secret_value) >= 30:
            confidence_score += 0.1
        
        if self._has_good_char_distribution(secret_value):
            confidence_score += 0.1
        
        # Convert to confidence level
        if confidence_score >= 0.8:
            return 'certain'
        elif confidence_score >= 0.6:
            return 'firm'
        elif confidence_score >= 0.4:
            return 'tentative'
        else:
            return 'unlikely'
    
    def _calculate_entropy_confidence(self, secret_value: str, context: str, entropy: float) -> str:
        """Calculate confidence level for entropy-based detection."""
        confidence_score = 0.3  # Base confidence for entropy detection
        
        # Entropy contribution
        if entropy >= 6.0:
            confidence_score += 0.3
        elif entropy >= 5.0:
            confidence_score += 0.2
        elif entropy >= 4.5:
            confidence_score += 0.1
        
        # Context analysis
        context_lower = context.lower()
        
        # Positive indicators
        for indicator in self.secret_context_indicators:
            if indicator in context_lower:
                confidence_score += 0.2
        
        # Negative indicators
        for indicator in self.false_positive_context_indicators:
            if indicator in context_lower:
                confidence_score -= 0.3
        
        # Convert to confidence level
        if confidence_score >= 0.8:
            return 'certain'
        elif confidence_score >= 0.6:
            return 'firm'
        elif confidence_score >= 0.4:
            return 'tentative'
        else:
            return 'unlikely'
    
    def _is_likely_false_positive_string(self, string: str) -> bool:
        """Check if a string is likely a false positive."""
        string_lower = string.lower()
        
        # Check against false positive patterns
        for pattern in self.false_positive_patterns:
            if re.match(pattern, string):
                return True
        
        # Check for obvious non-secret patterns
        if string_lower in ['true', 'false', 'null', 'undefined', 'none']:
            return True
        
        # Check for repeated characters
        if len(set(string)) < 3:
            return True
        
        # Check for common placeholder patterns
        if any(placeholder in string_lower for placeholder in ['xxx', 'yyy', 'zzz', 'test', 'demo']):
            return True
        
        return False
    
    def _has_good_char_distribution(self, string: str) -> bool:
        """Check if string has good character distribution (indicative of real secret)."""
        if len(string) < 10:
            return False
        
        unique_chars = set(string)
        char_ratio = len(unique_chars) / len(string)
        
        # Good distribution if at least 40% unique characters
        return char_ratio >= 0.4
    
    def _filter_and_rank_secrets(self, secrets: List[Dict[str, Any]], url: str) -> List[Dict[str, Any]]:
        """Filter out false positives and rank remaining secrets."""
        filtered_secrets = []
        platform = self._detect_platform_from_url(url)
        
        for secret in secrets:
            # Skip unlikely secrets
            if secret.get('confidence') == 'unlikely':
                continue
            
            # Skip if value is too short
            if len(secret['value']) < 10:
                continue
            
            # Additional filtering based on URL context
            if self._is_false_positive_by_url(secret, url):
                continue

            # Platform-specific denylist
            if self._is_platform_denylisted(secret, platform):
                continue

            # Require regex + entropy + context unless allowlisted
            if secret.get('type') not in self.platform_allowlist_types:
                detection_method = secret.get('detection_method', '')
                has_pattern = detection_method == 'pattern'
                entropy = secret.get('entropy')
                if entropy is None:
                    entropy = self._calculate_entropy(secret.get('value', ''))
                    secret['entropy'] = entropy
                has_entropy = entropy >= 4.5
                has_context = self._has_context_signal(secret.get('context', ''))

                if not (has_pattern and has_entropy and has_context):
                    continue
            
            # Add ranking score
            secret['rank_score'] = self._calculate_rank_score(secret)
            
            filtered_secrets.append(secret)
        
        # Sort by rank score (descending)
        filtered_secrets.sort(key=lambda x: x['rank_score'], reverse=True)
        
        return filtered_secrets

    def _detect_platform_from_url(self, url: str) -> str:
        url_lower = (url or '').lower()
        if 'bubbleapps.io' in url_lower or 'bubble.io' in url_lower:
            return 'bubble'
        if 'myshopify.com' in url_lower or 'shopify' in url_lower:
            return 'shopify'
        if 'webflow' in url_lower:
            return 'webflow'
        if 'wix' in url_lower or 'wixstatic' in url_lower or 'parastorage' in url_lower:
            return 'wix'
        if 'mendix' in url_lower or 'mxclientsystem' in url_lower:
            return 'mendix'
        return 'generic'

    def _is_platform_denylisted(self, secret: Dict[str, Any], platform: str) -> bool:
        patterns = self.platform_denylist_patterns.get(platform, [])
        if not patterns:
            return False
        context = secret.get('context', '') or ''
        for pattern in patterns:
            if re.search(pattern, context, re.IGNORECASE):
                return True
        return False

    def _has_context_signal(self, context: str) -> bool:
        context_lower = (context or '').lower()
        for indicator in self.secret_context_indicators:
            if indicator in context_lower:
                return True
        return False
    
    def _is_false_positive_by_url(self, secret: Dict[str, Any], url: str) -> bool:
        """Check if secret is likely false positive based on URL context."""
        url_lower = url.lower()
        
        # Documentation URLs
        if any(doc in url_lower for doc in ['docs.', 'documentation', 'example', 'tutorial']):
            return True
        
        # Test/dev environments
        if any(env in url_lower for env in ['test.', 'dev.', 'staging.', 'localhost']):
            # Be more strict about secrets in test environments
            return secret.get('confidence') in ['tentative']
        
        return False
    
    def _calculate_rank_score(self, secret: Dict[str, Any]) -> float:
        """Calculate ranking score for a secret."""
        score = 0.0
        
        # Confidence level
        confidence = secret.get('confidence', 'tentative')
        if confidence == 'certain':
            score += 3.0
        elif confidence == 'firm':
            score += 2.0
        elif confidence == 'tentative':
            score += 1.0
        
        # Secret type importance
        secret_type = secret.get('type', '')
        if secret_type in ['private_key', 'aws_secret', 'github_token']:
            score += 2.0
        elif secret_type in ['api_key', 'bearer_token', 'database_url']:
            score += 1.5
        elif secret_type == 'high_entropy_string':
            score += 1.0
        
        # Entropy bonus
        entropy = secret.get('entropy', 0)
        if entropy >= 6.0:
            score += 1.0
        elif entropy >= 5.0:
            score += 0.5
        
        # Length bonus
        if len(secret.get('value', '')) >= 40:
            score += 0.5
        
        return score
