#!/usr/bin/env python3
"""
Advanced Platform Detection Utility

Enhanced platform detection with multiple analysis methods
extracted from consolidated scanner files.

Author: Bachelor Thesis Project - Low-Code Platforms Security Analysis
"""

import re
import requests
from typing import Dict, Any, List, Optional, Tuple
from urllib.parse import urlparse
from bs4 import BeautifulSoup


class AdvancedPlatformDetector:
    """
    Advanced platform detection with multiple analysis methods.
    """
    
    def __init__(self, session: requests.Session):
        self.session = session
        self.timeout_seconds = getattr(session, "default_timeout", 10) or 10
        
        # Platform signatures
        self.platform_signatures = {
            'bubble.io': {
                'headers': ['x-bubble-'],
                'content_patterns': [
                    r'bubble\.io',
                    r'_bubble_page_',
                    r'bubble\.io\/*',
                    r'__BUBBLE',
                    r'workflow.*api',
                    r'plugin.*bubble'
                ],
                'script_patterns': [
                    r'bubble\.io.*\.js',
                    r'_bubble_.*\.js',
                    r'plugin.*bubble.*\.js'
                ],
                'meta_patterns': [
                    r'generator.*bubble',
                    r'bubble.*plugin'
                ]
            },
            'outsystems': {
                'headers': ['x-outsystems-'],
                'content_patterns': [
                    r'outsystems\.com',
                    r'OutSystemsUI',
                    r'OutSystemsNow',
                    r'RichWidgets',
                    r'Screen\.aspx',
                    r'wicket.*outsystems'
                ],
                'script_patterns': [
                    r'outsystems.*\.js',
                    r'RichWidgets.*\.js',
                    r'Screen\.aspx.*\.js'
                ],
                'meta_patterns': [
                    r'generator.*outsystems',
                    r'outsystems.*framework'
                ]
            },
            'airtable.com': {
                'headers': ['x-airtable-'],
                'content_patterns': [
                    r'airtable\.com',
                    r'airtable\.com/v0/',
                    r'app[a-zA-Z0-9]{15}',
                    r'airtable.*api',
                    r'base.*airtable'
                ],
                'script_patterns': [
                    r'airtable.*\.js',
                    r'api\.airtable\.com.*\.js'
                ],
                'meta_patterns': [
                    r'generator.*airtable',
                    r'airtable.*embed'
                ]
            },
            'shopify': {
                'headers': ['x-shopid', 'x-shopify', 'x-shopify-stage'],
                'content_patterns': [
                    r'myshopify\.com',
                    r'cdn\.shopify\.com',
                    r'shopifyassets',
                    r'shopifycloud',
                    r'shopify\-checkout',
                    r'ShopifyAnalytics'
                ],
                'script_patterns': [
                    r'cdn\.shopify\.com/.*\.js',
                    r'shopifyassets\.com/.*\.js'
                ],
                'meta_patterns': [
                    r'shopify-checkout-api-token',
                    r'generator.*shopify'
                ]
            },
            'webflow': {
                'headers': ['x-webflow-id'],
                'content_patterns': [
                    r'data-wf-site',
                    r'data-wf-page',
                    r'uploads-ssl\.webflow\.com'
                ],
                'script_patterns': [
                    r'webflow\.js',
                    r'webflow.*\.js'
                ],
                'meta_patterns': [
                    r'generator.*webflow'
                ]
            },
            'wix': {
                'headers': ['x-wix-'],
                'content_patterns': [
                    r'wixstatic\.com',
                    r'parastorage\.com',
                    r'wixBiSession',
                    r'wixRenderer',
                    r'wixData'
                ],
                'script_patterns': [
                    r'wixstatic\.com/.*\.js',
                    r'parastorage\.com/.*\.js'
                ],
                'meta_patterns': [
                    r'generator.*wix'
                ]
            },
            'mendix': {
                'headers': ['x-mendix'],
                'content_patterns': [
                    r'/mxclientsystem/',
                    r'mendix',
                    r'mxui',
                    r'window\.mx'
                ],
                'script_patterns': [
                    r'mxclientsystem/.*\.js',
                    r'mxui/.*\.js'
                ],
                'meta_patterns': [
                    r'generator.*mendix'
                ]
            },
            'mern': {
                'headers': ['x-powered-by: express'],
                'content_patterns': [
                    r'react.*\.js',
                    r'node_modules',
                    r'mongodb',
                    r'express',
                    r'create-react-app'
                ],
                'script_patterns': [
                    r'react.*\.js',
                    r'react-dom.*\.js',
                    r'bundle\.js.*react'
                ],
                'meta_patterns': [
                    r'generator.*react',
                    r'react.*app'
                ]
            }
        }

        self.platform_aliases = {
            "bubble.io": "bubble",
            "airtable.com": "airtable",
            "myshopify.com": "shopify",
            "webflow.io": "webflow",
            "wix.com": "wix",
            "mendixcloud.com": "mendix",
            "outsystems.dev": "outsystems",
        }

        self.strong_signals = {
            "bubble.io": {
                "headers": ["x-bubble-"],
                "content": [r'_bubble_page_', r'__BUBBLE'],
                "scripts": [r'_bubble_.*\.js'],
                "meta": [r'generator.*bubble'],
            },
            "outsystems": {
                "headers": ["x-outsystems-"],
                "content": [r'outsystemsui', r'outsystemsnow', r'richwidgets'],
                "scripts": [r'outsystems.*\.js', r'richwidgets.*\.js'],
                "meta": [r'generator.*outsystems'],
            },
            "airtable.com": {
                "headers": ["x-airtable-"],
                "content": [r'airtable\.com/v0/', r'app[a-zA-Z0-9]{15}'],
                "scripts": [r'api\.airtable\.com'],
                "meta": [r'airtable.*embed'],
            },
            "shopify": {
                "headers": ["x-shopify", "x-shopid"],
                "content": [r'myshopify\.com', r'shopify-checkout-api-token'],
                "scripts": [r'cdn\.shopify\.com/.*\.js'],
                "meta": [r'generator.*shopify'],
            },
            "webflow": {
                "headers": ["x-webflow-id"],
                "content": [r'data-wf-site', r'data-wf-page'],
                "scripts": [r'webflow\.js'],
                "meta": [r'generator.*webflow'],
            },
            "wix": {
                "headers": ["x-wix-"],
                "content": [r'wixbisession', r'wixrenderer'],
                "scripts": [r'wixstatic\.com/.*\.js', r'parastorage\.com/.*\.js'],
                "meta": [r'generator.*wix'],
            },
            "mendix": {
                "headers": ["x-mendix"],
                "content": [r'/mxclientsystem/', r'window\.mx'],
                "scripts": [r'mxclientsystem/.*\.js', r'mxui/.*\.js'],
                "meta": [r'generator.*mendix'],
            },
            "mern": {
                "headers": ["x-powered-by: express"],
                "content": [r'create-react-app'],
                "scripts": [r'react-dom.*\.js'],
                "meta": [r'generator.*react'],
            },
        }
    
    def detect_platform_advanced(self, url: str, platform_hint: Optional[str] = None) -> Dict[str, Any]:
        """
        Advanced platform detection with multiple analysis methods.
        
        Args:
            url: Target URL to analyze
            platform_hint: Optional platform hint
            
        Returns:
            Dictionary with detection results
        """
        detection_result = {
            'url': url,
            'detected_platforms': [],
            'confidence_scores': {},
            'evidence': {},
            'method': 'advanced',
            'platform_hint': platform_hint
        }

        # Infer hint from domain if not provided
        if platform_hint is None:
            inferred_hint = self._infer_platform_from_domain(url)
            if inferred_hint:
                detection_result['platform_hint'] = inferred_hint
                platform_hint = inferred_hint
        
        try:
            # Fetch the page
            response = self.session.get(url, timeout=self.timeout_seconds)
            if response.status_code >= 400:
                raise ValueError(f"HTTP {response.status_code} for {url}")
            content_type = response.headers.get("Content-Type", "").lower()
            is_html = (
                not content_type
                or "text/html" in content_type
                or "application/xhtml+xml" in content_type
            )
            soup = BeautifulSoup(response.text if is_html else "", 'html.parser')
            
            # Method 1: Header-based detection
            header_results = self._detect_by_headers(response)
            
            # Method 2: Content-based detection  
            content_results = self._detect_by_content(soup) if is_html else {}
            
            # Method 3: Script-based detection
            script_results = self._detect_by_scripts(soup) if is_html else {}
            
            # Method 4: Meta tag detection
            meta_results = self._detect_by_meta(soup) if is_html else {}
            
            # Combine results
            all_results = {}
            validation = {}
            for platform in self.platform_signatures.keys():
                score = 0
                evidence = []
                evidence_types = set()
                
                # Combine scores from all methods
                if platform in header_results:
                    score += header_results[platform]['score']
                    evidence.extend(header_results[platform]['evidence'])
                    evidence_types.add("headers")
                
                if platform in content_results:
                    score += content_results[platform]['score']
                    evidence.extend(content_results[platform]['evidence'])
                    evidence_types.add("content")
                
                if platform in script_results:
                    score += script_results[platform]['score']
                    evidence.extend(script_results[platform]['evidence'])
                    evidence_types.add("scripts")
                
                if platform in meta_results:
                    score += meta_results[platform]['score']
                    evidence.extend(meta_results[platform]['evidence'])
                    evidence_types.add("meta")

                strong_signal = self._has_strong_signal(platform, response, soup)
                if strong_signal:
                    score += 20

                hint_match = bool(
                    platform_hint and platform.lower() == platform_hint.lower()
                )
                if hint_match:
                    score += 15
                    evidence_types.add("domain_hint")

                # Validation gating to reduce false positives
                if not strong_signal and not hint_match and len(evidence_types) < 2:
                    continue
                if platform == "mern" and not strong_signal:
                    continue
                
                if score > 0:
                    all_results[platform] = {
                        'score': score,
                        'evidence': evidence,
                        'confidence': self._calculate_confidence(score),
                        'evidence_types': sorted(evidence_types),
                        'strong_signal': strong_signal,
                    }
                    validation[platform] = {
                        "evidence_types": sorted(evidence_types),
                        "strong_signal": strong_signal,
                    }
            
            # Sort by score
            sorted_platforms = sorted(all_results.items(), key=lambda x: x[1]['score'], reverse=True)
            
            detection_result['detected_platforms'] = [platform for platform, _ in sorted_platforms]
            detection_result['confidence_scores'] = {platform: data['confidence'] for platform, data in sorted_platforms}
            detection_result['evidence'] = {platform: data['evidence'] for platform, data in sorted_platforms}
            detection_result['validation'] = validation
            
            # Apply platform hint if provided (final confidence bump)
            if platform_hint and platform_hint.lower() in [p.lower() for p in detection_result['detected_platforms']]:
                for platform in detection_result['detected_platforms']:
                    if platform.lower() == platform_hint.lower():
                        detection_result['confidence_scores'][platform] = min(
                            100, detection_result['confidence_scores'][platform] + 10
                        )
                        break
            
        except Exception as e:
            detection_result['error'] = str(e)
            detection_result['detected_platforms'] = ['unknown']
            detection_result['confidence_scores'] = {'unknown': 0}
        
        return detection_result

    def _infer_platform_from_domain(self, url: str) -> Optional[str]:
        try:
            parsed = urlparse(url)
            hostname = (parsed.hostname or '').lower()
            if hostname.endswith("bubbleapps.io") or "bubble.io" in hostname:
                return "bubble.io"
            if hostname.endswith("myshopify.com"):
                return "shopify"
            if "webflow" in hostname:
                return "webflow"
            if "wix" in hostname:
                return "wix"
            if "mendix" in hostname:
                return "mendix"
            if "outsystems" in hostname:
                return "outsystems"
            if "airtable" in hostname:
                return "airtable.com"
        except Exception:
            return None
        return None

    def _header_pattern_matches(self, header_pattern: str, header: str, value: str) -> bool:
        pattern = header_pattern.lower()
        header_lower = header.lower()
        value_lower = str(value).lower()
        if ":" in pattern:
            name_part, value_part = pattern.split(":", 1)
            return name_part.strip() in header_lower and value_part.strip() in value_lower
        return pattern in header_lower or pattern in value_lower

    def _has_strong_signal(
        self, platform: str, response: requests.Response, soup: BeautifulSoup
    ) -> bool:
        rules = self.strong_signals.get(platform, {})
        if not rules:
            return False

        # Header signals
        for pattern in rules.get("headers", []):
            for header, value in response.headers.items():
                if self._header_pattern_matches(pattern, header, value):
                    return True

        html = str(soup)
        # Content signals
        for pattern in rules.get("content", []):
            if re.search(pattern, html, re.IGNORECASE):
                return True

        # Script signals
        for pattern in rules.get("scripts", []):
            if re.search(pattern, html, re.IGNORECASE):
                return True

        # Meta signals
        for pattern in rules.get("meta", []):
            if re.search(pattern, html, re.IGNORECASE):
                return True

        return False
    
    def _detect_by_headers(self, response: requests.Response) -> Dict[str, Dict]:
        """Detect platform by HTTP headers."""
        results = {}
        
        for platform, signatures in self.platform_signatures.items():
            score = 0
            evidence = []
            
            for header_pattern in signatures['headers']:
                for header, value in response.headers.items():
                    if self._header_pattern_matches(header_pattern, header, value):
                        score += 30
                        evidence.append(f"Header: {header}: {value}")
            
            if score > 0:
                results[platform] = {
                    'score': score,
                    'evidence': evidence
                }
        
        return results
    
    def _detect_by_content(self, soup: BeautifulSoup) -> Dict[str, Dict]:
        """Detect platform by page content."""
        results = {}
        page_text = str(soup)
        
        for platform, signatures in self.platform_signatures.items():
            score = 0
            evidence = []
            
            for pattern in signatures['content_patterns']:
                matches = re.findall(pattern, page_text, re.IGNORECASE)
                if matches:
                    score += len(matches) * 10
                    evidence.append(f"Content pattern: {pattern} ({len(matches)} matches)")
            
            if score > 0:
                results[platform] = {
                    'score': score,
                    'evidence': evidence
                }
        
        return results
    
    def _detect_by_scripts(self, soup: BeautifulSoup) -> Dict[str, Dict]:
        """Detect platform by script sources."""
        results = {}
        
        scripts = soup.find_all('script')
        script_content = ' '.join([str(script) for script in scripts])
        
        for platform, signatures in self.platform_signatures.items():
            score = 0
            evidence = []
            
            for pattern in signatures['script_patterns']:
                matches = re.findall(pattern, script_content, re.IGNORECASE)
                if matches:
                    score += len(matches) * 15
                    evidence.append(f"Script pattern: {pattern} ({len(matches)} matches)")
            
            if score > 0:
                results[platform] = {
                    'score': score,
                    'evidence': evidence
                }
        
        return results
    
    def _detect_by_meta(self, soup: BeautifulSoup) -> Dict[str, Dict]:
        """Detect platform by meta tags."""
        results = {}
        
        meta_tags = soup.find_all('meta')
        meta_content = ' '.join([str(meta) for meta in meta_tags])
        
        for platform, signatures in self.platform_signatures.items():
            score = 0
            evidence = []
            
            for pattern in signatures['meta_patterns']:
                matches = re.findall(pattern, meta_content, re.IGNORECASE)
                if matches:
                    score += len(matches) * 20
                    evidence.append(f"Meta pattern: {pattern} ({len(matches)} matches)")
            
            if score > 0:
                results[platform] = {
                    'score': score,
                    'evidence': evidence
                }
        
        return results
    
    # Minimum confidence threshold for platform detection (percentage)
    MIN_CONFIDENCE_THRESHOLD = 40
    
    # High confidence threshold for automatic selection
    HIGH_CONFIDENCE_THRESHOLD = 70

    def _calculate_confidence(self, score: int) -> int:
        """Calculate confidence percentage from score."""
        # Normalize score to 0-100 range with diminishing returns for very high scores
        # Use a more conservative formula to avoid over-confidence
        if score <= 0:
            return 0
        elif score <= 50:
            # Linear scaling for lower scores
            confidence = score * 1.2
        else:
            # Diminishing returns for higher scores
            confidence = 60 + (score - 50) * 0.8
        
        return min(100, max(0, int(confidence)))
    
    def get_primary_platform(self, detection_result: Dict[str, Any]) -> Tuple[Optional[str], int]:
        """
        Get the primary detected platform with confidence gating.
        
        Args:
            detection_result: Detection result dictionary
            
        Returns:
            Tuple of (platform_name, confidence) or (None, 0) if no confident detection
        """
        platforms = detection_result.get('detected_platforms', [])
        confidence_scores = detection_result.get('confidence_scores', {})
        
        if not platforms or platforms == ['unknown']:
            return None, 0
        
        primary_platform = platforms[0]
        confidence = confidence_scores.get(primary_platform, 0)
        
        # Apply confidence gating
        if confidence < self.MIN_CONFIDENCE_THRESHOLD:
            return None, confidence
        
        return primary_platform, confidence
    
    def should_use_generic_scanner(self, detection_result: Dict[str, Any]) -> bool:
        """
        Determine if generic scanner should be used due to low confidence.
        
        Args:
            detection_result: Detection result dictionary
            
        Returns:
            True if generic scanner should be used
        """
        platform, confidence = self.get_primary_platform(detection_result)
        
        # Use generic if no platform detected or confidence too low
        if platform is None:
            return True
        
        # Use generic if confidence is below threshold
        if confidence < self.MIN_CONFIDENCE_THRESHOLD:
            return True
        
        # Check for ambiguous results (multiple platforms with similar confidence)
        confidence_scores = detection_result.get('confidence_scores', {})
        if len(confidence_scores) > 1:
            sorted_confidences = sorted(confidence_scores.values(), reverse=True)
            if len(sorted_confidences) >= 2:
                # If top two platforms have similar confidence (within 15 points)
                if sorted_confidences[0] - sorted_confidences[1] < 15:
                    return True
        
        return False
    
    def get_platform_summary(self, detection_result: Dict[str, Any]) -> str:
        """Get a human-readable platform summary."""
        if 'error' in detection_result:
            return f"Detection failed: {detection_result['error']}"
        
        platforms = detection_result['detected_platforms']
        if not platforms or platforms == ['unknown']:
            return "Unknown platform"
        
        if len(platforms) == 1:
            platform = platforms[0]
            confidence = detection_result['confidence_scores'].get(platform, 0)
            return f"{platform} ({confidence}% confidence)"
        
        # Multiple platforms detected
        primary = platforms[0]
        primary_confidence = detection_result['confidence_scores'].get(primary, 0)
        others = ', '.join(platforms[1:3])  # Show top 3
        
        return f"{primary} ({primary_confidence}% confidence) - also detected: {others}"


def detect_platform_advanced(url: str, session: requests.Session, platform_hint: Optional[str] = None) -> Dict[str, Any]:
    """
    Convenience function for advanced platform detection.
    
    Args:
        url: Target URL
        session: Requests session
        platform_hint: Optional platform hint
        
    Returns:
        Platform detection results
    """
    detector = AdvancedPlatformDetector(session)
    return detector.detect_platform_advanced(url, platform_hint)
