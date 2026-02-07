#!/usr/bin/env python3
"""
Common web security checks shared across analyzers.
"""

from __future__ import annotations

import base64
import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qs, urljoin, urlparse

import requests
from bs4 import BeautifulSoup

from ..utils.evidence_builder import EvidenceBuilder
from ..utils.secret_detector import SecretDetector


class CommonWebChecksMixin:
    """Mixin providing shared web security checks with evidence tracking."""

    def _get_timeout_seconds(self, fallback: int = 10) -> int:
        try:
            return int(getattr(self, "timeout_seconds", fallback) or fallback)
        except (TypeError, ValueError):
            return fallback

    def _is_html_response(self, response: requests.Response) -> bool:
        if response is None:
            return False
        if response.status_code >= 400:
            return False
        content_type = response.headers.get("Content-Type", "").lower()
        if not content_type:
            return True
        return "text/html" in content_type or "application/xhtml+xml" in content_type

    def _is_same_origin_url(self, base_url: str, other_url: str) -> bool:
        try:
            base = urlparse(base_url)
            other = urlparse(other_url)
            return base.scheme == other.scheme and base.netloc == other.netloc
        except Exception:
            return False

    def _get_secret_detector(self) -> SecretDetector:
        if not hasattr(self, "_secret_detector"):
            self._secret_detector = SecretDetector()
        return self._secret_detector

    def _fetch_external_javascript(
        self,
        soup: Optional[BeautifulSoup],
        base_url: str,
        limit: int = 10,
    ) -> List[Tuple[str, str, Optional[requests.Response]]]:
        if soup is None:
            return []

        scan_depth = int(getattr(self, "scan_depth", 1) or 1)
        if scan_depth <= 1:
            return []

        allow_third_party = bool(getattr(self, "allow_third_party_js", False))
        fetch_external = bool(getattr(self, "fetch_external_js_assets", True))
        if not fetch_external:
            return []

        script_tags = soup.find_all("script", src=True)
        if not script_tags:
            return []

        entries: List[Tuple[str, str, Optional[requests.Response]]] = []
        seen = set()
        timeout = self._get_timeout_seconds(10)
        max_bytes = int(getattr(self, "max_js_bytes", 512 * 1024))
        for tag in script_tags:
            src = tag.get("src")
            if not src:
                continue
            if tag.get("type") and "javascript" not in tag.get("type", "").lower():
                continue
            script_url = urljoin(base_url, src)
            if not script_url.lower().startswith(("http://", "https://")):
                continue
            if script_url in seen:
                continue
            seen.add(script_url)
            if len(entries) >= limit:
                break
            same_origin = self._is_same_origin_url(base_url, script_url)
            if not same_origin:
                if scan_depth < 3 or not allow_third_party:
                    continue
            try:
                resp = self.session.get(
                    script_url,
                    timeout=timeout,
                    verify=getattr(self, "verify_ssl", True),
                )
            except Exception as exc:
                if hasattr(self, "_record_warning"):
                    self._record_warning(
                        "External JavaScript fetch failed",
                        url=script_url,
                        error=str(exc),
                    )
                continue
            if resp.status_code != 200:
                continue
            content_type = resp.headers.get("Content-Type", "").lower()
            if content_type and "javascript" not in content_type and "ecmascript" not in content_type:
                continue
            if resp.content is not None and len(resp.content) > max_bytes:
                if hasattr(self, "_record_warning"):
                    self._record_warning(
                        "External JavaScript skipped due to size",
                        url=script_url,
                        size_bytes=len(resp.content),
                    )
                continue
            entries.append((script_url, resp.text, resp))
        return entries

    def _get_set_cookie_headers(self, response: requests.Response) -> List[str]:
        """Extract Set-Cookie headers from response."""
        raw_headers = getattr(response.raw, "headers", None) if hasattr(response, 'raw') else None
        if raw_headers is not None and hasattr(raw_headers, "get_all"):
            values = raw_headers.get_all("Set-Cookie")
            return [v for v in values if v]

        value = response.headers.get("Set-Cookie")
        if not value:
            return []

        return [value]

    def _is_bubble_workflow_session(self, url: str, param_name: str, param_value: str) -> bool:
        """
        Check if a URL parameter is a Bubble workflow session (false positive).
        
        Bubble.io uses session-like parameters in workflow URLs that are not
        actual authentication sessions.
        
        Args:
            url: Full URL
            param_name: Name of the parameter
            param_value: Value of the parameter
            
        Returns:
            True if this is a Bubble workflow parameter (false positive)
        """
        # Bubble-specific patterns that indicate workflow parameters
        bubble_indicators = [
            r'bubbleapps\.io',
            r'bubble\.io',
            r'api/1\.1/wf/',
            r'version-\w+/api/',
            r'\.bubble\.'
        ]
        
        is_bubble_url = any(re.search(pattern, url, re.IGNORECASE) for pattern in bubble_indicators)
        
        if not is_bubble_url:
            return False
        
        # Bubble workflow parameters that are NOT authentication sessions
        bubble_workflow_params = [
            'workflow_session',
            'wf_session',
            'bubble_session',
            'instance_session',
            'test_session',
            'preview_session',
        ]
        
        # Check if parameter name matches known Bubble workflow patterns
        param_lower = param_name.lower()
        if any(bp in param_lower for bp in bubble_workflow_params):
            return True
        
        # Check for Bubble-specific value patterns (UUID-like but not real sessions)
        if param_name.lower() in ['session', 'token']:
            # Bubble workflow values are often UUIDs or contain specific patterns
            if re.match(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', param_value, re.I):
                # This is likely a Bubble workflow ID, not a user session
                return True
            # Bubble test/preview sessions often have specific prefixes
            if re.match(r'^(test_|preview_|debug_|wf_)', param_value, re.I):
                return True
        
        return False

    def _check_session_tokens_in_url(self, url: str, is_bubble_context: bool = False):
        """
        Check for session tokens in URL with platform-specific filtering.
        
        Args:
            url: URL to check
            is_bubble_context: Whether this is a Bubble.io application
        """
        session_params = [
            "session",
            "token",
            "sid",
            "sessionid",
            "session_id",
            "session_code",
            "state",
            "nonce",
            "auth_token",
            "code",
            "access_token",
            "id_token",
        ]

        found_params = []
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query)
        
        for param in session_params:
            if re.search(rf"[?&]{param}=", url, re.IGNORECASE):
                # Check for false positives in Bubble contexts
                if is_bubble_context or self._is_bubble_workflow_session(url, param, query_params.get(param, [''])[0] if param in query_params else ''):
                    # Additional validation: check if this is a real authentication token
                    values = query_params.get(param, [])
                    if values:
                        value = values[0]
                        # Skip if this looks like a Bubble workflow parameter
                        if self._is_bubble_workflow_session(url, param, value):
                            continue
                        # Skip short values that might be non-sensitive identifiers
                        if len(value) < 16:
                            continue
                        # Skip obvious placeholder/test values
                        if re.match(r'^(test|example|demo|sample|xxx|yyy|abc123)', value, re.I):
                            continue
                
                found_params.append(param)

        if not found_params:
            return

        session_evidence = EvidenceBuilder.url_parameter(
            "|".join(found_params),
            "Session-related token(s) found in URL parameters",
        )
        self.add_enriched_vulnerability(
            "Session Token in URL",
            "Medium",
            f"Session-related token(s) found in URL: {', '.join(sorted(set(found_params)))}",
            session_evidence,
            "Use secure cookies for session management and avoid passing tokens in URLs.",
            category="Session Management",
            owasp="A07:2021 - Identification and Authentication Failures",
            cwe=["CWE-384", "CWE-598"],
        )

    def _check_secrets_in_javascript(
        self,
        js_content: str,
        url: str,
        soup: Optional[BeautifulSoup] = None,
    ):
        """Check for secrets in JavaScript using the shared SecretDetector."""
        detector = self._get_secret_detector()
        max_assets = getattr(self, "max_external_js_assets", 8)
        fetch_external = getattr(self, "fetch_external_js_assets", True)

        content_sources: List[Tuple[str, str, Optional[requests.Response]]] = [
            ("inline", js_content or "", None)
        ]
        if fetch_external:
            content_sources.extend(self._fetch_external_javascript(soup, url, limit=max_assets))

        reported = set()
        for source, content, response in content_sources:
            if not content:
                continue
            detected = detector.detect_secrets(content, url)
            for secret in detected:
                value = secret.get("value", "")
                if not value:
                    continue
                key = (value, source)
                if key in reported:
                    continue
                reported.add(key)

                confidence = secret.get("confidence", "tentative")
                severity = self._map_secret_severity(secret)

                evidence = EvidenceBuilder.exact_match(
                    value,
                    secret.get("context") or "Secret-like value detected in JavaScript",
                )
                if isinstance(evidence, dict):
                    evidence["source"] = source
                    evidence["secret_type"] = secret.get("type")
                    evidence["detection_method"] = secret.get("detection_method")

                self.add_enriched_vulnerability(
                    "Potential Secret in JavaScript",
                    severity,
                    f"Secret-like value detected in JavaScript ({secret.get('type', 'unknown')}): {value[:10]}...",
                    evidence,
                    "Remove secrets from client-side code and load them from secure server-side configuration.",
                    confidence=self._normalize_confidence(confidence),
                    category="Secret Management",
                    owasp="A02:2021 - Cryptographic Failures",
                    cwe=["CWE-798"],
                    url=url,
                    matched_value=value,
                    http_response=response,
                )

    def _map_secret_severity(self, secret: Dict[str, Any]) -> str:
        secret_type = secret.get("type", "")
        if secret_type in {"private_key", "aws_secret", "github_token"}:
            return "Critical"
        if secret_type in {"api_key", "bearer_token", "database_url"}:
            return "High"
        if secret_type in {"airtable_key", "jwt_token"}:
            return "High"
        return "Medium"

    def _normalize_confidence(self, confidence: str) -> str:
        mapping = {
            "certain": "Certain",
            "firm": "Firm",
            "tentative": "Tentative",
        }
        return mapping.get(confidence.lower(), "Tentative")

    def _check_cookie_security(self, response: requests.Response):
        """Check cookie security headers."""
        cookies = self._get_set_cookie_headers(response)

        for cookie in cookies:
            cookie_name = cookie.split("=", 1)[0] if "=" in cookie else "Unknown"
            cookie_lower = cookie.lower()

            if "secure" not in cookie_lower:
                self.add_enriched_vulnerability(
                    "Insecure Cookie (Missing Secure Flag)",
                    "Low",
                    f"Cookie '{cookie_name}' lacks Secure flag",
                    cookie[:100],
                    "Set the 'Secure' flag for all cookies to ensure they are only transmitted over HTTPS.",
                    confidence="Tentative",
                    category="Session Management",
                    owasp="A05:2021 - Security Misconfiguration",
                    cwe=["CWE-614"],
                )

            if "httponly" not in cookie_lower:
                self.add_enriched_vulnerability(
                    "Cookie without HttpOnly Flag",
                    "Low",
                    f"Cookie '{cookie_name}' lacks HttpOnly flag",
                    cookie[:100],
                    "Set the 'HttpOnly' flag for all cookies to prevent them from being accessed by client-side scripts.",
                    confidence="Tentative",
                    category="Session Management",
                    owasp="A05:2021 - Security Misconfiguration",
                    cwe=["CWE-1004"],
                )

    def _check_csp_policy(self, response: requests.Response):
        """Check Content Security Policy."""
        if not self._is_html_response(response):
            return
        csp = response.headers.get("Content-Security-Policy", "")
        if not csp:
            self.add_enriched_vulnerability(
                "Missing Content Security Policy",
                "Info",
                "No CSP header found",
                EvidenceBuilder.header_evidence("Content-Security-Policy"),
                "Implement Content Security Policy",
                confidence="Tentative",
                category="Security Headers",
                owasp="A05:2021 - Security Misconfiguration",
                cwe=["CWE-693"],
            )
            return

        issues = []
        csp_lower = csp.lower()
        if "unsafe-inline" in csp_lower:
            issues.append("contains unsafe-inline")
        if "unsafe-eval" in csp_lower:
            issues.append("contains unsafe-eval")
        if "form-action" not in csp_lower:
            issues.append("missing form-action")

        if issues:
            self.add_enriched_vulnerability(
                "Weak Content Security Policy",
                "Low",
                "CSP policy contains potentially unsafe directives.",
                EvidenceBuilder.header_evidence("Content-Security-Policy", csp[:200]),
                "Harden CSP by removing unsafe-inline/unsafe-eval and adding form-action restrictions.",
                confidence="Tentative",
                category="Security Headers",
                owasp="A05:2021 - Security Misconfiguration",
                cwe=["CWE-693"],
            )

    def _check_clickjacking(self, response: requests.Response):
        """Check for clickjacking protection."""
        if not self._is_html_response(response):
            return
        xfo = response.headers.get("X-Frame-Options", "")
        csp = response.headers.get("Content-Security-Policy", "")
        if xfo or "frame-ancestors" in csp.lower():
            return

        self.add_enriched_vulnerability(
            "Missing Clickjacking Protection",
            "Low",
            "No X-Frame-Options header or CSP frame-ancestors directive.",
            EvidenceBuilder.header_evidence("X-Frame-Options"),
            "Implement X-Frame-Options or CSP frame-ancestors to prevent clickjacking.",
            confidence="Tentative",
            category="Security Headers",
            owasp="A05:2021 - Security Misconfiguration",
            cwe=["CWE-693"],
        )

    def _check_information_disclosure(
        self,
        js_content: str,
        html_content: str,
        response: requests.Response,
    ):
        """Check for information disclosure."""
        if not self._is_html_response(response):
            return
        error_patterns = [
            r"error[:\s]+[\"']([^\"']+)[\"']",
            r"exception[:\s]+[\"']([^\"']+)[\"']",
            r"stack\s*trace",
            r"debug\s*info",
            r"traceback",
        ]

        content = js_content + html_content
        matches = []
        for pattern in error_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                matches.append(pattern)

        if len(matches) >= 2 or any("stack" in m or "traceback" in m for m in matches):
            self.add_enriched_vulnerability(
                "Information Disclosure",
                "Low",
                "Potential error information exposed",
                EvidenceBuilder.regex_pattern(matches[0], "Error/debug pattern in response content"),
                "Review error handling and information disclosure",
                confidence="Tentative",
                category="Information Disclosure",
                owasp="A09:2021 - Security Logging and Monitoring Failures",
                cwe=["CWE-200"],
            )

    def _check_reflected_input(self, url: str, response: requests.Response, html_content: str):
        """Check for reflected input (potential XSS)."""
        if not self._is_html_response(response):
            return
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        for param, values in params.items():
            for value in values:
                if value and value in html_content:
                    evidence = EvidenceBuilder.exact_match(
                        value,
                        f"Parameter '{param}' reflected in response",
                    )
                    self.add_enriched_vulnerability(
                        "Reflected Input (Potential XSS)",
                        "Medium",
                        f"Input parameter '{param}' is reflected in response",
                        evidence,
                        "Implement output encoding and input validation",
                        confidence="Tentative",
                        category="Cross-Site Scripting",
                        owasp="A03:2021 - Injection",
                        cwe=["CWE-79"],
                        parameter=param,
                        url=url,
                    )

    def _check_cacheable_https(self, response: requests.Response, url: str):
        """Check for cacheable HTTPS responses."""
        if not url.lower().startswith("https://"):
            return

        cache_control = response.headers.get("Cache-Control", "")
        pragma = response.headers.get("Pragma", "")
        cache_control_lower = cache_control.lower()

        if any(directive in cache_control_lower for directive in ["no-store", "no-cache", "private"]):
            return

        if "no-cache" in pragma.lower():
            return

        request_headers = {}
        if getattr(response, "request", None) is not None:
            request_headers = getattr(response.request, "headers", {}) or {}

        sensitive_request = any(
            header in request_headers for header in ["Authorization", "Cookie"]
        )

        sensitive_cookie_names = ["session", "auth", "token", "sid", "jwt", "sso"]
        cookie_header = request_headers.get("Cookie", "")
        if any(name in cookie_header.lower() for name in sensitive_cookie_names):
            sensitive_request = True

        if sensitive_request:
            self.add_enriched_vulnerability(
                "Cacheable HTTPS Response",
                "Low",
                "HTTPS response with sensitive request headers appears cacheable.",
                EvidenceBuilder.header_evidence("Cache-Control", cache_control),
                "Ensure Cache-Control: no-store for authenticated or sensitive responses.",
                category="Caching",
                owasp="A05:2021 - Security Misconfiguration",
                cwe=["CWE-525"],
            )

    def _check_base64_data(self, url: str, html_content: str):
        """Check for Base64 encoded data in URL parameters."""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        for param, values in params.items():
            for value in values:
                if len(value) < 16:
                    continue
                if not re.fullmatch(r"[A-Za-z0-9+/=]+", value):
                    continue
                try:
                    decoded = base64.b64decode(value).decode("utf-8", errors="ignore")
                except Exception:
                    continue
                if decoded and any(token in decoded.lower() for token in ["password", "token", "secret", "key"]):
                    evidence = EvidenceBuilder.exact_match(value, "Base64 data in URL parameter")
                    self.add_enriched_vulnerability(
                        "Base64 Encoded Data in URL",
                        "Info",
                        f"Base64-encoded data detected in parameter '{param}'.",
                        evidence,
                        "Avoid transmitting sensitive data in URLs; use secure request bodies or headers.",
                        category="Information Disclosure",
                        owasp="A02:2021 - Cryptographic Failures",
                        cwe=["CWE-312"],
                        parameter=param,
                        url=url,
                    )
