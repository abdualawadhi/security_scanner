#!/usr/bin/env python3
"""Advanced security checks shared by multiple analyzers."""

from __future__ import annotations

import re
import secrets
from typing import Iterable, List, Optional
from urllib.parse import parse_qs, urljoin, urlparse

import httpx
import requests


class AdvancedChecksMixin:
    """Mixin providing additional Burp-aligned checks.

    Assumes the concrete analyzer provides:
    - self.session: requests.Session
    - self.add_enriched_vulnerability(...)
    """

    def _get_set_cookie_headers(self, response: requests.Response) -> List[str]:
        raw_headers = getattr(response.raw, "headers", None)
        if raw_headers is not None and hasattr(raw_headers, "get_all"):
            values = raw_headers.get_all("Set-Cookie")
            return [v for v in values if v]

        value = response.headers.get("Set-Cookie")
        if not value:
            return []

        return [value]

    def _check_http2_support(self, url: str):
        """
        Detect whether the origin supports HTTP/2 with proper negotiation.
        
        This check uses ALPN (Application-Layer Protocol Negotiation) to properly
        detect HTTP/2 support rather than just checking the response version.
        """
        import ssl
        import socket

        parsed = urlparse(url)
        if parsed.scheme.lower() != "https":
            return

        hostname = parsed.hostname
        if not hostname:
            return

        timeout = 6.0
        if hasattr(self, "_get_timeout_seconds"):
            try:
                timeout = float(self._get_timeout_seconds(6))
            except Exception:
                timeout = 6.0
        verify_ssl = bool(getattr(self, "verify_ssl", True))

        http2_supported = False
        http2_negotiated = False
        http2_advertised = False
        
        try:
            # First check: Test TLS ALPN for h2 support
            context = ssl.create_default_context()
            if not verify_ssl:
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
            context.set_alpn_protocols(['h2', 'http/1.1'])
            
            with socket.create_connection((hostname, 443), timeout=timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    negotiated_protocol = ssock.selected_alpn_protocol()
                    if negotiated_protocol == 'h2':
                        http2_supported = True
        except (ssl.SSLError, socket.error, socket.timeout):
            pass
        
        # Second check: Make an actual HTTP/2 request if ALPN indicates support
        if http2_supported:
            try:
                with httpx.Client(
                    http2=True, 
                    timeout=timeout, 
                    follow_redirects=True,
                    verify=verify_ssl
                ) as client:
                    response = client.get(url)
                    if response.http_version == "HTTP/2":
                        http2_negotiated = True
                        alt_svc = response.headers.get("alt-svc", "")
                        if "h2" in alt_svc:
                            http2_advertised = True
            except (httpx.HTTPError, Exception):
                http2_supported = False
        
        # Only report if HTTP/2 is properly supported AND negotiated
        # Require at least two independent confirmations to reduce false positives
        confirmations = sum([1 for flag in (http2_supported, http2_negotiated, http2_advertised) if flag])
        if confirmations >= 2:
            self.add_enriched_vulnerability(
                "HTTP/2 Protocol Supported",
                "Info",
                "Target supports and successfully negotiates HTTP/2. Review HTTP/2-specific hardening (HPACK/DoS controls, reverse-proxy config).",
                f"HTTP/2 confirmed via ALPN, HTTP/2 request, and/or Alt-Svc advertisement",
                "Review HTTP/2 configuration at the edge (WAF/CDN/proxy), apply rate limits, and keep TLS stack updated.",
                category="Protocol Security",
                owasp="A05:2021 - Security Misconfiguration",
                cwe=["CWE-16"],
                background="HTTP/2 provides performance improvements over HTTP/1.1 but introduces new attack vectors such as HPACK bomb attacks and stream multiplexing abuse.",
                impact="Without proper HTTP/2 hardening, attackers may exploit protocol-specific vulnerabilities to cause denial of service or bypass security controls.",
                references=[
                    "https://www.rfc-editor.org/rfc/rfc7540",
                    "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/17-Testing_for_HTTP2",
                ],
            )

    def _check_request_url_override(self, url: str):
        """Active check for request URL override behavior.

        Tests common override headers (X-Original-URL / X-Rewrite-URL etc.).
        """

        parsed = urlparse(url)
        if not parsed.scheme or not parsed.netloc:
            return

        origin = f"{parsed.scheme}://{parsed.netloc}/"
        test_paths = ["/admin", "/robots.txt", "/.env", "/config", "/server-status"]
        override_headers = [
            "X-Original-URL",
            "X-Rewrite-URL",
            "X-Forwarded-Uri",
            "X-Forwarded-Path",
        ]

        try:
            success_codes = {200, 201, 202, 204, 301, 302, 303, 307, 308}

            for path in test_paths:
                direct_url = urljoin(origin, path.lstrip("/"))

                direct = self.session.get(direct_url, timeout=6, allow_redirects=False)
                direct_status = direct.status_code

                for header in override_headers:
                    overridden = self.session.get(
                        origin,
                        headers={header: path},
                        timeout=6,
                        allow_redirects=False,
                    )
                    override_status = overridden.status_code

                    # Flag if direct access is denied/missing, but override yields a successful response.
                    if direct_status in {401, 403, 404} and override_status in success_codes:
                        self.add_enriched_vulnerability(
                            "Request URL Override",
                            "Medium",
                            "Potential request URL override behavior detected; manual verification is required to confirm access-control impact.",
                            f"Header {header}: {path} | direct {direct_status} vs override {override_status}",
                            "Disable/strip URL override headers at the edge proxy, or ensure the application does not trust them. Manually verify whether sensitive resources become accessible.",
                            confidence="Tentative",
                            category="Access Control",
                            owasp="A01:2021 - Broken Access Control",
                            cwe=["CWE-284"],
                            http_response=overridden,
                        )
                        return

        except Exception:
            return

    def _check_cookie_domain_scoping(self, response: requests.Response, url: str):
        """Detect cookies scoped to parent domains or suspicious Domain attributes."""

        host = urlparse(url).hostname
        if not host:
            return

        for cookie in self._get_set_cookie_headers(response):
            m = re.search(r"(?i)\bdomain=([^;]+)", cookie)
            if not m:
                continue

            domain_attr = m.group(1).strip().lstrip(".").lower()
            host_l = host.lower()

            # Very broad or invalid domain attributes
            if "." not in domain_attr or domain_attr in {"com", "net", "org", "io"}:
                self.add_enriched_vulnerability(
                    "Cookie Domain Scoping Issue",
                    "Medium",
                    "Cookie Domain attribute appears overly broad or invalid.",
                    f"Host={host_l} Domain={domain_attr} Cookie={cookie[:200]}",
                    "Use host-only cookies where possible; avoid setting Domain to a public suffix or overly broad parent.",
                    category="Session Management",
                    owasp="A05:2021 - Security Misconfiguration",
                    cwe=["CWE-565"],
                )
                continue

            if domain_attr == host_l:
                continue

            if host_l.endswith("." + domain_attr):
                # Cookie is scoped to a parent domain
                self.add_enriched_vulnerability(
                    "Cookie Scoped to Parent Domain",
                    "Low",
                    "Cookie is scoped to a parent domain, which can expand the attack surface across subdomains.",
                    f"Host={host_l} Domain={domain_attr} Cookie={cookie[:200]}",
                    "Prefer host-only cookies (omit Domain) for session/auth cookies; isolate auth to dedicated subdomains.",
                    category="Session Management",
                    owasp="A05:2021 - Security Misconfiguration",
                    cwe=["CWE-565"],
                )
            else:
                # Domain attribute not related to host
                self.add_enriched_vulnerability(
                    "Cookie Domain Attribute Mismatch",
                    "Medium",
                    "Cookie Domain attribute does not match the request host; this may indicate misconfiguration.",
                    f"Host={host_l} Domain={domain_attr} Cookie={cookie[:200]}",
                    "Ensure Set-Cookie Domain is correct for the host and not influenced by user input or upstream proxies.",
                    category="Session Management",
                    owasp="A05:2021 - Security Misconfiguration",
                    cwe=["CWE-565"],
                )

    def _check_cloud_resources(self, content: str):
        """Detect exposed cloud resources and credentials (AWS-focused)."""

        findings: List[str] = []

        access_key_matches = re.findall(r"\b(AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16})\b", content)
        for k in access_key_matches:
            findings.append(f"AWS Access Key ID: {k}")

        secret_key_matches = re.findall(
            r"(?i)aws(.{0,20})?(secret|access)[_-]?key(.{0,20})?['\"\s:=]{1,10}([A-Za-z0-9/+=]{40})",
            content,
        )
        for m in secret_key_matches:
            findings.append("AWS Secret Access Key (contextual)")

        s3_matches = re.findall(r"\b([a-z0-9.-]+)\.s3\.amazonaws\.com\b", content)
        for b in s3_matches[:5]:
            findings.append(f"S3 bucket host: {b}.s3.amazonaws.com")

        s3_path_matches = re.findall(r"\bs3\.amazonaws\.com/([a-z0-9.-]+)\b", content)
        for b in s3_path_matches[:5]:
            findings.append(f"S3 bucket path: {b}")

        cloudfront = re.findall(r"\b[a-z0-9]+\.cloudfront\.net\b", content)
        for d in cloudfront[:5]:
            findings.append(f"CloudFront domain: {d}")

        arn = re.findall(r"\barn:aws:[^\s\"']+", content)
        for a in arn[:3]:
            findings.append(f"AWS ARN: {a}")

        if not findings:
            return

        severity = "Medium"
        if access_key_matches and secret_key_matches:
            severity = "Critical"
        elif access_key_matches:
            severity = "High"

        evidence = "; ".join(findings[:8])
        self.add_enriched_vulnerability(
            "Cloud Resource / AWS Key Exposure",
            severity,
            "Potential cloud resource identifiers or AWS credentials found in client-accessible content.",
            evidence,
            "Remove credentials from client-side code, rotate exposed keys immediately, and use short-lived credentials via server-side token exchange.",
            category="Secret Management",
            owasp="A02:2021 - Cryptographic Failures",
            cwe=["CWE-798", "CWE-200"],
        )

    def _check_secret_uncached_url_input(self, url: str, response: requests.Response):
        """Detect secrets in URL params combined with cacheable responses."""

        parsed = urlparse(url)
        if not parsed.query:
            return

        params = parse_qs(parsed.query)
        sensitive_param_names = {
            "token",
            "access_token",
            "id_token",
            "auth",
            "apikey",
            "api_key",
            "key",
            "secret",
            "password",
            "session",
            "sid",
            "jwt",
            "nonce",
            "state",
        }

        suspect = []
        for name, values in params.items():
            name_l = name.lower()
            if name_l in sensitive_param_names or any(s in name_l for s in ["token", "key", "secret", "pass", "session"]):
                suspect.append(name)
                continue
            for v in values:
                if len(v) >= 20 or v.count(".") == 2:  # token-ish / JWT-ish
                    suspect.append(name)
                    break

        if not suspect:
            return

        cache_control = response.headers.get("Cache-Control", "")
        pragma = response.headers.get("Pragma", "")
        is_cacheable = "no-store" not in cache_control.lower() and "no-cache" not in cache_control.lower() and "private" not in cache_control.lower() and "no-cache" not in pragma.lower()

        if is_cacheable:
            self.add_enriched_vulnerability(
                "Secret Uncached Input: URL",
                "Medium",
                "Sensitive-looking URL parameters observed on a potentially cacheable response.",
                f"Params={sorted(set(suspect))} Cache-Control={cache_control}",
                "Avoid passing secrets in URLs; move tokens to Authorization headers or POST bodies and set Cache-Control: no-store.",
                category="Secret Management",
                owasp="A02:2021 - Cryptographic Failures",
                cwe=["CWE-598", "CWE-200"],
            )

    def _check_secret_input_header_reflection(self, url: str):
        """Send a benign secret-like header and see if it is reflected back."""

        token = f"scanner-secret-{secrets.token_hex(8)}"
        header_name = "X-Scanner-Secret"

        try:
            resp = self.session.get(url, headers={header_name: token}, timeout=6)
        except Exception:
            return

        body = ""
        try:
            body = resp.text
        except Exception:
            body = ""

        reflected_in_headers = any(token in v for v in resp.headers.values())
        reflected_in_body = token in body

        if reflected_in_headers or reflected_in_body:
            location = "headers" if reflected_in_headers else "body"
            self.add_enriched_vulnerability(
                "Secret Input Reflected in Response (Header)",
                "High",
                f"A secret-like request header value was reflected in the response {location}.",
                f"Header={header_name} Value={token}",
                "Do not reflect sensitive headers; sanitize server-side logging/debug output and ensure reverse proxies strip debug echoes.",
                category="Information Disclosure",
                owasp="A09:2021 - Security Logging and Monitoring Failures",
                cwe=["CWE-200"],
                http_response=resp,
            )

    def _check_dom_data_manipulation(self, js_content: str):
        """Heuristic detection for DOM-based data manipulation sinks/sources."""

        sources = [
            r"location\.hash",
            r"location\.search",
            r"document\.url",
            r"document\.location",
            r"document\.referrer",
            r"window\.name",
            r"postMessage",
        ]
        sinks = [
            r"\.innerHTML\b",
            r"\.outerHTML\b",
            r"insertAdjacentHTML\b",
            r"document\.write\b",
            r"\beval\s*\(",
        ]

        src_hits = [s for s in sources if re.search(s, js_content, re.IGNORECASE)]
        sink_hits = [s for s in sinks if re.search(s, js_content, re.IGNORECASE)]

        if src_hits and sink_hits:
            self.add_enriched_vulnerability(
                "DOM Data Manipulation (DOM-based)",
                "Medium",
                "Client-side code contains DOM sources and dangerous sinks which may indicate DOM-based XSS/data manipulation risk.",
                f"Sources={len(src_hits)} Sinks={len(sink_hits)}",
                "Avoid assigning URL-derived data into HTML sinks; use safe DOM APIs and output encoding.",
                category="Cross-Site Scripting",
                owasp="A03:2021 - Injection",
                cwe=["CWE-79"],
            )
