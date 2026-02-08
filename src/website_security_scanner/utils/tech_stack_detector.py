#!/usr/bin/env python3
"""
Technology Stack Detection Utility

Detects Server, Backend, and Frontend technologies from HTTP responses and page content.
This module analyzes HTTP headers, HTML content, and JavaScript to identify the technology
stack in use by a web application.

Author: Bachelor Thesis Project - Low-Code Platforms Security Analysis
"""

import re
import requests
from typing import Dict, List, Any, Optional
from bs4 import BeautifulSoup


class TechStackDetector:
    """
    Detects the technology stack of a web application.

    Analyzes HTTP headers, HTML content, scripts, and meta tags to identify:
    - Server technologies (Nginx, Apache, Cloudflare, etc.)
    - Backend frameworks (Node.js, Python, Express, Django, etc.)
    - Frontend frameworks (React, Vue, jQuery, Angular, etc.)
    """

    def __init__(self, session: requests.Session):
        """
        Initialize the tech stack detector.

        Args:
            session: Configured requests session for HTTP operations
        """
        self.session = session
        self.timeout_seconds = getattr(session, "default_timeout", 10) or 10

        # Technology signatures for detection
        self.server_signatures = {
            'nginx': {
                'headers': [r'server:\s*nginx'],
                'patterns': [r'nginx', r'openresty'],
            },
            'apache': {
                'headers': [r'server:\s*apache', r'server:\s*cpanel'],
                'patterns': [r'apache', r'httpd'],
            },
            'cloudflare': {
                'headers': [r'cf-ray:', r'server:\s*cloudflare', r'cf-'],
                'patterns': [r'cloudflare'],
            },
            'iis': {
                'headers': [r'server:\s*microsoft-iis'],
                'patterns': [r'iis', r'microsoft-iis'],
            },
            'aws': {
                'headers': [r'x-amz-', r'server:\s*aws', r'x-amz-cf-'],
                'patterns': [r'amazon', r'awselb', r'aws'],
            },
            'vercel': {
                'headers': [r'x-vercel-', r'x-vercel-id'],
                'patterns': [r'vercel'],
            },
            'netlify': {
                'headers': [r'x-nf-request-id', r'netlify'],
                'patterns': [r'netlify'],
            },
        }

        self.backend_signatures = {
            'node.js': {
                'headers': [r'x-powered-by:\s*express', r'x-powered-by:\s*node'],
                'patterns': [r'node\.js', r'nodejs', r'express'],
                'scripts': [r'/node_modules/', r'react\.js', r'express'],
            },
            'python': {
                'headers': [r'server:\s*.*python', r'x-powered-by:\s*.*python'],
                'patterns': [r'python', r'django', r'flask', r'pyramid'],
                'scripts': [r'/static/', r'django\.js'],
            },
            'php': {
                'headers': [r'x-powered-by:\s*php', r'server:\s*.*php'],
                'patterns': [r'php'],
                'scripts': [r'\.php\b'],
            },
            'ruby': {
                'headers': [r'x-powered-by:\s*.*ruby', r'x-powered-by:\s*phusion'],
                'patterns': [r'ruby', r'rails', r'rack'],
                'scripts': [r'/assets/', r'turbolinks'],
            },
            'java': {
                'headers': [r'server:\s*.*tomcat', r'server:\s*.*jetty', r'server:\s*jboss'],
                'patterns': [r'jsp', r'servlet', r'java', r'spring'],
                'scripts': [r'\.jsf\b', r'richfaces'],
            },
            'go': {
                'headers': [r'server:\s*go-', r'x-powered-by:\s*go'],
                'patterns': [r'golang', r'gofast'],
                'scripts': [],
            },
        }

        self.frontend_signatures = {
            'react': {
                'patterns': [
                    r'react\s*(?:dom)?',
                    r'reactdom',
                    r'_react',
                    r'react\s*\.\s*createElement',
                    r'usestate',
                    r'useeffect',
                ],
                'scripts': [
                    r'react(\.production\.min)?\.js',
                    r'react-dom(\.production\.min)?\.js',
                    r'/_next/static/',
                    r'/_next/',
                ],
                'meta': [r'generator.*react'],
            },
            'vue': {
                'patterns': [
                    r'vue\.js',
                    r'\.vue',
                    r'v-if',
                    r'v-for',
                    r'v-bind',
                    r'vue-router',
                    r'vuex',
                ],
                'scripts': [
                    r'vue(\.min)?\.js',
                    r'vue-router(\.min)?\.js',
                    r'vuex(\.min)?\.js',
                ],
                'meta': [r'generator.*vue'],
            },
            'jquery': {
                'patterns': [
                    r'\$\(document\)',
                    r'jquery',
                    r'\.ajax\(',
                    r'\.ready\(',
                    r'\.on\(',
                ],
                'scripts': [
                    r'jquery[-\d.]*\.js',
                    r'jquery(\.min)?\.js',
                ],
                'meta': [],
            },
            'angular': {
                'patterns': [
                    r'ng-app',
                    r'ng-controller',
                    r'ng-model',
                    r'angular',
                    r'ng-module',
                    r'\.\.module\(',
                ],
                'scripts': [
                    r'angular(\.min)?\.js',
                    r'angular-route(\.min)?\.js',
                    r'angular-resource(\.min)?\.js',
                ],
                'meta': [r'generator.*angular'],
            },
            'svelte': {
                'patterns': [
                    r'svelte',
                    r'svelte:',
                ],
                'scripts': [
                    r'svelte(\.min)?\.js',
                    r'\.svelte',
                ],
                'meta': [],
            },
            'next.js': {
                'patterns': [
                    r'/_next/static/',
                    r'next/router',
                    r'next/link',
                ],
                'scripts': [
                    r'/_next/static/',
                    r'next(\.min)?\.js',
                ],
                'meta': [r'generator.*next'],
            },
        }

    def detect_tech_stack(
        self, url: str, response: Optional[requests.Response] = None
    ) -> Dict[str, Any]:
        """
        Detect the technology stack of a web application.

        Args:
            url: Target URL to analyze
            response: Optional HTTP response (if not provided, will fetch)

        Returns:
            Dictionary containing detected technologies:
            {
                'server': {'detected': [], 'evidence': {}},
                'backend': {'detected': [], 'evidence': {}},
                'frontend': {'detected': [], 'evidence': {}},
                'all': {'detected': [], 'evidence': {}}
            }
        """
        if response is None:
            try:
                response = self.session.get(url, timeout=self.timeout_seconds)
            except Exception as e:
                return {
                    'server': {'detected': [], 'evidence': {}},
                    'backend': {'detected': [], 'evidence': {}},
                    'frontend': {'detected': [], 'evidence': {}},
                    'all': {'detected': [], 'evidence': {}},
                    'error': str(e),
                }

        # Check if response is HTML
        content_type = response.headers.get("Content-Type", "").lower()
        is_html = "text/html" in content_type or "application/xhtml+xml" in content_type

        soup = BeautifulSoup(response.text if is_html else "", 'html.parser')

        # Detect each category
        server_results = self._detect_server(response, soup)
        backend_results = self._detect_backend(response, soup, is_html)
        frontend_results = self._detect_frontend(response, soup, is_html)

        # Combine all results
        all_detected = (
            server_results['detected'] + backend_results['detected'] + frontend_results['detected']
        )
        all_evidence = {
            **server_results['evidence'],
            **backend_results['evidence'],
            **frontend_results['evidence'],
        }

        return {
            'server': server_results,
            'backend': backend_results,
            'frontend': frontend_results,
            'all': {
                'detected': all_detected,
                'evidence': all_evidence,
            },
        }

    def _detect_server(
        self, response: requests.Response, soup: BeautifulSoup
    ) -> Dict[str, Any]:
        """Detect server technologies."""
        detected = []
        evidence = {}

        # Check headers
        headers_str = '\n'.join(f'{k}: {v}' for k, v in response.headers.items())

        for tech_name, signatures in self.server_signatures.items():
            tech_evidence = []

            # Check header patterns
            for pattern in signatures.get('headers', []):
                if re.search(pattern, headers_str, re.IGNORECASE):
                    tech_evidence.append(f'Header pattern: {pattern}')

            # Check content patterns
            page_text = str(soup)
            for pattern in signatures.get('patterns', []):
                if re.search(pattern, page_text, re.IGNORECASE):
                    tech_evidence.append(f'Content pattern: {pattern}')

            if tech_evidence:
                detected.append(tech_name)
                evidence[tech_name] = tech_evidence

        return {'detected': detected, 'evidence': evidence}

    def _detect_backend(
        self, response: requests.Response, soup: BeautifulSoup, is_html: bool
    ) -> Dict[str, Any]:
        """Detect backend technologies."""
        detected = []
        evidence = {}

        # Check headers
        headers_str = '\n'.join(f'{k}: {v}' for k, v in response.headers.items())

        for tech_name, signatures in self.backend_signatures.items():
            tech_evidence = []

            # Check header patterns
            for pattern in signatures.get('headers', []):
                if re.search(pattern, headers_str, re.IGNORECASE):
                    tech_evidence.append(f'Header pattern: {pattern}')

            if is_html:
                # Check content patterns
                page_text = str(soup)
                for pattern in signatures.get('patterns', []):
                    if re.search(pattern, page_text, re.IGNORECASE):
                        tech_evidence.append(f'Content pattern: {pattern}')

                # Check script patterns
                scripts = soup.find_all('script')
                for script in scripts:
                    script_src = script.get('src', '')
                    script_content = script.string or ''

                    for pattern in signatures.get('scripts', []):
                        if re.search(pattern, script_src, re.IGNORECASE) or re.search(
                            pattern, script_content, re.IGNORECASE
                        ):
                            tech_evidence.append(f'Script pattern: {pattern} in {script_src or "inline"}')
                            break

            if tech_evidence:
                detected.append(tech_name)
                evidence[tech_name] = tech_evidence

        return {'detected': detected, 'evidence': evidence}

    def _detect_frontend(
        self, response: requests.Response, soup: BeautifulSoup, is_html: bool
    ) -> Dict[str, Any]:
        """Detect frontend frameworks."""
        detected = []
        evidence = {}

        if not is_html:
            return {'detected': detected, 'evidence': evidence}

        page_text = str(soup)

        for tech_name, signatures in self.frontend_signatures.items():
            tech_evidence = []

            # Check content patterns
            for pattern in signatures.get('patterns', []):
                matches = re.findall(pattern, page_text, re.IGNORECASE)
                if matches:
                    tech_evidence.append(f'Content pattern: {pattern} ({len(matches)} matches)')

            # Check script sources
            scripts = soup.find_all('script')
            for script in scripts:
                script_src = script.get('src', '')
                script_content = script.string or ''

                for pattern in signatures.get('scripts', []):
                    if re.search(pattern, script_src, re.IGNORECASE):
                        tech_evidence.append(f'Script source: {script_src}')
                        break

            # Check meta tags
            meta_tags = soup.find_all('meta')
            for meta in meta_tags:
                meta_content = str(meta)
                for pattern in signatures.get('meta', []):
                    if re.search(pattern, meta_content, re.IGNORECASE):
                        tech_evidence.append(f'Meta tag pattern: {pattern}')
                        break

            if tech_evidence:
                detected.append(tech_name)
                evidence[tech_name] = tech_evidence

        return {'detected': detected, 'evidence': evidence}

    def get_tech_stack_summary(self, tech_stack: Dict[str, Any]) -> str:
        """
        Get a human-readable summary of the detected technology stack.

        Args:
            tech_stack: Tech stack detection results

        Returns:
            Formatted summary string
        """
        summary_parts = []

        if tech_stack['server']['detected']:
            summary_parts.append(f"Server: {', '.join(tech_stack['server']['detected'])}")

        if tech_stack['backend']['detected']:
            summary_parts.append(f"Backend: {', '.join(tech_stack['backend']['detected'])}")

        if tech_stack['frontend']['detected']:
            summary_parts.append(f"Frontend: {', '.join(tech_stack['frontend']['detected'])}")

        if not summary_parts:
            return "No technologies detected"

        return '; '.join(summary_parts)


def detect_tech_stack(
    url: str, session: requests.Session, response: Optional[requests.Response] = None
) -> Dict[str, Any]:
    """
    Convenience function for tech stack detection.

    Args:
        url: Target URL
        session: Requests session
        response: Optional HTTP response (if not provided, will fetch)

    Returns:
        Technology stack detection results
    """
    detector = TechStackDetector(session)
    return detector.detect_tech_stack(url, response)
