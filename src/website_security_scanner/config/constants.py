"""
Security Scanner Constants
Low-Code Platform Security Scanner

Professional-grade constants for security scanning operations.

Author: Bachelor Thesis Project - Low-Code Platforms Security Analysis
"""

from typing import Dict, List

# Severity Levels (aligned with industry standards)
SEVERITY_LEVELS: Dict[str, int] = {
    "Critical": 4,
    "High": 3,
    "Medium": 2,
    "Low": 1,
    "Info": 0,
    "Information": 0,
}

# Confidence Levels (Burp Suite style)
CONFIDENCE_LEVELS: Dict[str, int] = {
    "Certain": 3,
    "Firm": 2,
    "Tentative": 1,
}

# Vulnerability Categories (OWASP-aligned)
VULNERABILITY_CATEGORIES: List[str] = [
    "Authentication",
    "Authorization",
    "Session Management",
    "Data Exposure",
    "Input Validation",
    "Cryptography",
    "Error Handling",
    "API Security",
    "Configuration",
    "Information Disclosure",
    "Business Logic",
    "CSRF",
    "XSS",
    "SQL Injection",
    "Command Injection",
    "Path Traversal",
    "File Upload",
    "Security Headers",
    "SSL/TLS",
    "Cookie Security",
    "CORS",
    "Clickjacking",
    "Platform-Specific",
    "General",
]

# HTTP Security Headers (Best Practices)
HTTP_SECURITY_HEADERS: Dict[str, Dict[str, str]] = {
    "X-Frame-Options": {
        "description": "Protection against clickjacking attacks",
        "recommended": "DENY or SAMEORIGIN",
        "owasp": "A7:2017-Cross-Site Scripting (XSS)",
    },
    "X-Content-Type-Options": {
        "description": "Prevents MIME type sniffing",
        "recommended": "nosniff",
        "owasp": "A6:2017-Security Misconfiguration",
    },
    "X-XSS-Protection": {
        "description": "Enables browser XSS protection",
        "recommended": "1; mode=block",
        "owasp": "A7:2017-Cross-Site Scripting (XSS)",
    },
    "Strict-Transport-Security": {
        "description": "Enforces HTTPS connections",
        "recommended": "max-age=31536000; includeSubDomains",
        "owasp": "A6:2017-Security Misconfiguration",
    },
    "Content-Security-Policy": {
        "description": "Controls resource loading to prevent XSS",
        "recommended": "default-src 'self'",
        "owasp": "A7:2017-Cross-Site Scripting (XSS)",
    },
    "Referrer-Policy": {
        "description": "Controls referrer information disclosure",
        "recommended": "no-referrer or strict-origin-when-cross-origin",
        "owasp": "A3:2017-Sensitive Data Exposure",
    },
    "Permissions-Policy": {
        "description": "Controls browser features and APIs",
        "recommended": "geolocation=(), microphone=(), camera=()",
        "owasp": "A6:2017-Security Misconfiguration",
    },
    "X-Permitted-Cross-Domain-Policies": {
        "description": "Controls cross-domain policy files",
        "recommended": "none",
        "owasp": "A6:2017-Security Misconfiguration",
    },
}

# Platform Types
PLATFORM_TYPES: List[str] = [
    "bubble",
    "outsystems",
    "airtable",
    "unknown",
]

# OWASP Top 10 (2021) Mapping
OWASP_TOP_10_2021: Dict[str, str] = {
    "A01": "Broken Access Control",
    "A02": "Cryptographic Failures",
    "A03": "Injection",
    "A04": "Insecure Design",
    "A05": "Security Misconfiguration",
    "A06": "Vulnerable and Outdated Components",
    "A07": "Identification and Authentication Failures",
    "A08": "Software and Data Integrity Failures",
    "A09": "Security Logging and Monitoring Failures",
    "A10": "Server-Side Request Forgery (SSRF)",
}

# Common CWE Mappings
COMMON_CWE: Dict[str, str] = {
    "CWE-79": "Cross-site Scripting (XSS)",
    "CWE-89": "SQL Injection",
    "CWE-200": "Exposure of Sensitive Information",
    "CWE-209": "Generation of Error Message Containing Sensitive Information",
    "CWE-256": "Plaintext Storage of a Password",
    "CWE-259": "Use of Hard-coded Password",
    "CWE-295": "Improper Certificate Validation",
    "CWE-297": "Improper Validation of Certificate with Host Mismatch",
    "CWE-311": "Missing Encryption of Sensitive Data",
    "CWE-312": "Cleartext Storage of Sensitive Information",
    "CWE-319": "Cleartext Transmission of Sensitive Information",
    "CWE-326": "Inadequate Encryption Strength",
    "CWE-327": "Use of a Broken or Risky Cryptographic Algorithm",
    "CWE-352": "Cross-Site Request Forgery (CSRF)",
    "CWE-359": "Exposure of Private Information",
    "CWE-384": "Session Fixation",
    "CWE-521": "Weak Password Requirements",
    "CWE-522": "Insufficiently Protected Credentials",
    "CWE-614": "Sensitive Cookie in HTTPS Session Without 'Secure' Attribute",
    "CWE-798": "Use of Hard-coded Credentials",
    "CWE-863": "Incorrect Authorization",
}

# Scan Timeout Settings (seconds)
DEFAULT_REQUEST_TIMEOUT: int = 30
DEFAULT_SCAN_TIMEOUT: int = 300
MAX_CONCURRENT_REQUESTS: int = 10

# User Agents for Testing
USER_AGENTS: Dict[str, str] = {
    "chrome": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "firefox": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "safari": "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "edge": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
}

# Default Output Formats
OUTPUT_FORMATS: List[str] = ["json", "yaml", "html", "text"]

# Regex Patterns for Common Vulnerabilities
COMMON_PATTERNS: Dict[str, str] = {
    "api_key": r"(?i)(api[_-]?key|apikey|api[_-]?token)[\s]*[:=][\s]*['\"]?([a-zA-Z0-9_\-]{20,})['\"]?",
    "secret_key": r"(?i)(secret[_-]?key|secretkey)[\s]*[:=][\s]*['\"]?([a-zA-Z0-9_\-]{20,})['\"]?",
    "password": r"(?i)(password|passwd|pwd)[\s]*[:=][\s]*['\"]?([^\s'\"]{6,})['\"]?",
    "jwt": r"eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*",
    "aws_key": r"AKIA[0-9A-Z]{16}",
    "private_key": r"-----BEGIN (RSA|EC|DSA|OPENSSH) PRIVATE KEY-----",
}
