# Architecture & Design

## Low-Code Platform Security Scanner - Professional Implementation

This document describes the professional architecture, design patterns, and best practices implemented in the security scanner.

---

## Table of Contents

1. [System Overview](#system-overview)
2. [Module Architecture](#module-architecture)
3. [Design Patterns](#design-patterns)
4. [Professional Features](#professional-features)
5. [Security Standards](#security-standards)
6. [Extension Guide](#extension-guide)

---

## System Overview

The Low-Code Platform Security Scanner is a professional-grade security testing toolkit designed for thesis-level academic research and enterprise security assessments. It provides comprehensive vulnerability detection for low-code platforms (Bubble.io, OutSystems, Airtable) and generic web applications.

### Core Philosophy

- **Professional Quality**: Enterprise-grade code with comprehensive error handling, logging, and configuration management
- **Standardization**: Consistent vulnerability reporting across all platform analyzers
- **Extensibility**: Clean abstractions allowing easy addition of new platform analyzers
- **Research-Ready**: Burp Suite-style reports suitable for academic publication

---

## Module Architecture

```
src/website_security_scanner/
├── __init__.py
├── main.py                          # LowCodeSecurityScanner orchestrator
├── result_transformer.py            # Result normalization
├── report_generator.py              # Professional HTML report generation
│
├── analyzers/                       # Platform-specific security analyzers
│   ├── __init__.py
│   ├── base.py                      # BaseAnalyzer (enriched reporting)
│   ├── bubble.py                    # Bubble.io analyzer
│   ├── outsystems.py                # OutSystems analyzer
│   ├── airtable.py                  # Airtable analyzer
│   ├── generic.py                   # Generic web analyzer
│   ├── advanced_checks.py           # AdvancedChecksMixin
│   ├── factory.py                   # Analyzer factory
│   └── reports.py                   # Report utilities
│
├── config/                          # Configuration management
│   ├── __init__.py
│   ├── settings.py                  # ScannerConfig, SecurityStandards
│   └── constants.py                 # System-wide constants
│
├── exceptions/                      # Custom exception hierarchy
│   ├── __init__.py
│   └── scanner_exceptions.py        # Professional exception classes
│
├── utils/                           # Utility modules
│   ├── __init__.py
│   ├── logger.py                    # Professional logging infrastructure
│   └── utils.py                     # Validation & utility functions
│
└── cli/                             # Command-line interface
    ├── __init__.py
    └── cli.py                       # Rich CLI with batch support
```

---

## Design Patterns

### 1. Strategy Pattern (Analyzers)

Different analysis strategies for each platform while maintaining a common interface:

```python
class BaseAnalyzer:
    def analyze(self, url, response, soup) -> Dict[str, Any]:
        raise NotImplementedError()

class BubbleAnalyzer(BaseAnalyzer):
    def analyze(self, url, response, soup) -> Dict[str, Any]:
        # Bubble-specific analysis
        
class AirtableAnalyzer(BaseAnalyzer):
    def analyze(self, url, response, soup) -> Dict[str, Any]:
        # Airtable-specific analysis
```

### 2. Mixin Pattern (Advanced Checks)

Shared security checks are implemented as a mixin to avoid code duplication:

```python
class AdvancedChecksMixin:
    def _check_session_tokens_in_url(self, url):
        # Shared implementation
        
    def _check_secrets_in_javascript(self, js_content, url):
        # Shared implementation

class BubbleAnalyzer(AdvancedChecksMixin, BaseAnalyzer):
    # Inherits all advanced checks
```

### 3. Factory Pattern (Analyzer Creation)

```python
def get_analyzer_for_platform(platform_type, session):
    analyzers = {
        'bubble': BubbleAnalyzer,
        'outsystems': OutSystemsAnalyzer,
        'airtable': AirtableAnalyzer,
    }
    analyzer_class = analyzers.get(platform_type, GenericWebAnalyzer)
    return analyzer_class(session)
```

### 4. Configuration Object Pattern

```python
config = ScannerConfig.from_env()
errors = config.validate()
if errors:
    raise ScannerConfigurationError("Invalid configuration", details=errors)
```

---

## Professional Features

### 1. Enriched Vulnerability Reporting

All analyzers now support professional-grade vulnerability reporting:

```python
# Basic vulnerability (backwards compatible)
self.add_vulnerability(
    vuln_type="API Key Exposure",
    severity="High",
    description="Exposed API key found",
    evidence="app_12345678901234",
)

# Enriched vulnerability (recommended)
self.add_enriched_vulnerability(
    vuln_type="API Key Exposure",
    severity="High",
    description="Airtable API key exposed in client-side JavaScript",
    evidence=[
        {"type": "regex", "pattern": r"key[A-Za-z0-9]{17}"},
        {"type": "exact", "text": "keyABC123...", "context": "line 45"}
    ],
    background="API keys grant full access to Airtable base data...",
    impact="An attacker could read, modify, or delete all data...",
    references=[
        "https://support.airtable.com/docs/api-security",
        "https://owasp.org/www-project-api-security/"
    ],
    confidence="Certain",
    category="API Security",
    owasp="A01:2021-Broken Access Control",
    cwe=["CWE-522", "CWE-798"]
)
```

### 2. HTTP Context Recording

For Burp-style Request/Response reporting:

```python
def analyze(self, url, response, soup):
    # Record HTTP context at the start of analysis
    self._record_http_context(url, response)
    
    # All subsequent enriched vulnerabilities automatically include
    # the HTTP request/response pair
    self.add_enriched_vulnerability(...)
```

### 3. Professional Logging

Structured logging with multiple output handlers:

```python
from ..utils.logger import get_logger

class MyAnalyzer(BaseAnalyzer):
    def __init__(self, session):
        super().__init__(session)
        self.logger = get_logger(self.__class__.__name__)
    
    def analyze(self, url, response, soup):
        self.logger.info(f"Starting analysis for {url}")
        
        try:
            # Analysis logic
            self.logger.debug("Analysis step completed")
        except Exception as e:
            self.logger.error(f"Analysis failed", exc_info=True)
```

### 4. Configuration Management

Centralized configuration with validation:

```python
from website_security_scanner.config import ScannerConfig

# Load from environment variables
config = ScannerConfig.from_env()

# Or programmatic configuration
config = ScannerConfig(
    request_timeout=30,
    max_retries=3,
    enable_advanced_checks=True,
    output_format="html"
)

# Validate configuration
errors = config.validate()
if errors:
    print(f"Configuration errors: {errors}")
```

### 5. Exception Handling

Professional exception hierarchy with context:

```python
from website_security_scanner.exceptions import (
    ScannerNetworkError,
    AnalysisError,
    ScannerTimeoutError
)

try:
    response = session.get(url, timeout=config.request_timeout)
except requests.Timeout:
    raise ScannerTimeoutError(
        "Request timed out",
        timeout_seconds=config.request_timeout,
        operation="http_request"
    )
except requests.ConnectionError as e:
    raise ScannerNetworkError(
        "Connection failed",
        url=url,
        retry_count=retries
    )
```

---

## Security Standards

### OWASP Top 10 Mapping

All vulnerabilities are mapped to OWASP Top 10 2021:

```python
# From constants.py
OWASP_TOP_10_2021 = {
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
```

### CWE Integration

Common Weakness Enumeration identifiers for precise vulnerability classification:

```python
# Vulnerability with CWE mapping
self.add_enriched_vulnerability(
    vuln_type="Cookie Security: Missing Secure Attribute",
    cwe=["CWE-614"],  # Sensitive Cookie in HTTPS Session Without 'Secure' Attribute
    owasp="A05:2021-Security Misconfiguration",
    ...
)
```

### Severity & Confidence Levels

- **Severity**: Critical, High, Medium, Low, Info
- **Confidence**: Certain, Firm, Tentative (aligned with Burp Suite)

---

## Extension Guide

### Adding a New Platform Analyzer

1. **Create analyzer class**:

```python
# src/website_security_scanner/analyzers/newplatform.py

from typing import Any, Dict, List
import requests
from bs4 import BeautifulSoup

from .base import BaseAnalyzer
from .advanced_checks import AdvancedChecksMixin

class NewPlatformAnalyzer(AdvancedChecksMixin, BaseAnalyzer):
    """
    Specialized analyzer for NewPlatform applications.
    
    Provides comprehensive security analysis for NewPlatform...
    """
    
    def __init__(self, session: requests.Session):
        """Initialize NewPlatform analyzer."""
        super().__init__(session)
        self.platform_specific_data: List[str] = []
    
    def analyze(
        self, url: str, response: requests.Response, soup: BeautifulSoup
    ) -> Dict[str, Any]:
        """
        Comprehensive NewPlatform security analysis.
        
        Args:
            url: Target URL being analyzed
            response: HTTP response from target
            soup: Parsed BeautifulSoup object
            
        Returns:
            Dictionary containing analysis results and vulnerabilities
        """
        # ALWAYS record HTTP context for enriched reporting
        self._record_http_context(url, response)
        
        # Extract content
        js_content = self._extract_javascript(soup)
        html_content = str(soup)
        
        # Platform-specific checks
        self._check_newplatform_specific_issue(js_content)
        
        # Use inherited advanced checks
        self._check_session_tokens_in_url(url)
        self._check_secrets_in_javascript(js_content, url)
        
        return {
            "platform_specific_data": self.platform_specific_data,
            "vulnerabilities": self.vulnerabilities,
            "findings": self.findings,
        }
    
    def _check_newplatform_specific_issue(self, js_content: str):
        """Check for platform-specific security issue."""
        import re
        
        pattern = r'newPlatformAPI\s*=\s*["\']([^"\']+)["\']'
        matches = re.findall(pattern, js_content)
        
        if matches:
            self.add_enriched_vulnerability(
                vuln_type="NewPlatform API Key Exposure",
                severity="High",
                description=f"Found {len(matches)} exposed API keys",
                evidence=matches,
                background="NewPlatform API keys provide...",
                impact="Attackers could access sensitive...",
                references=[
                    "https://docs.newplatform.com/security",
                ],
                confidence="Certain",
                category="API Security",
                owasp="A01:2021-Broken Access Control",
                cwe=["CWE-798"]
            )
```

2. **Register in factory** (`analyzers/factory.py`):

```python
def get_analyzer_for_platform(platform_type: str, session: requests.Session):
    analyzers = {
        'bubble': BubbleAnalyzer,
        'outsystems': OutSystemsAnalyzer,
        'airtable': AirtableAnalyzer,
        'newplatform': NewPlatformAnalyzer,  # Add here
    }
    ...
```

3. **Add platform detection** (`main.py`):

```python
def identify_platform(self, url):
    domain = urlparse(url).netloc.lower()
    
    if "newplatform" in domain:
        return "newplatform"
    ...
```

### Adding Custom Security Checks

For checks that should be available to all analyzers, add to `AdvancedChecksMixin`:

```python
# analyzers/advanced_checks.py

class AdvancedChecksMixin:
    def _check_new_vulnerability(self, content: str):
        """Check for new vulnerability type."""
        # Implementation
        
        if vulnerability_found:
            self.add_enriched_vulnerability(
                vuln_type="New Vulnerability Type",
                severity="Medium",
                description="Description of the issue",
                ...
            )
```

---

## Best Practices

### 1. Always Use Enriched Reporting

```python
# ❌ Basic (legacy)
self.add_vulnerability(
    "Issue", "High", "Description"
)

# ✅ Professional
self.add_enriched_vulnerability(
    vuln_type="Issue",
    severity="High",
    description="Detailed description",
    background="Why this matters",
    impact="Business/technical impact",
    references=["https://..."],
    ...
)
```

### 2. Record HTTP Context

```python
def analyze(self, url, response, soup):
    # ✅ ALWAYS at start of analyze()
    self._record_http_context(url, response)
    
    # Now all enriched vulnerabilities include request/response
```

### 3. Use Type Hints

```python
# ✅ Properly typed
def analyze(
    self, url: str, response: requests.Response, soup: BeautifulSoup
) -> Dict[str, Any]:
    pass

# ✅ Typed attributes
self.api_endpoints: List[str] = []
self.vulnerabilities: List[Dict[str, Any]] = []
```

### 4. Professional Documentation

```python
def method_name(self, param1: str, param2: int) -> bool:
    """
    Brief description of what this method does.
    
    More detailed explanation if needed, including:
    - Important behaviors
    - Side effects
    - Performance considerations
    
    Args:
        param1: Description of param1
        param2: Description of param2
        
    Returns:
        Description of return value
        
    Raises:
        ScannerError: When X condition occurs
    """
```

### 5. Proper Logging

```python
# ✅ Contextual logging
self.logger.info(f"Starting analysis for {url}")
self.logger.warning(f"Vulnerability found: {vuln_type}")
self.logger.error(f"Analysis failed", exc_info=True)

# ❌ Avoid print statements
print("Starting scan...")  # Don't do this
```

---

## Performance Considerations

### Concurrent Scanning

```python
config = ScannerConfig(
    max_concurrent_scans=5,
    max_concurrent_requests=10,
    rate_limit_delay=0.5  # seconds between requests
)
```

### Caching

```python
config = ScannerConfig(
    enable_caching=True,
    cache_ttl=3600  # 1 hour
)
```

### Timeouts

```python
config = ScannerConfig(
    request_timeout=30,
    scan_timeout=300
)
```

---

## Testing Strategy

### Unit Tests

Test individual analyzer methods:

```python
def test_bubble_workflow_detection():
    analyzer = BubbleAnalyzer(session)
    js_content = "api/1.1/wf/test_workflow"
    
    analyzer._analyze_workflows(js_content)
    
    assert len(analyzer.workflow_patterns) > 0
    assert any("test_workflow" in str(p) for p in analyzer.workflow_patterns)
```

### Integration Tests

Test complete scan workflows:

```python
def test_complete_bubble_scan():
    scanner = LowCodeSecurityScanner()
    results = scanner.scan_target("https://test.bubbleapps.io/version-test")
    
    assert results["platform_type"] == "bubble"
    assert "vulnerabilities" in results
```

---

## Reporting

### HTML Reports (Burp Suite Style)

```python
from website_security_scanner.report_generator import ProfessionalReportGenerator

generator = ProfessionalReportGenerator()
report_path = generator.generate_report(
    scan_results,
    output_path="security_report.html"
)
```

### Custom Report Formats

Extend the report generator:

```python
class CustomReportGenerator(ProfessionalReportGenerator):
    def generate_pdf_report(self, results):
        # PDF generation logic
        pass
```

---

## Compliance & Standards

### OWASP ASVS Levels

```python
standards = SecurityStandards(
    asvs_level=2,  # Level 1, 2, or 3
    min_security_header_score=0.75,
    min_tls_version="TLSv1.2"
)
```

### PCI DSS / HIPAA

```python
config = ScannerConfig(
    check_pci_dss=True,
    check_hipaa=True
)
```

---

## Support & Contribution

For questions or contributions:
- Review existing analyzer implementations
- Follow the established patterns
- Add comprehensive tests
- Update documentation

---

**Version**: 2.0.0 (Professional Implementation)
**Last Updated**: 2024
**Maintainer**: Bachelor Thesis Project Team
