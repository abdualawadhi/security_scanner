# Contributing Guide

## Low-Code Platform Security Scanner

Thank you for your interest in contributing to the Low-Code Platform Security Scanner! This guide will help you understand our development standards and contribution process.

---

## Table of Contents

1. [Code of Conduct](#code-of-conduct)
2. [Development Setup](#development-setup)
3. [Coding Standards](#coding-standards)
4. [Adding New Features](#adding-new-features)
5. [Testing Requirements](#testing-requirements)
6. [Pull Request Process](#pull-request-process)

---

## Code of Conduct

This project maintains professional academic standards. Please:
- Write clean, well-documented code
- Follow established patterns and conventions
- Test your changes thoroughly
- Provide clear commit messages and documentation

---

## Development Setup

### Prerequisites

- Python 3.8+
- Virtual environment tool (venv, virtualenv, or conda)
- Git

### Setup Steps

```bash
# Clone the repository
git clone <repository-url>
cd website_security_scanner

# Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Run tests (if available)
python -m pytest tests/

# Run a test scan
python -m website_security_scanner --url https://example.com --output-format text
```

---

## Coding Standards

### Python Style Guide

We follow PEP 8 with these specific guidelines:

#### Naming Conventions

```python
# Classes: PascalCase
class BubbleAnalyzer:
    pass

# Functions and methods: snake_case
def analyze_security_headers():
    pass

# Constants: UPPER_SNAKE_CASE
MAX_RETRIES = 3
DEFAULT_TIMEOUT = 30

# Private methods: _leading_underscore
def _internal_helper():
    pass
```

#### Type Hints

**REQUIRED** for all public methods and class attributes:

```python
from typing import Dict, List, Optional, Any

class MyAnalyzer:
    def __init__(self, session: requests.Session):
        self.vulnerabilities: List[Dict[str, Any]] = []
        self.api_keys: List[str] = []
    
    def analyze(
        self, url: str, response: requests.Response, soup: BeautifulSoup
    ) -> Dict[str, Any]:
        """Analyze target for vulnerabilities."""
        return {"vulnerabilities": self.vulnerabilities}
```

#### Documentation

**REQUIRED** for all public classes, methods, and functions:

```python
def calculate_risk_score(
    severity: str, 
    confidence: str,
    exploitability: float
) -> float:
    """
    Calculate numerical risk score for a vulnerability.
    
    The risk score combines severity, confidence, and exploitability
    metrics to produce a value between 0.0 and 10.0 for prioritization.
    
    Args:
        severity: Severity level (Critical, High, Medium, Low, Info)
        confidence: Confidence level (Certain, Firm, Tentative)
        exploitability: Ease of exploitation (0.0 to 1.0)
        
    Returns:
        Risk score between 0.0 and 10.0
        
    Raises:
        ValueError: If severity or confidence level is invalid
        
    Example:
        >>> calculate_risk_score("High", "Certain", 0.9)
        9.2
    """
    pass
```

### Imports Organization

```python
# Standard library imports
import json
import re
from datetime import datetime
from typing import Any, Dict, List

# Third-party imports
import requests
from bs4 import BeautifulSoup

# Local application imports
from .base import BaseAnalyzer
from ..config import ScannerConfig
from ..exceptions import AnalysisError
from ..utils.logger import get_logger
```

---

## Adding New Features

### Adding a New Platform Analyzer

1. **Create the analyzer file**:

```bash
touch src/website_security_scanner/analyzers/newplatform.py
```

2. **Implement the analyzer**:

```python
#!/usr/bin/env python3
"""
NewPlatform Security Analyzer
Low-Code Platform Security Scanner

Specialized analyzer for NewPlatform applications with platform-specific
vulnerability detection.

Author: Your Name <email@example.com>
"""

from typing import Any, Dict, List
import requests
from bs4 import BeautifulSoup

from .base import BaseAnalyzer
from .advanced_checks import AdvancedChecksMixin


class NewPlatformAnalyzer(AdvancedChecksMixin, BaseAnalyzer):
    """
    Specialized analyzer for NewPlatform applications.
    
    Provides comprehensive security analysis including:
    - API endpoint exposure detection
    - Authentication mechanism analysis
    - Data access control verification
    """
    
    def __init__(self, session: requests.Session):
        """
        Initialize NewPlatform analyzer.
        
        Args:
            session: Configured requests session for HTTP operations
        """
        super().__init__(session)
        self.api_endpoints: List[str] = []
    
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
        # REQUIRED: Record HTTP context for enriched reporting
        self._record_http_context(url, response)
        
        # Your analysis logic here
        js_content = self._extract_javascript(soup)
        
        self._check_api_endpoints(js_content)
        
        # Use inherited checks
        self._check_session_tokens_in_url(url)
        
        return {
            "api_endpoints": self.api_endpoints,
            "vulnerabilities": self.vulnerabilities,
            "findings": self.findings,
        }
    
    def _extract_javascript(self, soup: BeautifulSoup) -> str:
        """Extract JavaScript content for analysis."""
        js_content = ""
        for script in soup.find_all("script"):
            if script.string:
                js_content += script.string + "\n"
        return js_content
    
    def _check_api_endpoints(self, js_content: str):
        """Check for exposed API endpoints."""
        import re
        
        pattern = r'api\.newplatform\.com/v1/([a-zA-Z0-9/_]+)'
        matches = re.findall(pattern, js_content)
        
        if matches:
            self.api_endpoints.extend(matches)
            
            # REQUIRED: Use enriched vulnerability reporting
            self.add_enriched_vulnerability(
                vuln_type="API Endpoint Exposure",
                severity="Medium",
                description=f"Found {len(matches)} exposed API endpoints",
                evidence=matches,
                background=(
                    "Exposed API endpoints may reveal sensitive application "
                    "structure and provide attack vectors..."
                ),
                impact=(
                    "Attackers can enumerate API endpoints to discover "
                    "additional attack surface and potential vulnerabilities..."
                ),
                references=[
                    "https://docs.newplatform.com/security/api",
                    "https://owasp.org/www-project-api-security/",
                ],
                recommendation=(
                    "Implement API endpoint obfuscation and rate limiting. "
                    "Use authentication tokens for all API access."
                ),
                confidence="Firm",
                category="API Security",
                owasp="A01:2021-Broken Access Control",
                cwe=["CWE-200"]
            )
```

3. **Register in factory** (`analyzers/factory.py`):

```python
from .newplatform import NewPlatformAnalyzer

def get_analyzer_for_platform(platform_type: str, session: requests.Session):
    """Factory function to get appropriate analyzer for platform type."""
    analyzers = {
        'bubble': BubbleAnalyzer,
        'outsystems': OutSystemsAnalyzer,
        'airtable': AirtableAnalyzer,
        'newplatform': NewPlatformAnalyzer,  # Add here
    }
    
    analyzer_class = analyzers.get(platform_type, GenericWebAnalyzer)
    return analyzer_class(session)
```

4. **Add platform detection** (`main.py`):

```python
def identify_platform(self, url):
    """Identify the low-code platform based on URL and response."""
    domain = urlparse(url).netloc.lower()
    
    if "newplatform" in domain or "newplat.io" in domain:
        return "newplatform"
    # ... existing platforms
```

5. **Update documentation**:
   - Add entry to README.md under "Supported Platforms"
   - Document platform-specific vulnerabilities checked
   - Add usage examples

### Adding New Security Checks

For checks that should be available to all analyzers:

1. **Add to AdvancedChecksMixin** (`analyzers/advanced_checks.py`):

```python
class AdvancedChecksMixin:
    """Mixin providing advanced security checks for all analyzers."""
    
    def _check_new_vulnerability_type(self, content: str, url: str):
        """
        Check for new vulnerability type.
        
        Args:
            content: Content to analyze (JS, HTML, etc.)
            url: Target URL being analyzed
        """
        import re
        
        # Detection logic
        pattern = r'vulnerablePattern\(["\']([^"\']+)["\']\)'
        matches = re.findall(pattern, content)
        
        if matches:
            self.add_enriched_vulnerability(
                vuln_type="New Vulnerability Type",
                severity="High",  # or appropriate level
                description=f"Detected vulnerable pattern: {len(matches)} instances",
                evidence=matches,
                background="This vulnerability occurs when...",
                impact="An attacker could exploit this to...",
                references=[
                    "https://cwe.mitre.org/data/definitions/XXX.html",
                ],
                recommendation="To remediate this issue...",
                confidence="Firm",
                category="Appropriate Category",
                owasp="AXX:2021-Category",
                cwe=["CWE-XXX"]
            )
```

2. **Use in analyzer**:

```python
class MyAnalyzer(AdvancedChecksMixin, BaseAnalyzer):
    def analyze(self, url, response, soup):
        self._record_http_context(url, response)
        
        content = str(soup)
        
        # Use the new check
        self._check_new_vulnerability_type(content, url)
```

---

## Testing Requirements

### Unit Tests

Create tests in `tests/test_analyzers/`:

```python
# tests/test_analyzers/test_newplatform.py

import pytest
import requests
from bs4 import BeautifulSoup
from website_security_scanner.analyzers.newplatform import NewPlatformAnalyzer


class TestNewPlatformAnalyzer:
    """Test suite for NewPlatform analyzer."""
    
    @pytest.fixture
    def analyzer(self):
        """Create analyzer instance for testing."""
        session = requests.Session()
        return NewPlatformAnalyzer(session)
    
    @pytest.fixture
    def sample_response(self):
        """Create mock response for testing."""
        response = requests.Response()
        response.status_code = 200
        response._content = b'<html>...</html>'
        return response
    
    def test_api_endpoint_detection(self, analyzer):
        """Test detection of exposed API endpoints."""
        js_content = '''
        var endpoint = "api.newplatform.com/v1/users";
        fetch(endpoint);
        '''
        
        analyzer._check_api_endpoints(js_content)
        
        assert len(analyzer.api_endpoints) > 0
        assert "users" in analyzer.api_endpoints[0]
    
    def test_vulnerability_reporting(self, analyzer, sample_response):
        """Test that vulnerabilities are properly reported."""
        soup = BeautifulSoup(sample_response.content, 'html.parser')
        
        results = analyzer.analyze("https://test.newplatform.com", sample_response, soup)
        
        assert "vulnerabilities" in results
        assert isinstance(results["vulnerabilities"], list)
    
    def test_http_context_recording(self, analyzer, sample_response):
        """Test that HTTP context is recorded."""
        soup = BeautifulSoup(sample_response.content, 'html.parser')
        
        analyzer.analyze("https://test.newplatform.com", sample_response, soup)
        
        # Verify HTTP context was recorded
        assert analyzer._last_response is not None
```

### Integration Tests

```python
# tests/integration/test_full_scan.py

def test_newplatform_full_scan():
    """Test complete scan of NewPlatform application."""
    from website_security_scanner.main import LowCodeSecurityScanner
    
    scanner = LowCodeSecurityScanner()
    results = scanner.scan_target("https://test.newplatform.com")
    
    assert results["platform_type"] == "newplatform"
    assert "vulnerabilities" in results
    assert len(results["vulnerabilities"]) >= 0
```

---

## Pull Request Process

### Before Submitting

1. **Code Quality**:
   ```bash
   # Format code
   black src/
   
   # Check style
   flake8 src/
   
   # Type checking (if mypy is installed)
   mypy src/
   ```

2. **Run Tests**:
   ```bash
   pytest tests/ -v
   ```

3. **Update Documentation**:
   - Add/update docstrings
   - Update README.md if adding features
   - Update ARCHITECTURE.md for structural changes

### PR Template

```markdown
## Description

Brief description of changes made.

## Type of Change

- [ ] Bug fix
- [ ] New feature (new analyzer, security check, etc.)
- [ ] Enhancement (improvement to existing functionality)
- [ ] Documentation update

## Testing

- [ ] Unit tests added/updated
- [ ] Integration tests added/updated
- [ ] Manual testing performed

## Checklist

- [ ] Code follows project style guidelines
- [ ] All methods have proper type hints
- [ ] All public APIs are documented
- [ ] Tests pass locally
- [ ] No breaking changes (or clearly documented)
- [ ] Documentation updated

## Related Issues

Closes #XXX
```

### Review Process

1. Submit PR with clear description
2. Ensure CI checks pass
3. Address review comments
4. Maintain professional, constructive communication

---

## Common Patterns

### Error Handling

```python
from ..exceptions import AnalysisError, ScannerNetworkError

def risky_operation(self, url: str):
    """Perform operation that might fail."""
    try:
        response = self.session.get(url, timeout=30)
        response.raise_for_status()
    except requests.Timeout:
        raise ScannerNetworkError(
            "Request timed out",
            url=url,
            timeout_seconds=30
        )
    except requests.RequestException as e:
        raise AnalysisError(
            f"Analysis failed: {e}",
            analyzer=self.__class__.__name__,
            analysis_type="http_request"
        )
```

### Logging

```python
class MyAnalyzer(BaseAnalyzer):
    def analyze(self, url, response, soup):
        self.logger.info(f"Starting analysis for {url}")
        
        try:
            # Analysis logic
            self.logger.debug("Step 1 completed")
            
        except Exception as e:
            self.logger.error(f"Analysis failed", exc_info=True)
            raise
```

### Configuration Usage

```python
from ..config import ScannerConfig

config = ScannerConfig.from_env()

# Validate
errors = config.validate()
if errors:
    self.logger.error(f"Invalid configuration: {errors}")
    
# Use settings
timeout = config.request_timeout
max_retries = config.max_retries
```

---

## Questions?

For questions or clarifications:
- Review ARCHITECTURE.md for design patterns
- Check existing analyzers for examples
- Open an issue for discussion

---

**Thank you for contributing to make this scanner even more professional and comprehensive!**

