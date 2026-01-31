# Comprehensive Low-Code Platform Security Scanner

A dedicated, comprehensive security scanner specifically designed for detecting vulnerabilities in popular low-code/no-code platforms. This scanner provides specialized detection capabilities for the most common low-code platforms, including platform-specific vulnerabilities that generic scanners often miss.

## 🎯 Features

### Supported Platforms
- **Airtable** - Cloud database and collaboration platform
- **Bubble.io** - Visual programming platform for web applications
- **OutSystems** - Enterprise low-code application development platform
- **MERN Stack** - MongoDB, Express.js, React, Node.js applications
- **Glide** - Mobile app development from spreadsheets
- **Adalo** - No-code mobile and web app builder
- **Thunkable** - Drag-and-drop mobile app builder
- **AppSheet** - No-code app development from data sources
- **Generic Low-Code** - Custom or unknown low-code platforms

### Comprehensive Vulnerability Detection

#### Platform-Specific Vulnerabilities
- **API Exposure**: Workflow APIs, REST endpoints, GraphQL interfaces
- **Authentication Issues**: Session management, token exposure, privilege escalation
- **Data Leakage**: Database schema exposure, sensitive data in URLs, privacy rule bypass
- **Configuration Issues**: Misconfigured permissions, exposed admin interfaces
- **Injection Vulnerabilities**: Platform-specific injection attacks

#### Standard Web Vulnerabilities
- Cross-Site Scripting (XSS)
- SQL Injection and NoSQL Injection
- Cross-Site Request Forgery (CSRF)
- Security Misconfigurations
- Missing Security Headers
- SSL/TLS Issues

#### Advanced Security Checks
- Host Header Injection
- HTTP Request Smuggling
- Server-Side Request Forgery (SSRF)
- Directory Traversal
- File Upload Vulnerabilities
- Clickjacking Protection

## 🚀 Quick Start

### Prerequisites
```bash
pip install -r requirements.txt
```

### Basic Usage
```bash
# Scan a low-code application
python comprehensive_low_code_scanner.py https://myapp.bubbleapps.io

# Scan with platform hint
python comprehensive_low_code_scanner.py https://myapp.com --platform bubble

# Platform detection only
python comprehensive_low_code_scanner.py https://myapp.com --detect-only

# Export results in different formats
python comprehensive_low_code_scanner.py https://myapp.com --output html --file report.html
```

### Command Line Options

```
usage: comprehensive_low_code_scanner.py [-h] [--platform PLATFORM] [--output {json,html,text}]
                                        [--file FILE] [--detect-only] [--verbose]
                                        [--list-platforms] url

Comprehensive Low-Code Platform Security Scanner

positional arguments:
  url                   Target URL to scan

optional arguments:
  -h, --help            show this help message and exit
  --platform PLATFORM, -p PLATFORM
                        Platform hint (bubble, outsystems, airtable, mern, etc.)
  --output {json,html,text}, -o {json,html,text}
                        Output format (default: json)
  --file FILE, -f FILE  Output file path (default: auto-generated)
  --detect-only         Only detect platform, do not perform full scan
  --verbose, -v         Verbose output
  --list-platforms      List all supported platforms and exit
```

## 📊 Output Formats

### JSON Output
Comprehensive structured data including:
- Platform detection results
- Vulnerability findings with severity levels
- Security assessment scores
- OWASP compliance status
- Detailed recommendations

### HTML Output
Interactive web report with:
- Executive summary dashboard
- Vulnerability breakdown charts
- Platform-specific recommendations
- Color-coded severity indicators

### Text Output
Plain text report suitable for:
- Command line review
- Integration with other tools
- Quick security assessments

## 🔍 Platform Detection

The scanner automatically detects the platform type by analyzing:

1. **Domain Analysis**: Recognizes platform-specific domains
2. **Content Analysis**: Scans page content for platform indicators
3. **Header Analysis**: Checks response headers for platform clues
4. **Code Patterns**: Identifies platform-specific code patterns

### Detection Confidence
- **High Confidence (0.9+)**: Clear platform indicators found
- **Medium Confidence (0.6-0.8)**: Some indicators present
- **Low Confidence (<0.6)**: Limited or ambiguous indicators

## 🛡️ Security Assessment

### Security Scoring
- **A Grade (90-100)**: Excellent security posture
- **B Grade (80-89)**: Good security with minor issues
- **C Grade (70-79)**: Adequate security needing improvement
- **D Grade (60-69)**: Poor security requiring attention
- **F Grade (<60)**: Critical security issues present

### OWASP Compliance
Checks compliance against OWASP Top 10 categories:
- A01:2021 - Broken Access Control
- A02:2021 - Cryptographic Failures
- A03:2021 - Injection
- A04:2021 - Insecure Design
- A05:2021 - Security Misconfiguration
- A06:2021 - Vulnerable Components
- A07:2021 - Identification & Authentication
- A08:2021 - Software Integrity
- A09:2021 - Security Logging
- A10:2021 - SSRF

## 💡 Platform-Specific Recommendations

### Airtable Applications
- Secure API keys and base IDs
- Review sharing permissions
- Monitor for unauthorized data exports
- Implement proper authentication

### Bubble.io Applications
- Review privacy rules and data access
- Secure API workflows and external calls
- Implement proper user authentication flows
- Monitor for exposed sensitive data

### OutSystems Applications
- Review role-based access controls
- Secure session management and tokens
- Monitor for host header injection
- Implement proper input validation

### MERN Stack Applications
- Secure MongoDB connections
- Implement proper CORS policies
- Review JWT token security
- Monitor for NoSQL injection

## 🔧 Advanced Usage

### Custom Platform Support
```python
from website_security_scanner.analyzers.low_code_scanner import LowCodePlatformScanner

scanner = LowCodePlatformScanner()

# Add custom platform
scanner.add_custom_platform("myplatform", {
    "name": "My Custom Platform",
    "domains": ["myplatform.com", "app.myplatform.com"],
    "analyzer": "generic",
    "description": "Custom low-code platform"
})

# Scan with custom platform
results = scanner.comprehensive_scan("https://app.myplatform.com")
```

### Integration with Existing Code
```python
from website_security_scanner.analyzers.low_code_scanner import scan_low_code_platform

# Quick scan function
results = scan_low_code_platform("https://myapp.com", platform_hint="bubble")

# Platform detection only
platform_info = detect_platform("https://myapp.com")
```

## 📈 Performance & Scalability

- **Concurrent Scanning**: Multiple platform analyzers can run in parallel
- **Efficient Detection**: Smart platform detection minimizes unnecessary scans
- **Memory Optimized**: Streaming analysis for large applications
- **Timeout Protection**: Configurable timeouts prevent hanging scans

## 🔒 Security Considerations

- **Safe Scanning**: Read-only operations, no exploitation attempts
- **No Data Modification**: Scanner only analyzes, never modifies data
- **Privacy Respect**: No sensitive data collection or storage
- **Ethical Use**: Designed for authorized security testing only

## 🤝 Contributing

### Adding New Platforms
1. Create platform-specific analyzer in `src/website_security_scanner/analyzers/`
2. Update `SUPPORTED_PLATFORMS` in `low_code_scanner.py`
3. Add platform info to factory.py
4. Test with sample applications

### Vulnerability Research
- Focus on platform-specific attack vectors
- Document proof-of-concept findings
- Contribute detection methods for new vulnerabilities

## 📚 Examples

### Example 1: Bubble.io Application Scan
```bash
python comprehensive_low_code_scanner.py https://mybubbleapp.bubbleapps.io --output html
```

### Example 2: OutSystems Application Scan
```bash
python comprehensive_low_code_scanner.py https://myapp.outsystems.app --platform outsystems --verbose
```

### Example 3: Unknown Platform Detection
```bash
python comprehensive_low_code_scanner.py https://unknownapp.com --detect-only
```

## 🐛 Troubleshooting

### Common Issues
- **Platform Not Detected**: Try using `--platform` hint
- **Scan Timeouts**: Large applications may need longer timeouts
- **False Positives**: Review results manually for platform context
- **Network Issues**: Ensure stable internet connection

### Debug Mode
```bash
python comprehensive_low_code_scanner.py https://myapp.com --verbose
```

## 📄 License

This project is part of a Bachelor Thesis on Low-Code Platform Security Analysis.

## 🙏 Acknowledgments

- Built upon the foundation of the existing security scanner
- Platform-specific vulnerability research
- OWASP community guidelines
- Low-code platform documentation and security research

---

**Note**: This scanner is designed for authorized security testing. Always obtain permission before scanning applications you do not own.