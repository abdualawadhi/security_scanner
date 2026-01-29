# Quick Start Guide - Low-Code Security Scanner

## Overview

The Low-Code Platform Security Scanner is a comprehensive security testing tool designed for low-code platforms including Bubble.io, OutSystems, Airtable, and generic web applications. This guide will get you up and running quickly with both command-line and web interface usage.

## What's New?

- **Professional Web Frontend**: Modern dashboard with real-time scanning
- **Vulnerability Verification**: Active testing to confirm exploitability
- **Enhanced Detection**: 17+ vulnerability types matching Burp Suite Professional
- **Multiple Platforms**: Support for Bubble, OutSystems, Airtable, and generic apps

## Installation

### Prerequisites
- Python 3.8+
- pip package manager

### Setup
```bash
# Clone or download the project
git clone <repository-url>
cd website_security_scanner

# Install dependencies
pip install -r requirements.txt

# Verify installation
python -m website_security_scanner.cli.cli --help
```

## Quick Examples

### Python API
```python
from src.website_security_scanner.main import LowCodeSecurityScanner

# Initialize scanner
scanner = LowCodeSecurityScanner()

# Scan any low-code application
results = scanner.scan_url("https://your-app.bubbleapps.io")

# Check results
print(f"Vulnerabilities found: {len(results['vulnerabilities'])}")
for vuln in results['vulnerabilities']:
    print(f"- [{vuln['severity']}] {vuln['type']}")
```

## What Gets Detected?

### 🔴 Critical Issues
- **Hardcoded Secrets** - API keys, passwords, tokens in JavaScript
- **Cloud Resource Exposure** - AWS keys, S3 buckets, CloudFront domains

### 🟠 High Priority
- **XSS Vulnerabilities** - Reflected input without encoding
- **Weak CSP** - Allows unsafe-inline or unsafe-eval
- **Missing Access Control** - No role-based restrictions
- **Secret Header Reflection** - Sensitive headers echoed back

### 🟡 Medium Priority
- **Session Tokens in URLs** - Tokens exposed in query parameters
- **Insecure Cookies** - Missing Secure flag
- **Clickjacking** - No frame protection
- **CSP Issues** - Missing form-action, unsafe styles
- **Request URL Override** - Header-based routing bypass
- **DOM Data Manipulation** - Potential DOM-based XSS

### 🔵 Low Priority
- **Cookie Flags** - Missing HttpOnly or SameSite
- **Information Leakage** - Private IPs, detailed errors
- **Caching Issues** - Sensitive data cached
- **Path Issues** - Relative stylesheet imports
- **Cookie Domain Scoping** - Overly broad cookie domains

### ⚪ Informational
- **Email Disclosure** - Email addresses in content
- **Base64 Data** - Encoded data in URLs
- **HTTP/2 Support** - Protocol detection

## Usage Options

### Option 1: Web Interface (Recommended)

#### Start the Web Server
```bash
python src/website_security_scanner/web/run_server.py
```

Access at: **http://localhost:5000**

#### Quick Web Scan
1. Open dashboard for statistics overview
2. Click "New Scan"
3. Enter target URL (e.g., `https://your-app.bubbleapps.io`)
4. Enable options:
   - ✅ **Verify Vulnerabilities** (recommended for confirmation)
   - ✅ **Deep Scan** (comprehensive analysis)
5. Click "Start Scan"
6. Monitor real-time progress
7. Download professional HTML report when complete

#### Web Features
- **Real-time Dashboard**: Live statistics and scan monitoring
- **Batch Scanning**: Process multiple URLs simultaneously
- **History Management**: Filterable scan history with search
- **Professional Reports**: Burp Suite-style HTML reports
- **WebSocket Updates**: Live progress without page refresh

### Option 2: Command Line Interface

#### Single URL Scan
```bash
python -m website_security_scanner.cli.cli --url https://your-app.bubbleapps.io
```

#### Enhanced Scan with Verification
```bash
python -m website_security_scanner.cli.cli \
  --url https://your-app.bubbleapps.io \
  --enhanced \
  --verify-vulnerabilities
```

#### Batch Scanning
```bash
# Create URLs file (one per line)
echo "https://app1.bubbleapps.io" > urls.txt
echo "https://app2.outsystems.app" >> urls.txt
echo "https://airtable.com/app3" >> urls.txt

# Batch scan
python -m website_security_scanner.cli.cli --batch urls.txt --enhanced
```

#### Configuration File Usage
```bash
# Create config.yaml
cat > config.yaml << EOF
scanner:
  timeout: 10
  delay_between_requests: 2
targets:
  bubble:
    - "https://example.bubbleapps.io/app"
  outsystems:
    - "https://example.outsystems.app/app"
reports:
  formats: ["html", "json"]
EOF

# Scan with config
python -m website_security_scanner.cli.cli --config config.yaml
```

## Understanding Results

### Security Score
- **90-100**: Excellent security posture
- **70-89**: Good security with minor improvements
- **50-69**: Moderate security concerns
- **20-49**: Poor security with significant issues
- **0-19**: Critical security requiring immediate action

### Vulnerability Confidence Levels
- **Certain**: High confidence, exploitation confirmed
- **Firm**: Strong indicators present
- **Tentative**: Detected but not verified

### Sample Output
```json
{
  "url": "https://example.bubbleapps.io",
  "platform_type": "bubble",
  "security_score": 73,
  "vulnerabilities": [
    {
      "type": "API Key Exposure",
      "severity": "Critical",
      "confidence": "Certain",
      "description": "Airtable API key found in JavaScript",
      "evidence": "keyABC123...",
      "recommendation": "Move API keys to server-side"
    }
  ]
}
```

## Platform-Specific Examples

### Bubble.io Applications
```bash
# Scan Bubble app
python -m website_security_scanner.cli.cli \
  --url https://amqmalawadhi-85850.bubbleapps.io/version-test/ \
  --enhanced
```

### OutSystems Applications
```bash
# Scan OutSystems app
python -m website_security_scanner.cli.cli \
  --url https://personal-7hwwkk2j-dev.outsystems.app/UST/ \
  --verify-vulnerabilities
```

### Airtable Applications
```bash
# Scan Airtable base
python -m website_security_scanner.cli.cli \
  --url https://airtable.com/app5oLkwSi8gaXUod/ \
  --enhanced
```

## Advanced Usage

### CI/CD Integration
```yaml
# .github/workflows/security-scan.yml
- name: Security Scan
  run: |
    python -m website_security_scanner.cli.cli \
      --url "${{ env.APP_URL }}" \
      --format json \
      --output security-report.json
```

### Custom Reporting
```bash
# Generate HTML report
python -m website_security_scanner.cli.cli \
  --url https://target.com \
  --format html \
  --output report.html

# Generate JSON for processing
python -m website_security_scanner.cli.cli \
  --url https://target.com \
  --format json \
  --output report.json
```

## Troubleshooting

### Common Issues

**Web Interface Won't Start**
```bash
# Check port availability
netstat -an | grep :5000

# Use different port
python src/website_security_scanner/web/run_server.py --port 8080
```

**Scan Times Out**
```bash
# Increase timeout
python -m website_security_scanner.cli.cli --url https://target.com --timeout 30
```

**SSL Certificate Errors**
```bash
# Skip SSL verification (development only)
python -m website_security_scanner.cli.cli --url https://target.com --no-ssl-verify
```

**Too Many False Positives**
- The scanner includes false positive filters
- Review results manually for your specific application
- Adjust patterns in analyzer code if needed

### Debug Mode
```bash
# Web server debug
python src/website_security_scanner/web/run_server.py --debug

# CLI verbose output
python -m website_security_scanner.cli.cli --url https://target.com --verbose
```

## Next Steps

1. **Read the Full Documentation**
   - [README.md](../../README.md) - Complete feature overview
   - [WEB_FRONTEND_GUIDE.md](WEB_FRONTEND_GUIDE.md) - Web interface details
   - [VULNERABILITY_VERIFICATION_GUIDE.md](VULNERABILITY_VERIFICATION_GUIDE.md) - Verification details

2. **Explore Advanced Features**
   - Custom analyzers for new platforms
   - Integration with your security workflow
   - Automated scanning in CI/CD

3. **Contribute Back**
   - Report bugs or false positives
   - Suggest new vulnerability checks
   - Share your security findings

## Support

- **Documentation**: Check `docs/` directory for detailed guides
- **Issues**: Submit via project repository
- **Academic Use**: This tool was developed for a Bachelor thesis on low-code platform security

---

**Happy Scanning! 🔒**

All commands are run via the CLI script defined in `src/website_security_scanner/cli/cli.py`.

```bash
# Scan a single URL
python src/website_security_scanner/cli/cli.py --url https://your-app.outsystems.app

# Scan a single URL and generate an enhanced professional HTML report
python src/website_security_scanner/cli/cli.py \
  --url https://your-app.outsystems.app \
  --enhanced

# Batch scan from file (one URL per line)
python src/website_security_scanner/cli/cli.py \
  --batch urls.txt \
  --format json \
  --output reports/batch_scan.json

# Scan using a YAML configuration file
python src/website_security_scanner/cli/cli.py \
  --config config/config.yaml \
  --format json \
  --output reports/config_scan.json
```

## Understanding Results

### Vulnerability Structure
Each finding includes:
- **Type**: Name of the vulnerability
- **Severity**: Critical, High, Medium, Low, or Information
- **Description**: What the issue is
- **Evidence**: Proof/example of the vulnerability
- **Recommendation**: How to fix it

### Example Output
```json
{
    "type": "Session Token in URL",
    "severity": "Medium",
    "description": "Session token found in URL query string",
    "evidence": "URL contains session-like parameter: https://...",
    "recommendation": "Transmit session tokens in HTTP cookies..."
}
```

## Comparison with Burp Suite

| Feature | Burp Suite | Our Scanner |
|---------|-----------|-------------|
| Session token detection | ✓ | ✓ |
| Secret scanning | ✓ | ✓ |
| Cookie security | ✓ | ✓ |
| CSP validation | ✓ | ✓ |
| Clickjacking | ✓ | ✓ |
| XSS detection | ✓ | ✓ |
| Information disclosure | ✓ | ✓ |
| **Cost** | $$$ | Free |
| **Platform-specific** | Generic | OutSystems-optimized |

## Report Formats

### JSON
```bash
--format json
```
Machine-readable, perfect for CI/CD integration

### HTML
```bash
--format html --enhanced-report
```
Burp Suite-style professional report with styling

### YAML
```bash
--format yaml
```
Human-readable structured format

### Text
```bash
--format txt
```
Simple text output for quick review

## Integration Examples

### CI/CD Pipeline
```yaml
# .github/workflows/security-scan.yml
- name: Security Scan
  run: |
    python src/website_security_scanner/cli/cli.py \
      --url "${{ env.APP_URL }}" \
      --format json \
      --output security-report.json
    
    # Fail if critical vulnerabilities found
    python - << 'PYCODE'
    import json
    with open('security-report.json', encoding='utf-8') as f:
        data = json.load(f)
    vulns = data.get('vulnerabilities', [])
    critical = [v for v in vulns if v.get('severity') == 'Critical']
    if critical:
        print(f"Found {len(critical)} critical vulnerabilities!")
        raise SystemExit(1)
    PYCODE
```

### Python Script
```python
from website_security_scanner.main import LowCodeSecurityScanner


def check_security(url: str) -> bool:
    scanner = LowCodeSecurityScanner()
    results = scanner.scan_target(url)

    vulns = results.get("vulnerabilities", [])
    critical = [v for v in vulns if v.get("severity") == "Critical"]

    if critical:
        print(f"Found {len(critical)} critical issues!")
        for vuln in critical:
            print(f"  - {vuln.get('type') or vuln.get('title')}: {vuln.get('description', '')}")
        return False

    print("No critical issues found")
    return True


if __name__ == "__main__":
    if not check_security("https://your-app.outsystems.app"):
        raise SystemExit(1)
```

## Common Use Cases

### 1. Pre-deployment Security Check
```bash
# Before deploying to production
python3 -m src.website_security_scanner.cli.cli scan \
    https://staging.your-app.outsystems.app \
    --format html --enhanced-report
```

### 2. Compliance Audit
```bash
# Generate comprehensive report
python3 -m src.website_security_scanner.cli.cli scan \
    https://your-app.outsystems.app \
    --format html --enhanced-report \
    --output audit-report.html
```

### 3. Security Monitoring
```bash
# Regular scans with comparison
python3 -m src.website_security_scanner.cli.cli batch urls.txt \
    --output-dir reports/$(date +%Y-%m-%d)/
```

## Performance Tips

1. **Use batch scanning** for multiple URLs
2. **Enable caching** to speed up repeated scans
3. **Filter severity** to focus on critical issues
4. **Parallel execution** for large batches

## Troubleshooting

### Issue: No vulnerabilities found
**Solution**: Ensure the URL is accessible and responds with HTML content

### Issue: Too many false positives
**Solution**: The scanner includes false positive filters. If needed, adjust patterns in `analyzers.py`

### Issue: Timeout errors
**Solution**: Increase timeout in scanner configuration

### Issue: SSL errors
**Solution**: Use `--verify-ssl=false` for development environments (not recommended for production)

## Next Steps

1. Read [OUTSYSTEMS_ENHANCEMENTS.md](OUTSYSTEMS_ENHANCEMENTS.md) for detailed documentation
2. Review [VULNERABILITY_DETECTION_MAP.md](VULNERABILITY_DETECTION_MAP.md) for detection logic
3. Check [CHANGES_SUMMARY.md](CHANGES_SUMMARY.md) for implementation details
4. Explore the Burp Suite report in `Bursuite Reports/Outsystems.txt`

## Support

For issues or questions:
1. Check the documentation files
2. Review test cases in the project
3. Examine the source code in `src/website_security_scanner/`

## Best Practices

✅ **Do:**
- Run scans regularly
- Review all findings
- Prioritize by severity
- Track fixes over time
- Use in CI/CD pipeline

❌ **Don't:**
- Ignore low-severity findings
- Scan production without permission
- Rely solely on automated scanning
- Skip manual security review
- Share sensitive scan reports

---

**Happy Scanning! 🔒**
