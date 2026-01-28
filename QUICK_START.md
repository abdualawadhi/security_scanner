# Quick Start Guide - Enhanced Security Scanner

## What's New?

The OutSystems analyzer has been significantly enhanced to detect **17 different vulnerability types**, matching industry-standard tools like Burp Suite Professional.

## Quick Example

```python
from src.website_security_scanner.main import LowCodeSecurityScanner

# Initialize scanner
scanner = LowCodeSecurityScanner()

# Scan an OutSystems application
results = scanner.scan_url("https://your-app.outsystems.app")

# Check results
print(f"Vulnerabilities found: {len(results['vulnerabilities'])}")
for vuln in results['vulnerabilities']:
    print(f"- [{vuln['severity']}] {vuln['type']}")
```

## What Gets Detected?

### 🔴 Critical Issues
- **Hardcoded Secrets** - API keys, passwords, tokens in JavaScript

### 🟠 High Priority
- **XSS Vulnerabilities** - Reflected input without encoding
- **Weak CSP** - Allows unsafe-inline or unsafe-eval
- **Missing Access Control** - No role-based restrictions

### 🟡 Medium Priority
- **Session Tokens in URLs** - Tokens exposed in query parameters
- **Insecure Cookies** - Missing Secure flag
- **Clickjacking** - No frame protection
- **CSP Issues** - Missing form-action, unsafe styles

### 🔵 Low Priority
- **Cookie Flags** - Missing HttpOnly or SameSite
- **Information Leakage** - Private IPs, detailed errors
- **Caching Issues** - Sensitive data cached
- **Path Issues** - Relative stylesheet imports

### ⚪ Informational
- **Email Disclosure** - Email addresses in content
- **Base64 Data** - Encoded data in URLs

## Command Line Usage

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
