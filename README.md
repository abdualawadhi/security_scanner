# Low-Code Platform Security Scanner

A comprehensive security analysis tool specifically designed for low-code platforms, developed as part of a Bachelor thesis on "Low-Code Platforms for E-commerce: Comparative Security Analysis".

## Overview

This tool performs automated security assessments of low-code applications built on popular platforms including:

- **Bubble.io** - Visual web application builder
- **OutSystems** - Enterprise low-code platform
- **Airtable** - Database and workflow platform
- **Generic Web Applications** - Any other web-based applications

## Features

### 🌐 Professional Web Frontend (NEW!)
- **Modern Web Interface**: Real-time dashboard with live scan monitoring
- **Interactive Scanning**: Single and batch URL scanning with progress tracking
- **WebSocket Integration**: Live updates via Socket.IO
- **Comprehensive History**: Filterable scan history with detailed results
- **One-Click Reports**: Professional HTML reports with download capability

### ✅ Vulnerability Verification (NEW!)
- **Active Testing**: Confirms detected vulnerabilities with safe exploitation attempts
- **8 Vulnerability Types**: XSS, SQLi, Command Injection, Path Traversal, SSRF, Open Redirect, XXE, CSRF
- **Confidence Levels**: Upgrades findings from Tentative to Firm/Certain
- **Safe Payloads**: Non-destructive testing with ethical boundaries
- **Detailed Evidence**: Payload information and verification methods in reports

### 🔍 Comprehensive Security Analysis
- **Platform-Specific Vulnerability Detection**: Tailored checks for each low-code platform
- **Common Web Vulnerabilities**: XSS, SQL Injection, CSRF, and more
- **Security Headers Analysis**: Complete HTTP security header evaluation
- **SSL/TLS Configuration Testing**: Certificate and encryption analysis
- **API Endpoint Discovery**: Identification of exposed APIs and workflows

### 📊 Advanced Reporting
- **Professional HTML Reports**: Burp Suite-style formatting with severity matrices
- **Multiple Output Formats**: JSON, YAML, HTML, and plain text reports
- **Comparative Analysis**: Cross-platform security comparison
- **Executive Summaries**: High-level security assessment overviews
- **Verification Results**: Includes active testing outcomes with evidence

### 🎯 Platform-Specific Checks

#### Bubble.io Applications
- Workflow API exposure detection
- Privacy rules bypass analysis
- Database schema leak identification
- Authentication token exposure
- Client-side data exposure assessment

#### OutSystems Applications
- REST API security analysis
- Screen action privilege escalation
- Entity exposure detection
- Session management evaluation
- Role-based access control assessment

#### Airtable Applications
- Base ID and API key exposure
- Table structure analysis
- Permission model evaluation
- Data access control assessment

## Installation

### Prerequisites
- Python 3.7 or higher
- pip (Python package manager)

### Setup

1. **Clone or download the project**:
```bash
git clone <repository-url>
cd website_security_scanner
```

2. **Install dependencies**:
```bash
pip install -r requirements.txt
```

3. **Verify installation**:
```bash
python main.py --help
```

## Quick Start

### Option 1: Web Interface (Recommended)

1. **Start the web server**:
```bash
python src/website_security_scanner/web/run_server.py
```

2. **Open in browser**:
```
http://localhost:5000
```

3. **Start scanning**: Use the intuitive web interface to configure and run scans with real-time progress monitoring!

See [WEB_FRONTEND_GUIDE.md](WEB_FRONTEND_GUIDE.md) for detailed documentation.

### Option 2: Command Line Interface

1. **Scan a single URL**:
```bash
python -m website_security_scanner.cli.cli --url https://your-app.bubbleapps.io/app-name
```

2. **Scan with vulnerability verification**:
```bash
python -m website_security_scanner.cli.cli \
  --url https://your-app.bubbleapps.io \
  --enhanced \
  --verify-vulnerabilities
```

3. **Scan multiple URLs from a file**:
```bash
python -m website_security_scanner.cli.cli --batch urls.txt --output results.json
```

4. **Generate comparative analysis**:
```bash
python -m website_security_scanner.cli.cli --batch urls.txt --comparative --output comparative_report.json
```

### Example URLs File (urls.txt)
```
https://amqmalawadhi-85850.bubbleapps.io/version-test/
https://personal-7hwwkk2j-dev.outsystems.app/UST/
https://airtable.com/app5oLkwSi8gaXUod/
```

## Configuration

### Using Configuration Files

Create a `config.yaml` file to customize scanner behavior:

```yaml
# Scanner Settings
scanner:
  timeout: 10
  delay_between_requests: 2
  verify_ssl: false

# Target URLs
targets:
  bubble:
    - "https://example.bubbleapps.io/app"
  outsystems:
    - "https://example.outsystems.app/app"
  airtable:
    - "https://airtable.com/appXXXXXXXXXXXXXX"

# Report Settings
reports:
  formats: ["json", "html", "txt"]
  output_directory: "reports"
  include_comparative_analysis: true
```

Run with configuration:
```bash
python cli.py --config config.yaml
```

## Command Line Options

### Input Options
```bash
# Scan single URL
python cli.py --url <URL>

# Batch scan from file
python cli.py --batch <file_path>

# Use configuration file
python cli.py --config <config_file>
```

### Output Options
```bash
# Specify output file and format
python cli.py --url <URL> --output report.json --format json

# Available formats: json, yaml, txt, html
python cli.py --url <URL> --format html --output report.html
```

### Analysis Options
```bash
# Generate comparative analysis
python cli.py --batch urls.txt --comparative

# Verbose output
python cli.py --url <URL> --verbose

# Disable colored output
python cli.py --url <URL> --no-color
```

### Scanner Options
```bash
# Custom timeout and delay
python cli.py --url <URL> --timeout 15 --delay 3

# Custom User-Agent
python cli.py --url <URL> --user-agent "Custom Scanner 1.0"
```

## Understanding the Results

### Security Score
- **100-80**: Excellent security posture
- **79-60**: Good security with minor improvements needed
- **59-40**: Moderate security concerns requiring attention
- **39-20**: Poor security with significant vulnerabilities
- **19-0**: Critical security issues requiring immediate action

### Vulnerability Severity Levels
- **Critical**: Immediate data breach risk (e.g., API keys in client code)
- **High**: Significant security risk (e.g., authentication bypass)
- **Medium**: Moderate security concern (e.g., missing CSRF protection)
- **Low**: Minor security improvement (e.g., missing security headers)

### Sample Output

```json
{
  "url": "https://example.bubbleapps.io/app",
  "platform_type": "bubble",
  "security_headers": {
    "security_score": "3/8",
    "X-Frame-Options": "Missing",
    "Content-Security-Policy": "Missing"
  },
  "vulnerabilities": [
    {
      "type": "Bubble Workflow Exposure",
      "severity": "High",
      "description": "Workflow endpoints detected in client-side code",
      "recommendation": "Review privacy rules for exposed workflow APIs"
    }
  ],
  "executive_summary": {
    "security_score": 73,
    "risk_level": "Medium",
    "total_vulnerabilities": 5
  }
}
```

## Academic Research Context

This tool was developed as part of a Bachelor thesis research project focusing on:

### Research Objectives
- Identify common security vulnerabilities in low-code platforms
- Compare security postures across different platforms
- Analyze platform-specific security risks
- Provide actionable security recommendations for low-code development

### Methodology
- **Static Analysis**: Client-side code examination for security patterns
- **Dynamic Testing**: Runtime security behavior assessment
- **Platform Comparison**: Cross-platform security posture evaluation
- **Risk Assessment**: Vulnerability impact and likelihood analysis

### Use in Academic Work
This scanner is designed to support:
- **Comparative Security Analysis**: Generate data for platform security comparisons
- **Vulnerability Research**: Identify and categorize security issues
- **Risk Assessment**: Evaluate security implications of low-code adoption
- **Best Practices Development**: Inform secure low-code development guidelines

## Report Generation

### Individual Reports
```bash
# Generate detailed JSON report
python cli.py --url <URL> --output detailed_report.json

# Generate human-readable text report
python cli.py --url <URL> --format txt --output readable_report.txt

# Generate HTML report with visualizations
python cli.py --url <URL> --format html --output visual_report.html
```

### Comparative Analysis Reports
```bash
# Compare multiple platforms
python cli.py --batch urls.txt --comparative --output comparison.json

# Generate executive summary
python cli.py --batch urls.txt --comparative --format txt --output executive_summary.txt
```

## Customization and Extension

### Adding New Platform Support
1. Create a new analyzer class inheriting from `BaseAnalyzer`
2. Implement platform-specific vulnerability detection logic
3. Add platform identification patterns
4. Register the new analyzer in the factory function

### Custom Vulnerability Checks
1. Extend existing analyzer classes
2. Add new vulnerability detection methods
3. Update severity classifications
4. Include remediation recommendations

## Limitations and Considerations

### Ethical Use
- Only scan applications you own or have explicit permission to test
- Respect rate limits and terms of service
- Use responsibly for educational and research purposes

### Technical Limitations
- Client-side analysis only (no server-side code access)
- Network-accessible applications only
- Limited by platform-specific obfuscation techniques
- May produce false positives requiring manual verification

### Platform-Specific Notes
- **Bubble.io**: Analysis focuses on client-side JavaScript patterns
- **OutSystems**: Limited to publicly accessible endpoints and client code
- **Airtable**: Primarily analyzes embedded applications and shared bases

## New Features Documentation

### 🌐 Web Frontend
For comprehensive web interface documentation, see [WEB_FRONTEND_GUIDE.md](WEB_FRONTEND_GUIDE.md):
- Dashboard and statistics
- Real-time scan monitoring
- API endpoints reference
- WebSocket events
- Deployment guidelines

### ✅ Vulnerability Verification
For detailed verification documentation, see [VULNERABILITY_VERIFICATION_GUIDE.md](VULNERABILITY_VERIFICATION_GUIDE.md):
- Supported vulnerability types
- Verification methods
- Safety considerations
- Usage examples
- Extending verification

### 📋 Enhancement Summary
For a complete overview of all enhancements, see [ENHANCEMENT_SUMMARY.md](ENHANCEMENT_SUMMARY.md):
- Architecture improvements
- Performance considerations
- Migration notes
- Future roadmap

## Troubleshooting

### Common Issues

1. **SSL Certificate Errors**:
```bash
python -m website_security_scanner.cli.cli --url <URL> --no-ssl-verify
```

2. **Timeout Issues**:
```bash
python -m website_security_scanner.cli.cli --url <URL> --timeout 30
```

3. **Rate Limiting**:
```bash
python -m website_security_scanner.cli.cli --batch urls.txt --delay 5
```

4. **Permission Errors**:
- Ensure write permissions for output directory
- Check file path validity
- Verify URL accessibility

5. **Web Frontend Issues**:
- Check port 5000 is not in use
- Ensure all dependencies installed (`pip install -r requirements.txt`)
- Verify WebSocket connection in browser console

### Debug Mode
```bash
python -m website_security_scanner.cli.cli --url <URL> --verbose
```

### Web Server Debug
```bash
python src/website_security_scanner/web/run_server.py --debug
```

## Contributing

This is an academic research project. Contributions are welcome in the form of:
- Bug reports and fixes
- New platform support
- Additional vulnerability checks
- Documentation improvements
- Research methodology suggestions

## License

This project is developed for academic research purposes. Please respect the terms of use of the platforms being analyzed and use this tool responsibly.

## Acknowledgments

- Developed as part of Bachelor thesis research
- Inspired by OWASP security testing methodologies
- Built with open-source security analysis principles

## Citation

If you use this tool in academic research, please cite:

```
[Your Name]. (2024). Low-Code Platform Security Scanner: A Comparative Analysis Tool. 
Bachelor Thesis, [University Name], Department of Computer Science.
```

## Contact

For academic collaboration or questions about this research:
- Email: [your-email@university.edu]
- Thesis Supervisor: [supervisor-email@university.edu]
- Department: Computer Science, [University Name]

---

**Disclaimer**: This tool is for educational and research purposes. Always obtain proper authorization before scanning applications. The authors are not responsible for misuse of this tool.