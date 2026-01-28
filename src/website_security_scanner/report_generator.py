"""
Professional Security Report Generator - Burp Suite Style
"""

import json
from datetime import datetime

class ProfessionalReportGenerator:
    def generate_report(self, scan_results, output_path=None):
        if output_path is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_path = f"security_report_{timestamp}.html"
        
        html_content = self._generate_html(scan_results)
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        return output_path
    
    def _generate_html(self, results):
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Scan Report - {results['scan_metadata']['url']}</title>
    {self._get_burp_styles()}
</head>
<body>
    <div id="container">
        {self._generate_burp_header(results)}
        {self._generate_burp_summary(results)}
        {self._generate_burp_contents(results)}
        {self._generate_burp_findings(results)}
        {self._generate_footer()}
    </div>
</body>
</html>"""
    
    def _get_burp_styles(self):
        return """<style>
body { background: #dedede; font-family: Arial, sans-serif; color: #404042; margin: 0; padding: 0; }
#container { width: 930px; padding: 0 15px; margin: 20px auto; background: #fff; }
.title { color: #fff; background: #1e517e; margin: 0 -15px 10px -15px; padding: 20px 15px; }
.title h1 { color: #fff; margin: 0; font-size: 1.8em; }
.subtitle { color: #e0e0e0; font-size: 0.9em; margin-top: 5px; }
h1 { font-size: 1.6em; color: #404042; margin: 20px 0 10px 0; }
h2 { font-size: 1.3em; color: #404042; margin: 15px 0 10px 0; }
.rule { height: 0; border-top: 1px solid #404042; margin: 20px -15px; }
table.overview_table { border: 2px solid #e6e6e6; width: 100%; border-collapse: collapse; margin: 10px 0; }
table.overview_table td { padding: 10px; border: 1px solid #e6e6e6; }
table.overview_table td.label { font-weight: bold; background: #f5f5f5; width: 200px; }
table.summary_table { border: 2px solid #e6e6e6; width: 100%; border-collapse: collapse; margin: 10px 0; }
table.summary_table td { padding: 10px; border: 1px solid #e6e6e6; }
.severity-badge { display: inline-block; padding: 5px 15px; border-radius: 3px; font-weight: bold; color: #fff; }
.severity-critical { background: #8b0000; }
.severity-high { background: #f32a4c; }
.severity-medium { background: #ff6633; }
.severity-low { background: #0094ff; }
.severity-info { background: #7e8993; }
.TOCH0 { font-size: 1.0em; font-weight: bold; margin: 10px 0 5px 0; }
.TOCH1 { font-size: 0.9em; margin: 5px 0 5px 30px; }
.finding-section { margin: 30px 0; padding: 20px; border: 1px solid #e6e6e6; background: #fafafa; }
.finding-header { background: #1e517e; color: #fff; padding: 10px 15px; margin: -20px -20px 15px -20px; }
.code-block { background: #f5f5f5; border: 1px solid #ddd; padding: 10px; font-family: monospace; font-size: 0.9em; overflow-x: auto; margin: 10px 0; white-space: pre-wrap; word-wrap: break-word; }
.recommendation { background: #e8f5e9; border-left: 4px solid #4caf50; padding: 10px; margin: 10px 0; }
.impact-box { background: #fff3e0; border-left: 4px solid #ff9800; padding: 10px; margin: 10px 0; }
.colour_block { padding: 5px 10px; text-align: center; display: inline-block; font-weight: bold; border-radius: 3px; }
.high_certain { background: #f32a4c; color: #fff; }
.medium_certain { background: #ff6633; color: #fff; }
.low_certain { background: #0094ff; color: #fff; }
.info_certain { background: #7e8993; color: #fff; }
</style>"""
    
    def _generate_burp_header(self, results):
        metadata = results['scan_metadata']
        return f"""<div class="title">
    <h1>🔒 Professional Security Scanner Report</h1>
    <div class="subtitle">
        Target: {metadata['url']}<br>
        Platform: {results['platform_analysis']['platform_type'].title()}<br>
        Scan Date: {datetime.fromisoformat(metadata['timestamp']).strftime('%B %d, %Y %H:%M:%S')}<br>
        Scanner: {metadata['scanner_version']}
    </div>
</div>"""
    
    def _generate_burp_summary(self, results):
        summary = results['executive_summary']
        assessment = results['security_assessment']
        return f"""<h1>Summary</h1>
<span>The table below shows the numbers of issues identified in different categories.</span><br><br>
<table class="overview_table">
    <tr>
        <td class="label">Overall Security Score</td>
        <td><span class="severity-badge severity-{assessment['risk_level'].lower()}">{assessment['overall_score']}/100</span></td>
    </tr>
    <tr>
        <td class="label">Risk Level</td>
        <td><span class="severity-badge severity-{assessment['risk_level'].lower()}">{assessment['risk_level']}</span></td>
    </tr>
    <tr>
        <td class="label">Critical Issues</td>
        <td><span class="colour_block high_certain">{summary['critical_findings']}</span></td>
    </tr>
    <tr>
        <td class="label">High Severity</td>
        <td><span class="colour_block high_certain">{summary['high_risk_issues']}</span></td>
    </tr>
    <tr>
        <td class="label">Medium Severity</td>
        <td><span class="colour_block medium_certain">{summary['medium_risk_issues']}</span></td>
    </tr>
    <tr>
        <td class="label">Low Severity</td>
        <td><span class="colour_block low_certain">{summary['low_risk_issues']}</span></td>
    </tr>
</table>

<div class="rule"></div>
<h1>Platform Analysis</h1>
<table class="overview_table">
    <tr>
        <td class="label">Platform Type</td>
        <td>{results['platform_analysis']['platform_type'].title()}</td>
    </tr>
    <tr>
        <td class="label">Technology Stack</td>
        <td>{', '.join(results['platform_analysis'].get('technology_stack', ['Not detected']))}</td>
    </tr>
    <tr>
        <td class="label">Response Time</td>
        <td>{results['scan_metadata'].get('response_time', 'N/A')} seconds</td>
    </tr>
    <tr>
        <td class="label">Status Code</td>
        <td>{results['scan_metadata'].get('status_code', 'N/A')}</td>
    </tr>
</table>"""
    
    def _generate_burp_contents(self, results):
        vulnerabilities = results['security_assessment'].get('vulnerabilities', [])
        contents = ['<div class="rule"></div>', '<h1>Contents</h1>']
        
        categories = {}
        for i, vuln in enumerate(vulnerabilities, 1):
            title = vuln.get('title', 'Unknown')
            category = vuln.get('category', 'Other')
            if category not in categories:
                categories[category] = []
            categories[category].append((i, title))
        
        idx = 1
        for category, items in categories.items():
            contents.append(f'<p class="TOCH0"><a href="#{idx}">{idx}. {category}</a></p>')
            for item_idx, title in items:
                contents.append(f'<p class="TOCH1"><a href="#{idx}.{item_idx}">{idx}.{item_idx}. {title}</a></p>')
            idx += 1
        
        return '\n'.join(contents)
    
    def _generate_burp_findings(self, results):
        vulnerabilities = results['security_assessment'].get('vulnerabilities', [])
        headers = results['security_assessment'].get('security_headers', {})
        ssl = results['security_assessment'].get('ssl_tls_analysis', {})
        
        findings = ['<div class="rule"></div>']
        
        findings.append('<h1 id="headers">Security Headers Analysis</h1>')
        findings.append('<div class="finding-section">')
        findings.append(f'<h2>Security Grade: {headers.get("security_grade", "Unknown")}</h2>')
        findings.append(f'<p>Score: {headers.get("header_quality_score", 0)}%</p>')
        findings.append('<table class="overview_table">')
        findings.append('<tr><td class="label">Header</td><td class="label">Status</td><td class="label">Value</td></tr>')
        
        for header, data in headers.get('headers_present', {}).items():
            findings.append(f'<tr><td>{header}</td><td>✓ Present</td><td>{data.get("value", "N/A")[:100]}</td></tr>')
        
        for missing in headers.get('headers_missing', []):
            findings.append(f'<tr><td>{missing.get("name", "Unknown")}</td><td>✗ Missing</td><td>-</td></tr>')
        
        findings.append('</table></div>')
        
        findings.append('<div class="rule"></div>')
        findings.append('<h1 id="ssl">SSL/TLS Configuration</h1>')
        findings.append('<div class="finding-section">')
        findings.append(f'<h2>Grade: {ssl.get("grade", "Unknown")}</h2>')
        findings.append('<table class="overview_table">')
        findings.append(f'<tr><td class="label">Protocol</td><td>{ssl.get("protocol_version", "Unknown")}</td></tr>')
        findings.append(f'<tr><td class="label">Cipher</td><td>{str(ssl.get("cipher_suite", "Unknown"))[:100]}</td></tr>')
        findings.append(f'<tr><td class="label">Valid Certificate</td><td>{"Yes" if ssl.get("certificate_valid") else "No"}</td></tr>')
        findings.append('</table></div>')
        
        findings.append('<div class="rule"></div>')
        findings.append('<h1 id="vulnerabilities">Detected Vulnerabilities</h1>')
        
        for i, vuln in enumerate(vulnerabilities, 1):
            severity = vuln.get('severity', 'Info').lower()
            findings.append(f'<div class="finding-section" id="vuln-{i}">')
            findings.append(f'<div class="finding-header"><h2>{i}. {vuln.get("title", "Unknown Vulnerability")}</h2></div>')
            findings.append('<table class="summary_table">')
            findings.append(f'<tr><td class="label">Severity</td><td><span class="severity-badge severity-{severity}">{vuln.get("severity", "Unknown")}</span></td></tr>')
            findings.append(f'<tr><td class="label">Confidence</td><td>{vuln.get("confidence", "Unknown")}</td></tr>')
            findings.append(f'<tr><td class="label">Category</td><td>{vuln.get("category", "N/A")}</td></tr>')
            findings.append(f'<tr><td class="label">OWASP</td><td>{vuln.get("owasp", "N/A")}</td></tr>')
            findings.append(f'<tr><td class="label">CWE</td><td>{", ".join(vuln.get("cwe", ["N/A"]))}</td></tr>')
            findings.append('</table>')
            findings.append(f'<h2>Description</h2><p>{vuln.get("description", "No description")}</p>')
            findings.append(f'<div class="impact-box"><strong>Impact:</strong> {vuln.get("impact", "Not specified")}</div>')
            findings.append(f'<div class="recommendation"><strong>Remediation:</strong> {vuln.get("remediation", "No remediation provided")}</div>')
            findings.append('</div>')
        
        if not vulnerabilities:
            findings.append('<p>No vulnerabilities detected.</p>')
        
        return '\n'.join(findings)
    
    def _generate_footer(self):
        return f"""<div class="rule"></div>
<div style="text-align: center; padding: 20px; color: #666; font-size: 0.9em;">
    <p>Report generated by UST Professional Security Scanner</p>
    <p>© {datetime.now().year} UST Security Research Team</p>
    <p>This report is confidential and intended for authorized personnel only.</p>
</div>"""
