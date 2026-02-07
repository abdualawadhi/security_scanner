"""
Enhanced Security Report Generator with Professional Features
Extends ProfessionalReportGenerator with interactive charts, risk scoring, and executive summaries
"""

import json
from datetime import datetime
from typing import Dict, List, Any

from .report_generator import ProfessionalReportGenerator


class EnhancedReportGenerator(ProfessionalReportGenerator):
    """Enhanced report generator with professional features."""
    
    def generate_report(self, scan_results, output_path=None, enhanced=True):
        """Generate report with enhanced features by default."""
        if output_path is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_path = f"security_report_{timestamp}.html"

        html_content = self.generate_html_content(scan_results, enhanced=enhanced)
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        return output_path

    def generate_html_content(self, scan_results, enhanced=True):
        """Generate HTML content with option for enhanced features."""
        if enhanced:
            return self._generate_enhanced_html(scan_results)
        return self._generate_html(scan_results)

    def _calculate_risk_score(self, vulnerabilities: List[Dict]) -> Dict[str, Any]:
        """Calculate overall risk score based on severity distribution."""
        severity_weights = {
            'critical': 10.0,
            'high': 7.5,
            'medium': 5.0,
            'low': 2.5,
            'info': 1.0
        }
        
        confidence_multipliers = {
            'certain': 1.0,
            'firm': 0.8,
            'tentative': 0.5
        }
        
        total_score = 0.0
        max_possible_score = 0.0
        
        severity_counts = {sev: 0 for sev in severity_weights.keys()}
        
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'info').lower()
            confidence = vuln.get('confidence', 'tentative').lower()
            
            if severity in severity_weights and confidence in confidence_multipliers:
                weight = severity_weights[severity]
                multiplier = confidence_multipliers[confidence]
                score = weight * multiplier
                
                total_score += score
                severity_counts[severity] += 1
                max_possible_score += weight * 1.0
        
        # Normalize to 0-100 scale using count-weighted maximum
        normalized_score = 0.0
        if max_possible_score > 0:
            normalized_score = min(100.0, (total_score / max_possible_score) * 100)
        
        # Determine risk level
        if normalized_score >= 80:
            risk_level = 'Critical'
        elif normalized_score >= 60:
            risk_level = 'High'
        elif normalized_score >= 40:
            risk_level = 'Medium'
        elif normalized_score >= 20:
            risk_level = 'Low'
        else:
            risk_level = 'Minimal'
        
        return {
            'score': round(normalized_score, 2),
            'level': risk_level,
            'severity_counts': severity_counts,
            'total_vulnerabilities': len(vulnerabilities)
        }

    def _generate_compliance_metrics(self, results: Dict) -> Dict[str, Any]:
        """Generate OWASP compliance metrics."""
        vulns = results.get('security_assessment', {}).get('vulnerabilities', [])
        compliance_summary = results.get('compliance_summary') or results.get('security_assessment', {}).get('compliance_summary', {})
        precomputed_score = None
        precomputed_issues = None
        if isinstance(compliance_summary, dict):
            owasp_summary = compliance_summary.get('OWASP') or compliance_summary.get('owasp')
            if isinstance(owasp_summary, dict):
                if 'coverage_percentage' in owasp_summary:
                    precomputed_score = owasp_summary.get('coverage_percentage')
                if 'vulnerabilities_covered' in owasp_summary:
                    precomputed_issues = owasp_summary.get('vulnerabilities_covered')
        
        owasp_coverage = {
            'A01_Broken_Access_Control': 0,
            'A02_Cryptographic_Failures': 0,
            'A03_Injection': 0,
            'A04_Insecure_Design': 0,
            'A05_Security_Misconfiguration': 0,
            'A06_Vulnerable_Components': 0,
            'A07_Identification_Failures': 0,
            'A08_Integrity_Failures': 0,
            'A09_Logging_Monitoring': 0,
            'A10_SSRF': 0
        }
        
        categories_found = set()
        for vuln in vulns:
            category = vuln.get('category', 'General')
            categories_found.add(category)

            owasp_key = self._infer_owasp_key(vuln)
            if owasp_key and owasp_key in owasp_coverage:
                owasp_coverage[owasp_key] += 1
        
        computed_issues = sum(owasp_coverage.values())
        total_owasp_issues = precomputed_issues if precomputed_issues is not None else computed_issues
        if precomputed_score is not None:
            compliance_score = precomputed_score
        else:
            compliance_score = max(0, 100 - (total_owasp_issues * 5))
        
        return {
            'score': round(compliance_score, 2),
            'owasp_coverage': owasp_coverage,
            'categories_found': list(categories_found),
            'total_owasp_issues': total_owasp_issues
        }

    def _generate_remediation_priorities(self, vulnerabilities: List[Dict]) -> List[Dict]:
        """Generate prioritized remediation list."""
        severity_order = ['critical', 'high', 'medium', 'low', 'info']
        
        prioritized = sorted(
            vulnerabilities,
            key=lambda v: (
                -severity_order.index(v.get('severity', 'info').lower()),
                {'certain': 3, 'firm': 2, 'tentative': 1}.get(v.get('confidence', 'tentative').lower(), 0)
            )
        )
        
        remediation_list = []
        for i, vuln in enumerate(prioritized[:20], 1):
            remediation_list.append({
                'priority': i,
                'title': vuln.get('title', 'Unknown Issue'),
                'severity': vuln.get('severity', 'info'),
                'confidence': vuln.get('confidence', 'tentative'),
                'url': vuln.get('instances', [{}])[0].get('url', 'N/A'),
                'cwe': vuln.get('cwe', []),
                'estimated_effort': self._estimate_remediation_effort(vuln),
                'business_impact': self._assess_business_impact(vuln)
            })
        
        return remediation_list

    def _estimate_remediation_effort(self, vuln: Dict) -> str:
        """Estimate remediation effort based on vulnerability type."""
        category = vuln.get('category', 'General').lower()
        
        if category in ['security headers', 'configuration', 'ssl/tls']:
            return 'Low (1-2 hours)'
        elif category in ['xss', 'csrf', 'input validation']:
            return 'Medium (4-8 hours)'
        elif category in ['sql injection', 'command injection', 'authorization']:
            return 'High (1-3 days)'
        elif category in ['authentication', 'session management']:
            return 'High (2-5 days)'
        else:
            return 'Medium (4-8 hours)'

    def _assess_business_impact(self, vuln: Dict) -> str:
        """Assess business impact of vulnerability."""
        severity = vuln.get('severity', 'info').lower()
        
        impact_map = {
            'critical': 'Severe - Potential data breach, complete system compromise, regulatory penalties',
            'high': 'Significant - Data exposure, service disruption, reputational damage',
            'medium': 'Moderate - Limited data exposure, partial functionality impact',
            'low': 'Minor - Information disclosure, minimal business impact',
            'info': 'Informational - No direct impact, compliance considerations'
        }
        
        return impact_map.get(severity, 'Unknown impact')

    def _generate_enhanced_html(self, results):
        """Generate enhanced HTML report with interactive features."""
        vulns = results.get('security_assessment', {}).get('vulnerabilities', [])
        risk_score = self._calculate_risk_score(vulns)
        compliance = self._generate_compliance_metrics(results)
        remediation = self._generate_remediation_priorities(vulns)
        chart_data = self._prepare_chart_data(vulns, risk_score)
        
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Professional Security Report - Enhanced</title>
    {self._get_enhanced_styles()}
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
</head>
<body>
    <div id="container">
        {self._generate_enhanced_header(results, risk_score, compliance)}
        {self._generate_enhanced_executive_summary(results, risk_score, compliance)}
        {self._generate_enhanced_risk_dashboard(chart_data, risk_score)}
        {self._generate_enhanced_remediation_priorities(remediation)}
        {self._generate_metadata_overview(results)}
        {self._generate_methodology_section(results)}
        {self._generate_platform_confidence_panel(results)}
        {self._generate_comparative_tables(results)}
        {self._generate_report_integrity_block(results)}
        {self._generate_burp_contents(results)}
        {self._generate_platform_specific_findings(results)}
        {self._generate_enhanced_findings(results)}
        {self._generate_enhanced_footer()}
    </div>
    {self._get_enhanced_scripts(chart_data)}
</body>
</html>"""

    def _get_enhanced_styles(self):
        """Enhanced CSS styles with modern design."""
        return """<style type="text/css">
* { margin: 0; padding: 0; box-sizing: border-box; }
body {
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
    color: #404042;
    min-height: 100vh;
    padding: 20px;
}
#container {
    width: 100%;
    max-width: 1200px;
    margin: 0 auto;
    background-color: #ffffff;
    box-shadow: 0 20px 60px rgba(0,0,0,0.3);
    border-radius: 12px;
    padding: 30px;
}
.header-enhanced {
    background: linear-gradient(135deg, #1e3a8a 0%, #1e40af 50%, #2563eb 100%);
    padding: 40px;
    border-radius: 12px;
    color: white;
    text-align: center;
    margin-bottom: 30px;
}
.header-enhanced h1 {
    font-size: 2.5em;
    margin-bottom: 15px;
    font-weight: 700;
}
.header-enhanced .subtitle {
    font-size: 1.2em;
    opacity: 0.9;
    margin-bottom: 25px;
}
.risk-score-container {
    display: flex;
    justify-content: center;
    gap: 50px;
    margin: 30px 0;
    flex-wrap: wrap;
}
.risk-score-circle {
    width: 180px;
    height: 180px;
    border-radius: 50%;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    background: conic-gradient(var(--risk-color) var(--risk-percent), #e5e7eb var(--risk-percent));
    position: relative;
    box-shadow: 0 8px 20px rgba(0,0,0,0.15);
}
.risk-score-circle::before {
    content: '';
    position: absolute;
    width: 150px;
    height: 150px;
    border-radius: 50%;
    background: white;
}
.risk-score-value {
    position: relative;
    z-index: 1;
    font-size: 3em;
    font-weight: 700;
    color: var(--risk-color);
}
.risk-score-label {
    position: relative;
    z-index: 1;
    font-size: 0.9em;
    color: #6b7280;
    text-transform: uppercase;
    letter-spacing: 1px;
}
.metrics-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
    gap: 25px;
    margin: 30px 0;
}
.metric-card {
    background: #f9fafb;
    padding: 30px;
    border-radius: 12px;
    text-align: center;
    border: 2px solid #e5e7eb;
    transition: all 0.3s ease;
}
.metric-card:hover {
    transform: translateY(-5px);
    box-shadow: 0 10px 30px rgba(0,0,0,0.1);
    border-color: #3b82f6;
}
.metric-card .metric-value {
    font-size: 3em;
    font-weight: 700;
    color: #1e40af;
}
.metric-card .metric-label {
    font-size: 1em;
    color: #6b7280;
    margin-top: 10px;
    text-transform: uppercase;
    letter-spacing: 1px;
}
.severity-badge {
    display: inline-block;
    padding: 6px 16px;
    border-radius: 25px;
    font-size: 0.85em;
    font-weight: 600;
    text-transform: uppercase;
}
.severity-critical { background: #dc2626; color: white; }
.severity-high { background: #ea580c; color: white; }
.severity-medium { background: #f59e0b; color: white; }
.severity-low { background: #3b82f6; color: white; }
.severity-info { background: #6b7280; color: white; }
.remediation-table {
    width: 100%;
    border-collapse: collapse;
    margin: 25px 0;
    background: white;
    box-shadow: 0 4px 6px rgba(0,0,0,0.05);
    border-radius: 12px;
    overflow: hidden;
}
.remediation-table th {
    background: linear-gradient(135deg, #1e40af 0%, #3b82f6 100%);
    color: white;
    padding: 18px;
    text-align: left;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 1px;
    font-size: 0.85em;
}
.remediation-table td {
    padding: 18px;
    border-bottom: 1px solid #e5e7eb;
}
.remediation-table tr:hover {
    background: #f3f4f6;
}
.remediation-table tr:last-child td {
    border-bottom: none;
}
.priority-number {
    display: inline-block;
    width: 35px;
    height: 35px;
    border-radius: 50%;
    background: #3b82f6;
    color: white;
    text-align: center;
    line-height: 35px;
    font-weight: 700;
}
.chart-container {
    margin: 35px 0;
    padding: 25px;
    background: #f9fafb;
    border-radius: 12px;
    border: 2px solid #e5e7eb;
}
.chart-container canvas {
    max-height: 350px;
}
.enhanced-section {
    margin: 50px 0;
    padding: 35px;
    background: #ffffff;
    border-radius: 12px;
    border: 1px solid #e5e7eb;
}
.section-header {
    display: flex;
    align-items: center;
    margin-bottom: 30px;
    padding-bottom: 20px;
    border-bottom: 2px solid #e5e7eb;
}
.section-header h2 {
    font-size: 2em;
    color: #1e40af;
    margin: 0;
}
.rule { height: 2px; border-top: 1px solid #404042; margin: 30px 0; background: #404042; }
table { font-family: Arial, sans-serif; }
a:link, a:visited { color: #3b82f6; text-decoration: none; }
a:hover, a:active { color: #1e40af; text-decoration: underline; }
h1 { font-size: 1.6em; line-height: 1.4em; color: #404042; }
h2 { font-size: 1.3em; color: #404042; margin: 20px 0 10px 0; }
h3 { font-size: 1.1em; color: #404042; margin: 15px 0 10px 0; }
.TEXT { font-size: 0.9em; line-height: 1.6; color: #4b5563; }
.rr_div {
    border: 2px solid #1e40af;
    padding: 15px;
    font-size: 0.85em;
    max-height: 400px;
    overflow-y: auto;
    background: #f9fafb;
    border-radius: 8px;
    font-family: 'Courier New', monospace;
}
.HIGHLIGHT { background-color: #fef08a; padding: 2px 4px; border-radius: 3px; }
@media (max-width: 768px) {
    .risk-score-container { gap: 20px; }
    .risk-score-circle { width: 140px; height: 140px; }
    .risk-score-circle::before { width: 110px; height: 110px; }
    .risk-score-value { font-size: 2em; }
    .metrics-grid { grid-template-columns: 1fr; }
}
</style>"""

    def _get_risk_color(self, risk_level):
        """Get color based on risk level."""
        colors = {
            'Critical': '#dc2626',
            'High': '#ea580c',
            'Medium': '#f59e0b',
            'Low': '#3b82f6',
            'Minimal': '#10b981'
        }
        return colors.get(risk_level, '#6b7280')

    def _generate_enhanced_header(self, results, risk_score, compliance):
        """Generate enhanced report header."""
        risk_color = self._get_risk_color(risk_score['level'])
        risk_percent = risk_score['score']
        return f"""<div class="header-enhanced">
    <h1><i class="fas fa-shield-alt"></i> Professional Security Report</h1>
    <p class="subtitle">Low-Code Platform Security Assessment</p>
    <div class="risk-score-container">
        <div class="risk-score-circle" style="--risk-color: {risk_color}; --risk-percent: {risk_percent}%;">
            <span class="risk-score-value">{risk_score['score']}</span>
            <span class="risk-score-label">Risk Score</span>
        </div>
        <div style="text-align: left;">
            <h3 style="margin-bottom: 15px; font-size: 1.4em;">Overall Assessment</h3>
            <p style="margin: 10px 0;"><strong>Security Level:</strong> <span class="severity-badge severity-{risk_score['level'].lower()}">{risk_score['level']}</span></p>
            <p style="margin: 10px 0;"><strong>Total Vulnerabilities:</strong> {risk_score['total_vulnerabilities']}</p>
            <p style="margin: 10px 0;"><strong>OWASP Compliance:</strong> {compliance['score']}%</p>
            <p style="margin: 10px 0;"><strong>Scan Date:</strong> {datetime.now().strftime('%B %d, %Y %H:%M')}</p>
        </div>
    </div>
</div>"""

    def _generate_enhanced_executive_summary(self, results, risk_score, compliance):
        """Generate executive summary section."""
        vulns = results.get('security_assessment', {}).get('vulnerabilities', [])
        platform = results.get('platform_analysis', {}).get('platform_type', 'Unknown').title()
        return f"""<div class="enhanced-section">
    <div class="section-header">
        <h2>Executive Summary</h2>
    </div>
    <div class="TEXT">
        <p style="margin-bottom: 20px; font-size: 1.05em;">This security assessment was conducted on the <strong>{platform}</strong> platform. The overall security posture has been evaluated as <strong>{risk_score['level']}</strong> with a risk score of <strong>{risk_score['score']}/100</strong>.</p>
        <h3>Key Findings</h3>
        <ul style="margin: 15px 0; padding-left: 25px;">
            <li><strong>Critical Issues:</strong> {risk_score['severity_counts']['critical']} vulnerabilities requiring immediate attention</li>
            <li><strong>High Severity:</strong> {risk_score['severity_counts']['high']} issues that should be addressed soon</li>
            <li><strong>Medium Severity:</strong> {risk_score['severity_counts']['medium']} vulnerabilities that should be remediated</li>
            <li><strong>Low Severity:</strong> {risk_score['severity_counts']['low']} issues for improvement</li>
        </ul>
        <h3>Compliance Status</h3>
        <p style="margin: 15px 0;">The target achieves <strong>{compliance['score']}%</strong> OWASP Top 10 2021 compliance with <strong>{compliance['total_owasp_issues']}</strong> identified OWASP-related issues.</p>
        <h3>Recommendations</h3>
        <ol style="margin: 15px 0; padding-left: 25px;">
            <li>Address all Critical and High severity vulnerabilities immediately</li>
            <li>Implement missing security headers to improve baseline security</li>
            <li>Review OWASP Top 10 coverage and implement recommended controls</li>
            <li>Establish regular security scanning and monitoring</li>
        </ol>
    </div>
</div>"""

    def _prepare_chart_data(self, vulns, risk_score):
        """Prepare data for charts."""
        severity_data = {
            'labels': ['Critical', 'High', 'Medium', 'Low', 'Info'],
            'data': [
                risk_score['severity_counts']['critical'],
                risk_score['severity_counts']['high'],
                risk_score['severity_counts']['medium'],
                risk_score['severity_counts']['low'],
                risk_score['severity_counts']['info']
            ],
            'colors': ['#dc2626', '#ea580c', '#f59e0b', '#3b82f6', '#6b7280']
        }
        category_counts = {}
        for vuln in vulns:
            cat = vuln.get('category', 'General')
            category_counts[cat] = category_counts.get(cat, 0) + 1
        return {
            'severity': severity_data,
            'categories': {
                'labels': list(category_counts.keys())[:10],
                'data': list(category_counts.values())[:10]
            }
        }

    def _generate_enhanced_risk_dashboard(self, chart_data, risk_score):
        """Generate risk dashboard with charts."""
        return f"""<div class="enhanced-section">
    <div class="section-header">
        <h2>Risk Dashboard</h2>
    </div>
    <div class="metrics-grid">
        <div class="metric-card">
            <div class="metric-value" style="color: #dc2626;">{risk_score['severity_counts']['critical']}</div>
            <div class="metric-label">Critical</div>
        </div>
        <div class="metric-card">
            <div class="metric-value" style="color: #ea580c;">{risk_score['severity_counts']['high']}</div>
            <div class="metric-label">High</div>
        </div>
        <div class="metric-card">
            <div class="metric-value" style="color: #f59e0b;">{risk_score['severity_counts']['medium']}</div>
            <div class="metric-label">Medium</div>
        </div>
        <div class="metric-card">
            <div class="metric-value" style="color: #3b82f6;">{risk_score['severity_counts']['low']}</div>
            <div class="metric-label">Low</div>
        </div>
    </div>
    <div class="chart-container">
        <canvas id="severityChart"></canvas>
    </div>
    <div class="chart-container">
        <canvas id="categoryChart"></canvas>
    </div>
</div>"""

    def _generate_enhanced_remediation_priorities(self, remediation):
        """Generate prioritized remediation table."""
        if not remediation:
            return '<div class="enhanced-section"><p>No vulnerabilities requiring remediation found.</p></div>'
        rows = []
        for item in remediation[:10]:
            cwe_links = ', '.join([f"<a href='https://cwe.mitre.org/data/definitions/{c}.html' target='_blank'>CWE-{c}</a>" for c in item['cwe'][:3]])
            rows.append(f"""
        <tr>
            <td><span class="priority-number">{item['priority']}</span></td>
            <td>
                <strong>{item['title']}</strong><br>
                <small>{item['url']}</small>
            </td>
            <td><span class="severity-badge severity-{item['severity'].lower()}">{item['severity']}</span></td>
            <td>{item['estimated_effort']}</td>
            <td>{cwe_links if cwe_links else 'N/A'}</td>
        </tr>""")
        return f"""<div class="enhanced-section">
    <div class="section-header">
        <h2>Remediation Priorities</h2>
    </div>
    <p class="TEXT">Top 10 prioritized vulnerabilities requiring remediation based on severity, confidence, and business impact.</p>
    <table class="remediation-table">
        <thead>
            <tr>
                <th width="80">Priority</th>
                <th width="40%">Vulnerability</th>
                <th width="120">Severity</th>
                <th width="180">Estimated Effort</th>
                <th>References</th>
            </tr>
        </thead>
        <tbody>
            {''.join(rows)}
        </tbody>
    </table>
</div>"""

    def _generate_enhanced_findings(self, results):
        """Generate enhanced vulnerability findings section."""
        return f"""<div class="enhanced-section">
    <div class="section-header">
        <h2>Detailed Vulnerability Findings</h2>
    </div>
    {self._generate_burp_findings(results)}
</div>"""

    def _generate_enhanced_footer(self):
        """Generate enhanced footer."""
        return f"""<div class="rule"></div>
<div style="text-align: center; padding: 40px; color: #6b7280; background: #f9fafb; border-radius: 12px; margin-top: 50px;">
    <h3 style="color: #1e40af; margin-bottom: 15px; font-size: 1.5em;">Report Generated by UST Professional Security Scanner</h3>
    <p style="font-size: 1.1em;">Low-Code Platform Security Assessment Tool</p>
    <p style="margin-top: 15px; font-size: 0.95em;">© {datetime.now().year} UST Security Research Team</p>
    <p style="margin-top: 8px; font-size: 0.9em; color: #9ca3af;">Bachelor Thesis Project - Comparative Security Analysis</p>
    <p style="margin-top: 20px;">
        <small>Report generated: {datetime.now().strftime('%B %d, %Y at %H:%M:%S')}</small>
    </p>
</div>"""

    def _get_enhanced_scripts(self, chart_data):
        """Get JavaScript for enhanced features."""
        severity_data = chart_data['severity']
        category_data = chart_data['categories']
        return f"""<script>
document.addEventListener('DOMContentLoaded', function() {{
    const severityCtx = document.getElementById('severityChart');
    if (severityCtx) {{
        new Chart(severityCtx, {{
            type: 'doughnut',
            data: {{
                labels: {json.dumps(severity_data['labels'])},
                datasets: [{{
                    data: {json.dumps(severity_data['data'])},
                    backgroundColor: {json.dumps(severity_data['colors'])},
                    borderWidth: 2,
                    borderColor: '#ffffff'
                }}]
            }},
            options: {{
                responsive: true,
                maintainAspectRatio: false,
                plugins: {{
                    legend: {{
                        position: 'bottom',
                        labels: {{ padding: 20, font: {{ size: 12 }} }}
                    }},
                    title: {{
                        display: true,
                        text: 'Vulnerability Severity Distribution',
                        font: {{ size: 16, weight: 'bold' }}
                    }}
                }}
            }}
        }});
    }}
    const categoryCtx = document.getElementById('categoryChart');
    if (categoryCtx && {json.dumps(category_data['labels'])}.length > 0) {{
        new Chart(categoryCtx, {{
            type: 'bar',
            data: {{
                labels: {json.dumps(category_data['labels'])},
                datasets: [{{
                    label: 'Vulnerabilities',
                    data: {json.dumps(category_data['data'])},
                    backgroundColor: '#3b82f6',
                    borderColor: '#1e40af',
                    borderWidth: 2
                }}]
            }},
            options: {{
                responsive: true,
                maintainAspectRatio: false,
                plugins: {{
                    legend: {{ display: false }},
                    title: {{
                        display: true,
                        text: 'Vulnerabilities by Category',
                        font: {{ size: 16, weight: 'bold' }}
                    }}
                }},
                scales: {{
                    y: {{
                        beginAtZero: true,
                        ticks: {{ stepSize: 1 }}
                    }}
                }}
            }}
        }});
    }}
}});
</script>"""
