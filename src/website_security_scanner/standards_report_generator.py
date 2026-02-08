"""
Standards-Based Security Report Generator - Zero Mock Data Architecture
Professional security scanner report generator that produces standards-based reports
with ZERO hard-coded or mock data. All content comes from actual scan results.

Author: Bachelor Thesis Project - Low-Code Platforms Security Analysis
"""

import json
import base64
import re
from datetime import datetime
from typing import Dict, List, Any, Optional
from .result_standardizer import (
    normalize_severity, 
    calculate_overall_score, 
    calculate_risk_level,
    SEVERITY_ORDER
)


class StandardsBasedReportGenerator:
    """
    Professional security report generator with strict data-driven architecture.
    
    This generator produces standards-based reports with ZERO hard-coded or mock data.
    All report content must come from actual scan results including CWE, CVSS, 
    OWASP classifications, and vulnerability details.
    
    Key Features:
    - Strict data-driven architecture - every piece of displayed data comes from scan_results
    - No sample/mock content - conditional rendering with "N/A" for missing data
    - Real CWE/OWASP references using actual vulnerability data
    - Dynamic compliance dashboard from actual compliance_mappings
    - Live HTTP traffic from actual instances field
    - Computed risk scores from actual vulnerability data
    """
    
    def __init__(self):
        """Initialize the standards-based report generator."""
        pass
    
    def generate_report(self, scan_results: Dict[str, Any], output_path: Optional[str] = None, 
                       enhanced: bool = True) -> str:
        """
        Generate a standards-based security report.
        
        Args:
            scan_results: Complete scan results with vulnerabilities and metadata
            output_path: Optional output file path
            enhanced: Whether to generate enhanced HTML report
            
        Returns:
            Generated HTML report content as string
        """
        if output_path is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_path = f"security_report_{timestamp}.html"
        
        html_content = self._generate_html_content(scan_results, enhanced=enhanced)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        return output_path
    
    def _generate_html_content(self, scan_results: Dict[str, Any], enhanced: bool = True) -> str:
        """
        Generate HTML report content using only actual scan data.
        
        Args:
            scan_results: Scan results containing vulnerabilities and metadata
            enhanced: Whether to generate enhanced version
            
        Returns:
            HTML report content
        """
        if enhanced:
            return self._generate_enhanced_html(scan_results)
        return self._generate_standard_html(scan_results)
    
    def _generate_enhanced_html(self, scan_results: Dict[str, Any]) -> str:
        """
        Generate enhanced HTML report with interactive features using only real data.
        """
        vulnerabilities = scan_results.get('security_assessment', {}).get('vulnerabilities', [])
        metadata = scan_results.get('scan_metadata', {})
        
        # Calculate real risk scores from actual vulnerability data
        risk_metrics = self._calculate_risk_metrics(vulnerabilities)
        compliance_metrics = self._calculate_compliance_metrics(vulnerabilities)
        
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="Content-Security-Policy" content="default-src 'self';img-src 'self' data:;style-src 'unsafe-inline' 'self';script-src 'unsafe-inline' 'self' https://cdn.jsdelivr.net">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Assessment Report - Standards-Based</title>
    {self._get_enhanced_styles()}
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
</head>
<body>
    <div id="container">
        {self._generate_report_header(scan_results, risk_metrics)}
        {self._generate_executive_summary(scan_results, risk_metrics)}
        {self._generate_risk_dashboard(scan_results, risk_metrics, compliance_metrics)}
        {self._generate_compliance_dashboard(scan_results, compliance_metrics)}
        {self._generate_vulnerability_findings(scan_results)}
        {self._generate_http_traffic_section(scan_results)}
        {self._generate_methodology_section(scan_results)}
        {self._generate_footer(scan_results)}
    </div>
    {self._get_enhanced_scripts(scan_results, risk_metrics)}
</body>
</html>"""
    
    def _generate_standard_html(self, scan_results: Dict[str, Any]) -> str:
        """Generate standard HTML report using only real data."""
        return self._generate_enhanced_html(scan_results)  # Use enhanced as standard for now
    
    def _calculate_risk_metrics(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Calculate risk metrics from actual vulnerability data.
        
        Args:
            vulnerabilities: List of vulnerability dictionaries
            
        Returns:
            Dictionary containing calculated risk metrics
        """
        if not vulnerabilities:
            return {
                'score': 0.0,
                'level': 'None',
                'severity_counts': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0},
                'total_vulnerabilities': 0,
                'cvss_scores': []
            }
        
        # Calculate overall score using centralized standardizer
        overall_score = calculate_overall_score(vulnerabilities)
        risk_level = calculate_risk_level(overall_score)
        
        # Count severity levels from actual data
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        cvss_scores = []
        
        for vuln in vulnerabilities:
            severity = normalize_severity(vuln.get('severity', 'info')).lower()
            if severity in severity_counts:
                severity_counts[severity] += 1
            else:
                severity_counts['info'] += 1
            
            # Extract CVSS score from vulnerability data
            cvss_score = vuln.get('cvss_score')
            if cvss_score is not None:
                cvss_scores.append(float(cvss_score))
        
        return {
            'score': overall_score,
            'level': risk_level,
            'severity_counts': severity_counts,
            'total_vulnerabilities': len(vulnerabilities),
            'cvss_scores': cvss_scores,
            'average_cvss': sum(cvss_scores) / len(cvss_scores) if cvss_scores else 0.0
        }
    
    def _calculate_compliance_metrics(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Calculate compliance metrics from actual vulnerability compliance mappings.
        
        Args:
            vulnerabilities: List of vulnerability dictionaries
            
        Returns:
            Dictionary containing compliance metrics
        """
        if not vulnerabilities:
            return {
                'owasp_coverage': {},
                'compliance_score': 100.0,
                'mapped_vulnerabilities': 0,
                'total_vulnerabilities': 0
            }
        
        # Calculate OWASP Top 10 coverage from actual data
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
        
        mapped_vulnerabilities = 0
        
        for vuln in vulnerabilities:
            # Check OWASP mappings from actual vulnerability data
            owasp_mapping = vuln.get('owasp', '')
            compliance_mappings = vuln.get('compliance_mappings', {})
            
            # Extract OWASP category from various possible fields
            owasp_category = owasp_mapping
            if isinstance(compliance_mappings, dict):
                owasp_from_compliance = compliance_mappings.get('OWASP') or compliance_mappings.get('owasp')
                if owasp_from_compliance:
                    owasp_category = owasp_from_compliance
            
            # Map to OWASP Top 10 categories
            if owasp_category:
                mapped_vulnerabilities += 1
                owasp_key = self._extract_owasp_key(str(owasp_category))
                if owasp_key in owasp_coverage:
                    owasp_coverage[owasp_key] += 1
        
        # Calculate compliance score (percentage of vulnerabilities with OWASP mapping)
        total_vulns = len(vulnerabilities)
        compliance_score = (mapped_vulnerabilities / total_vulns * 100) if total_vulns > 0 else 100.0
        
        return {
            'owasp_coverage': owasp_coverage,
            'compliance_score': round(compliance_score, 2),
            'mapped_vulnerabilities': mapped_vulnerabilities,
            'total_vulnerabilities': total_vulns
        }
    
    def _extract_owasp_key(self, owasp_value: str) -> str:
        """
        Extract OWASP Top 10 key from vulnerability data.
        
        Args:
            owasp_value: OWASP value from vulnerability data
            
        Returns:
            OWASP Top 10 key or empty string
        """
        if not owasp_value:
            return ""
        
        owasp_key_map = {
            "A01": "A01_Broken_Access_Control",
            "A02": "A02_Cryptographic_Failures", 
            "A03": "A03_Injection",
            "A04": "A04_Insecure_Design",
            "A05": "A05_Security_Misconfiguration",
            "A06": "A06_Vulnerable_Components",
            "A07": "A07_Identification_Failures",
            "A08": "A08_Integrity_Failures",
            "A09": "A09_Logging_Monitoring",
            "A10": "A10_SSRF",
        }
        
        # Search for OWASP codes
        match = re.search(r"A0[1-9]|A10", owasp_value)
        if match:
            code = match.group(0)
            return owasp_key_map.get(code, "")
        
        # Search for full category names
        for key in owasp_key_map.values():
            if key.replace('_', ' ').lower() in owasp_value.lower():
                return key
                
        return ""
    
    def _generate_report_header(self, scan_results: Dict[str, Any], risk_metrics: Dict[str, Any]) -> str:
        """Generate report header using actual metadata."""
        metadata = scan_results.get('scan_metadata', {})
        platform_info = scan_results.get('platform_analysis', {})
        
        # Extract actual data or show N/A
        target_url = metadata.get('url', 'N/A')
        platform_type = platform_info.get('platform_type', 'Unknown').title()
        scan_date = metadata.get('timestamp', 'N/A')
        
        # Format scan date if available
        if scan_date != 'N/A':
            try:
                scan_dt = datetime.fromisoformat(scan_date.replace('Z', '+00:00'))
                scan_date = scan_dt.strftime('%B %d, %Y at %H:%M:%S')
            except Exception:
                pass
        
        risk_score = risk_metrics.get('score', 0.0)
        risk_level = risk_metrics.get('level', 'None')
        
        return f"""
<div class="report-header">
    <div class="header-content">
        <h1>Security Assessment Report</h1>
        <div class="subtitle">Professional Standards-Based Analysis</div>
        <div class="scan-info">
            <div class="info-item">
                <strong>Target:</strong> {self._escape_html(target_url)}
            </div>
            <div class="info-item">
                <strong>Platform:</strong> {self._escape_html(platform_type)}
            </div>
            <div class="info-item">
                <strong>Scan Date:</strong> {scan_date}
            </div>
        </div>
        <div class="risk-overview">
            <div class="risk-score">
                <div class="score-value">{risk_score:.1f}</div>
                <div class="score-label">Risk Score</div>
            </div>
            <div class="risk-level">
                <div class="level-value">{self._escape_html(risk_level)}</div>
                <div class="level-label">Risk Level</div>
            </div>
        </div>
    </div>
</div>"""
    
    def _generate_executive_summary(self, scan_results: Dict[str, Any], risk_metrics: Dict[str, Any]) -> str:
        """Generate executive summary from actual vulnerability counts."""
        severity_counts = risk_metrics.get('severity_counts', {})
        total_vulns = risk_metrics.get('total_vulnerabilities', 0)
        
        # Calculate percentage breakdown
        def get_percentage(count):
            return round((count / total_vulns * 100) if total_vulns > 0 else 0, 1)
        
        return f"""
<div class="executive-summary">
    <h2>Executive Summary</h2>
    <div class="summary-grid">
        <div class="summary-card critical">
            <div class="card-value">{severity_counts.get('critical', 0)}</div>
            <div class="card-label">Critical</div>
            <div class="card-percent">{get_percentage(severity_counts.get('critical', 0))}%</div>
        </div>
        <div class="summary-card high">
            <div class="card-value">{severity_counts.get('high', 0)}</div>
            <div class="card-label">High</div>
            <div class="card-percent">{get_percentage(severity_counts.get('high', 0))}%</div>
        </div>
        <div class="summary-card medium">
            <div class="card-value">{severity_counts.get('medium', 0)}</div>
            <div class="card-label">Medium</div>
            <div class="card-percent">{get_percentage(severity_counts.get('medium', 0))}%</div>
        </div>
        <div class="summary-card low">
            <div class="card-value">{severity_counts.get('low', 0)}</div>
            <div class="card-label">Low</div>
            <div class="card-percent">{get_percentage(severity_counts.get('low', 0))}%</div>
        </div>
        <div class="summary-card info">
            <div class="card-value">{severity_counts.get('info', 0)}</div>
            <div class="card-label">Info</div>
            <div class="card-percent">{get_percentage(severity_counts.get('info', 0))}%</div>
        </div>
    </div>
    <div class="summary-text">
        {"<p>No vulnerabilities detected in this security assessment.</p>" if total_vulns == 0 else f"<p>Analysis identified {total_vulns} security issues requiring attention. See detailed findings below.</p>"}
    </div>
</div>"""
    
    def _generate_risk_dashboard(self, scan_results: Dict[str, Any], risk_metrics: Dict[str, Any], 
                                compliance_metrics: Dict[str, Any]) -> str:
        """Generate risk dashboard with actual data visualization."""
        severity_counts = risk_metrics.get('severity_counts', {})
        
        # Prepare chart data from actual vulnerability counts
        chart_labels = ['Critical', 'High', 'Medium', 'Low', 'Info']
        chart_data = [
            severity_counts.get('critical', 0),
            severity_counts.get('high', 0), 
            severity_counts.get('medium', 0),
            severity_counts.get('low', 0),
            severity_counts.get('info', 0)
        ]
        
        return f"""
<div class="risk-dashboard">
    <h2>Risk Analysis Dashboard</h2>
    <div class="dashboard-grid">
        <div class="chart-container">
            <h3>Vulnerability Distribution</h3>
            <canvas id="severityChart" width="400" height="200"></canvas>
        </div>
        <div class="metrics-container">
            <div class="metric-item">
                <div class="metric-value">{risk_metrics.get('total_vulnerabilities', 0)}</div>
                <div class="metric-label">Total Issues</div>
            </div>
            <div class="metric-item">
                <div class="metric-value">{risk_metrics.get('score', 0.0):.1f}</div>
                <div class="metric-label">Risk Score</div>
            </div>
            <div class="metric-item">
                <div class="metric-value">{compliance_metrics.get('compliance_score', 100.0):.1f}%</div>
                <div class="metric-label">Compliance Rate</div>
            </div>
        </div>
    </div>
</div>
<script>
// Chart data from actual scan results
window.vulnerabilityData = {{
    labels: {json.dumps(chart_labels)},
    data: {json.dumps(chart_data)}
}};
</script>"""
    
    def _generate_compliance_dashboard(self, scan_results: Dict[str, Any], 
                                     compliance_metrics: Dict[str, Any]) -> str:
        """Generate compliance dashboard from actual compliance mappings."""
        owasp_coverage = compliance_metrics.get('owasp_coverage', {})
        
        # Build OWASP coverage rows from actual data
        owasp_rows = []
        for category, count in owasp_coverage.items():
            if count > 0:
                category_name = category.replace('_', ' ').replace('A01 ', 'A01 - ')
                owasp_rows.append(f"""
                <tr>
                    <td>{self._escape_html(category_name)}</td>
                    <td>{count}</td>
                    <td><span class="status-mapped">Mapped</span></td>
                </tr>""")
        
        if not owasp_rows:
            owasp_rows.append('<tr><td colspan="3">No OWASP mappings found in scan results</td></tr>')
        
        return f"""
<div class="compliance-dashboard">
    <h2>Standards Compliance</h2>
    <div class="compliance-summary">
        <div class="compliance-score">
            <div class="score">{compliance_metrics.get('compliance_score', 0.0):.1f}%</div>
            <div class="label">OWASP Compliance</div>
        </div>
        <div class="mapping-stats">
            <div class="stat">
                <strong>{compliance_metrics.get('mapped_vulnerabilities', 0)}</strong> of {compliance_metrics.get('total_vulnerabilities', 0)} vulnerabilities mapped
            </div>
        </div>
    </div>
    <div class="owasp-coverage">
        <h3>OWASP Top 10 Coverage</h3>
        <table class="coverage-table">
            <thead>
                <tr>
                    <th>Category</th>
                    <th>Issues Found</th>
                    <th>Status</th>
                </tr>
            </thead>
            <tbody>
                {''.join(owasp_rows)}
            </tbody>
        </table>
    </div>
</div>"""
    
    def _generate_vulnerability_findings(self, scan_results: Dict[str, Any]) -> str:
        """Generate detailed vulnerability findings from actual data."""
        vulnerabilities = scan_results.get('security_assessment', {}).get('vulnerabilities', [])
        
        if not vulnerabilities:
            return """
<div class="vulnerability-findings">
    <h2>Detailed Findings</h2>
    <div class="no-vulnerabilities">
        <p>No vulnerabilities were detected in this security assessment.</p>
    </div>
</div>"""
        
        findings_html = ['<div class="vulnerability-findings">', '<h2>Detailed Findings</h2>']
        
        for i, vuln in enumerate(vulnerabilities, 1):
            findings_html.append(self._render_individual_vulnerability(vuln, i))
        
        findings_html.append('</div>')
        return '\n'.join(findings_html)
    
    def _render_individual_vulnerability(self, vuln: Dict[str, Any], index: int) -> str:
        """Render individual vulnerability using actual data."""
        title = vuln.get('title', 'Unnamed Vulnerability')
        severity = vuln.get('severity', 'Info')
        confidence = vuln.get('confidence', 'Tentative')
        description = vuln.get('description', 'No description available.')
        
        # Extract CWE references from actual data
        cwe_list = vuln.get('cwe', [])
        cwe_links = []
        for cwe_id in cwe_list:
            cwe_clean = cwe_id.replace('CWE-', '') if cwe_id.startswith('CWE-') else cwe_id
            cwe_links.append(f'<a href="https://cwe.mitre.org/data/definitions/{cwe_clean}.html" target="_blank">{self._escape_html(cwe_id)}</a>')
        
        # Extract CVSS score from actual data
        cvss_score = vuln.get('cvss_score', 'N/A')
        
        # Extract OWASP mapping from actual data
        owasp_mapping = vuln.get('owasp', 'N/A')
        
        # Extract background, impact, references from enriched data
        background = vuln.get('background', '')
        impact = vuln.get('impact', '')
        references = vuln.get('references', [])
        
        return f"""
<div class="vulnerability-item" id="vuln-{index}">
    <div class="vuln-header">
        <h3>{self._escape_html(title)}</h3>
        <div class="vuln-badges">
            <span class="severity-badge severity-{severity.lower()}">{self._escape_html(severity)}</span>
            <span class="confidence-badge confidence-{confidence.lower()}">{self._escape_html(confidence)}</span>
        </div>
    </div>
    
    <div class="vuln-metadata">
        <div class="metadata-item">
            <strong>CVSS Score:</strong> {cvss_score if cvss_score != 'N/A' else 'N/A'}
        </div>
        <div class="metadata-item">
            <strong>OWASP Category:</strong> {self._escape_html(str(owasp_mapping))}
        </div>
        {"<div class='metadata-item'><strong>CWE References:</strong> " + ", ".join(cwe_links) + "</div>" if cwe_links else ""}
    </div>
    
    <div class="vuln-description">
        <h4>Description</h4>
        <p>{self._escape_html(description)}</p>
    </div>
    
    {f"<div class='vuln-background'><h4>Background</h4><p>{self._escape_html(background)}</p></div>" if background else ""}
    {f"<div class='vuln-impact'><h4>Impact</h4><p>{self._escape_html(impact)}</p></div>" if impact else ""}
    
    {self._render_evidence_section(vuln)}
    {self._render_recommendations_section(vuln)}
    {self._render_references_section(references)}
    {self._render_verification_section(vuln)}
</div>"""
    
    def _render_evidence_section(self, vuln: Dict[str, Any]) -> str:
        """Render evidence section from actual data."""
        evidence = vuln.get('evidence', [])
        instances = vuln.get('instances', [])
        
        if not evidence and not instances:
            return ""
        
        evidence_html = ['<div class="evidence-section"><h4>Evidence</h4>']
        
        # Render evidence items
        if evidence:
            evidence_html.append('<div class="evidence-items">')
            for item in evidence:
                if isinstance(item, dict):
                    evidence_text = item.get('text', item.get('pattern', str(item)))
                else:
                    evidence_text = str(item)
                evidence_html.append(f'<div class="evidence-item"><code>{self._escape_html(evidence_text[:200])}</code></div>')
            evidence_html.append('</div>')
        
        evidence_html.append('</div>')
        return '\n'.join(evidence_html)
    
    def _render_recommendations_section(self, vuln: Dict[str, Any]) -> str:
        """Render recommendations section."""
        recommendation = vuln.get('recommendation', '')
        if not recommendation:
            return ""
        
        return f"""
<div class="recommendations-section">
    <h4>Recommendations</h4>
    <p>{self._escape_html(recommendation)}</p>
</div>"""
    
    def _render_references_section(self, references: List[str]) -> str:
        """Render references section from actual data."""
        if not references:
            return ""
        
        ref_links = []
        for ref in references:
            ref_links.append(f'<li><a href="{ref}" target="_blank">{self._escape_html(ref)}</a></li>')
        
        return f"""
<div class="references-section">
    <h4>References</h4>
    <ul>
        {''.join(ref_links)}
    </ul>
</div>"""
    
    def _render_verification_section(self, vuln: Dict[str, Any]) -> str:
        """Render verification section from actual data."""
        verification = vuln.get('verification', {})
        if not verification:
            return ""
        
        verified = verification.get('verified', False)
        method = verification.get('method', 'unknown')
        confidence = verification.get('confidence', 'unknown')
        
        status = "✓ Verified" if verified else "✗ Not Verified"
        status_class = "verified" if verified else "unverified"
        
        return f"""
<div class="verification-section">
    <h4>Vulnerability Verification</h4>
    <div class="verification-status">
        <span class="status-{status_class}">{status}</span>
        <span class="verification-method">Method: {self._escape_html(str(method))}</span>
        <span class="verification-confidence">Confidence: {self._escape_html(str(confidence))}</span>
    </div>
</div>"""
    
    def _generate_http_traffic_section(self, scan_results: Dict[str, Any]) -> str:
        """Generate HTTP traffic section from actual instances data."""
        vulnerabilities = scan_results.get('security_assessment', {}).get('vulnerabilities', [])
        
        # Collect all HTTP instances from vulnerabilities
        all_instances = []
        for vuln in vulnerabilities:
            instances = vuln.get('instances', [])
            for instance in instances:
                if instance.get('request') or instance.get('response'):
                    all_instances.append((vuln.get('title', 'Unknown'), instance))
        
        if not all_instances:
            return ""
        
        traffic_html = ['<div class="http-traffic-section">', '<h2>HTTP Traffic Analysis</h2>']
        
        for i, (vuln_title, instance) in enumerate(all_instances, 1):
            url = instance.get('url', 'N/A')
            request = instance.get('request', '')
            response = instance.get('response', '')
            
            traffic_html.append(f"""
<div class="traffic-item">
    <h4>Request/Response {i} - {self._escape_html(vuln_title)}</h4>
    <div class="traffic-url">URL: {self._escape_html(url)}</div>
    {f'<div class="request-section"><h5>Request</h5><pre class="http-content">{self._escape_html(request)}</pre></div>' if request else ''}
    {f'<div class="response-section"><h5>Response</h5><pre class="http-content">{self._escape_html(response)}</pre></div>' if response else ''}
</div>""")
        
        traffic_html.append('</div>')
        return '\n'.join(traffic_html)
    
    def _generate_methodology_section(self, scan_results: Dict[str, Any]) -> str:
        """Generate methodology section using actual metadata."""
        metadata = scan_results.get('scan_metadata', {})
        verification_summary = metadata.get('verification_summary', {})
        
        total_vulns = verification_summary.get('total_vulnerabilities', 0)
        verified_vulns = verification_summary.get('verified_vulnerabilities', 0)
        verification_rate = verification_summary.get('verification_rate', 0)
        
        return f"""
<div class="methodology-section">
    <h2>Assessment Methodology</h2>
    <div class="methodology-content">
        <p>This security assessment combines static analysis with optional active verification 
        to identify and validate security vulnerabilities in web applications.</p>
        
        <div class="verification-stats">
            <h4>Verification Coverage</h4>
            <div class="stat-grid">
                <div class="stat-item">
                    <strong>{total_vulns}</strong>
                    <span>Total Vulnerabilities</span>
                </div>
                <div class="stat-item">
                    <strong>{verified_vulns}</strong>
                    <span>Actively Verified</span>
                </div>
                <div class="stat-item">
                    <strong>{verification_rate}%</strong>
                    <span>Verification Rate</span>
                </div>
            </div>
        </div>
    </div>
</div>"""
    
    def _generate_footer(self, scan_results: Dict[str, Any]) -> str:
        """Generate report footer with actual metadata."""
        metadata = scan_results.get('scan_metadata', {})
        scanner_version = metadata.get('scanner_version', 'N/A')
        git_commit = metadata.get('git_commit', 'N/A')
        
        current_year = datetime.now().year
        
        return f"""
<div class="report-footer">
    <div class="footer-content">
        <div class="scanner-info">
            <p><strong>Generated by:</strong> Standards-Based Security Scanner v{self._escape_html(scanner_version)}</p>
            {f"<p><strong>Git Commit:</strong> {self._escape_html(git_commit)}</p>" if git_commit != 'N/A' else ""}
        </div>
        <div class="generation-info">
            <p><strong>Generated:</strong> {datetime.now().strftime('%B %d, %Y at %H:%M:%S')}</p>
            <p><strong>Report Type:</strong> Standards-Based Analysis</p>
        </div>
    </div>
    <div class="copyright">
        <p>© {current_year} Professional Security Assessment Report</p>
    </div>
</div>"""
    
    def _get_enhanced_styles(self) -> str:
        """Get enhanced CSS styles for the report."""
        return """<style type="text/css">
* { margin: 0; padding: 0; box-sizing: border-box; }
body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
    line-height: 1.6;
    color: #333;
    background: #f8f9fa;
    padding: 20px;
}
#container {
    max-width: 1200px;
    margin: 0 auto;
    background: white;
    border-radius: 8px;
    box-shadow: 0 2px 10px rgba(0,0,0,0.1);
    overflow: hidden;
}
.report-header {
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    color: white;
    padding: 40px;
}
.header-content h1 {
    font-size: 2.5em;
    margin-bottom: 10px;
    font-weight: 700;
}
.subtitle {
    font-size: 1.2em;
    opacity: 0.9;
    margin-bottom: 30px;
}
.scan-info {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
    gap: 20px;
    margin-bottom: 30px;
}
.info-item {
    background: rgba(255,255,255,0.1);
    padding: 15px;
    border-radius: 6px;
}
.risk-overview {
    display: flex;
    gap: 40px;
    align-items: center;
}
.risk-score, .risk-level {
    text-align: center;
}
.score-value, .level-value {
    font-size: 3em;
    font-weight: bold;
    margin-bottom: 5px;
}
.score-label, .level-label {
    font-size: 0.9em;
    opacity: 0.8;
    text-transform: uppercase;
    letter-spacing: 1px;
}
.executive-summary, .risk-dashboard, .compliance-dashboard, 
.vulnerability-findings, .http-traffic-section, .methodology-section {
    padding: 40px;
    border-bottom: 1px solid #eee;
}
.executive-summary h2, .risk-dashboard h2, .compliance-dashboard h2,
.vulnerability-findings h2, .http-traffic-section h2, .methodology-section h2 {
    font-size: 1.8em;
    margin-bottom: 30px;
    color: #2c3e50;
}
.summary-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
    gap: 20px;
    margin-bottom: 30px;
}
.summary-card {
    text-align: center;
    padding: 20px;
    border-radius: 8px;
    background: #f8f9fa;
    border: 2px solid transparent;
}
.summary-card.critical { border-color: #dc3545; }
.summary-card.high { border-color: #fd7e14; }
.summary-card.medium { border-color: #ffc107; }
.summary-card.low { border-color: #17a2b8; }
.summary-card.info { border-color: #6c757d; }
.card-value {
    font-size: 2.5em;
    font-weight: bold;
    margin-bottom: 5px;
}
.card-label {
    font-size: 0.9em;
    text-transform: uppercase;
    letter-spacing: 1px;
}
.card-percent {
    font-size: 0.8em;
    opacity: 0.7;
    margin-top: 5px;
}
.dashboard-grid {
    display: grid;
    grid-template-columns: 2fr 1fr;
    gap: 40px;
}
.chart-container {
    background: #f8f9fa;
    padding: 20px;
    border-radius: 8px;
}
.metrics-container {
    display: flex;
    flex-direction: column;
    gap: 20px;
}
.metric-item {
    text-align: center;
    padding: 20px;
    background: #f8f9fa;
    border-radius: 8px;
}
.metric-value {
    font-size: 2em;
    font-weight: bold;
    color: #495057;
}
.metric-label {
    font-size: 0.9em;
    color: #6c757d;
    text-transform: uppercase;
    letter-spacing: 1px;
}
.compliance-summary {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 30px;
    padding: 20px;
    background: #f8f9fa;
    border-radius: 8px;
}
.compliance-score {
    text-align: center;
}
.score {
    font-size: 2.5em;
    font-weight: bold;
    color: #28a745;
}
.coverage-table {
    width: 100%;
    border-collapse: collapse;
    background: white;
}
.coverage-table th,
.coverage-table td {
    padding: 12px;
    text-align: left;
    border-bottom: 1px solid #dee2e6;
}
.coverage-table th {
    background: #f8f9fa;
    font-weight: 600;
}
.status-mapped {
    background: #28a745;
    color: white;
    padding: 4px 8px;
    border-radius: 4px;
    font-size: 0.8em;
}
.vulnerability-item {
    margin-bottom: 40px;
    padding: 30px;
    border: 1px solid #dee2e6;
    border-radius: 8px;
    background: #f8f9fa;
}
.vuln-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 20px;
}
.vuln-header h3 {
    font-size: 1.4em;
    color: #2c3e50;
}
.vuln-badges {
    display: flex;
    gap: 10px;
}
.severity-badge, .confidence-badge {
    padding: 6px 12px;
    border-radius: 20px;
    font-size: 0.8em;
    font-weight: 600;
    text-transform: uppercase;
}
.severity-critical { background: #dc3545; color: white; }
.severity-high { background: #fd7e14; color: white; }
.severity-medium { background: #ffc107; color: #212529; }
.severity-low { background: #17a2b8; color: white; }
.severity-info { background: #6c757d; color: white; }
.confidence-certian { background: #28a745; color: white; }
.confidence-firm { background: #17a2b8; color: white; }
.confidence-tentative { background: #ffc107; color: #212529; }
.vuln-metadata {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 15px;
    margin-bottom: 20px;
    padding: 15px;
    background: white;
    border-radius: 6px;
}
.metadata-item {
    font-size: 0.9em;
}
.vuln-description, .vuln-background, .vuln-impact,
.evidence-section, .recommendations-section, 
.references-section, .verification-section {
    margin-bottom: 25px;
}
.vuln-description h4, .vuln-background h4, .vuln-impact h4,
.evidence-section h4, .recommendations-section h4,
.references-section h4, .verification-section h4 {
    font-size: 1.1em;
    margin-bottom: 10px;
    color: #495057;
    border-bottom: 2px solid #dee2e6;
    padding-bottom: 5px;
}
.evidence-items {
    display: flex;
    flex-direction: column;
    gap: 10px;
}
.evidence-item {
    background: white;
    padding: 10px;
    border-radius: 4px;
    border-left: 4px solid #17a2b8;
}
.evidence-item code {
    font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', monospace;
    font-size: 0.9em;
}
.verification-status {
    display: flex;
    gap: 20px;
    align-items: center;
    padding: 15px;
    background: white;
    border-radius: 6px;
}
.status-verified {
    background: #28a745;
    color: white;
    padding: 6px 12px;
    border-radius: 4px;
    font-weight: 600;
}
.status-unverified {
    background: #dc3545;
    color: white;
    padding: 6px 12px;
    border-radius: 4px;
    font-weight: 600;
}
.traffic-item {
    margin-bottom: 30px;
    padding: 20px;
    background: #f8f9fa;
    border-radius: 8px;
}
.traffic-item h4 {
    margin-bottom: 15px;
    color: #495057;
}
.traffic-url {
    margin-bottom: 15px;
    font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', monospace;
    font-size: 0.9em;
    background: white;
    padding: 8px;
    border-radius: 4px;
}
.request-section, .response-section {
    margin-bottom: 20px;
}
.request-section h5, .response-section h5 {
    margin-bottom: 10px;
    color: #495057;
}
.http-content {
    background: #2d3748;
    color: #e2e8f0;
    padding: 15px;
    border-radius: 6px;
    overflow-x: auto;
    font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', monospace;
    font-size: 0.85em;
    line-height: 1.4;
}
.methodology-content p {
    margin-bottom: 20px;
    line-height: 1.7;
}
.verification-stats {
    margin-top: 30px;
}
.verification-stats h4 {
    margin-bottom: 15px;
    color: #495057;
}
.stat-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
    gap: 20px;
}
.stat-item {
    text-align: center;
    padding: 20px;
    background: white;
    border-radius: 8px;
    border: 1px solid #dee2e6;
}
.stat-item strong {
    display: block;
    font-size: 2em;
    color: #495057;
    margin-bottom: 5px;
}
.stat-item span {
    font-size: 0.9em;
    color: #6c757d;
    text-transform: uppercase;
    letter-spacing: 1px;
}
.report-footer {
    background: #f8f9fa;
    padding: 30px 40px;
    border-top: 1px solid #dee2e6;
}
.footer-content {
    display: flex;
    justify-content: space-between;
    margin-bottom: 20px;
}
.scanner-info, .generation-info {
    font-size: 0.9em;
    color: #6c757d;
}
.copyright {
    text-align: center;
    font-size: 0.8em;
    color: #6c757d;
    padding-top: 20px;
    border-top: 1px solid #dee2e6;
}
.no-vulnerabilities {
    text-align: center;
    padding: 40px;
    background: #f8f9fa;
    border-radius: 8px;
    color: #6c757d;
}
@media (max-width: 768px) {
    .dashboard-grid {
        grid-template-columns: 1fr;
    }
    .risk-overview {
        flex-direction: column;
        gap: 20px;
    }
    .summary-grid {
        grid-template-columns: repeat(2, 1fr);
    }
    .footer-content {
        flex-direction: column;
        gap: 20px;
    }
}
</style>"""
    
    def _get_enhanced_scripts(self, scan_results: Dict[str, Any], risk_metrics: Dict[str, Any]) -> str:
        """Get enhanced JavaScript for charts and interactivity."""
        return f"""
<script>
document.addEventListener('DOMContentLoaded', function() {{
    // Create vulnerability distribution chart if data exists
    if (window.vulnerabilityData && window.vulnerabilityData.data.some(val => val > 0)) {{
        const ctx = document.getElementById('severityChart').getContext('2d');
        new Chart(ctx, {{
            type: 'doughnut',
            data: {{
                labels: window.vulnerabilityData.labels,
                datasets: [{{
                    data: window.vulnerabilityData.data,
                    backgroundColor: [
                        '#dc3545',
                        '#fd7e14', 
                        '#ffc107',
                        '#17a2b8',
                        '#6c757d'
                    ],
                    borderWidth: 2,
                    borderColor: '#fff'
                }}]
            }},
            options: {{
                responsive: true,
                maintainAspectRatio: false,
                plugins: {{
                    legend: {{
                        position: 'bottom'
                    }}
                }}
            }}
        }});
    }}
    
    // Add smooth scrolling for internal links
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {{
        anchor.addEventListener('click', function (e) {{
            e.preventDefault();
            const target = document.querySelector(this.getAttribute('href'));
            if (target) {{
                target.scrollIntoView({{
                    behavior: 'smooth'
                }});
            }}
        }});
    }});
}});
</script>"""
    
    def _escape_html(self, text: str) -> str:
        """Escape HTML characters to prevent XSS."""
        if not isinstance(text, str):
            text = str(text)
        return (text.replace('&', '&amp;')
                    .replace('<', '&lt;')
                    .replace('>', '&gt;')
                    .replace('"', '&quot;')
                    .replace("'", '&#39;'))