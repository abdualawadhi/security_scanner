#!/usr/bin/env python3
"""
Security Report Generator
Low-Code Platform Security Scanner

Generate comprehensive security reports with executive summaries
and recommendations matrices.

Author: Bachelor Thesis Project - Low-Code Platforms Security Analysis
"""

from typing import Any, Dict, List


class SecurityReportGenerator:
    """Generate comprehensive security reports"""

    def __init__(self):
        self.severity_weights = {
            "Critical": 4,
            "High": 3,
            "Medium": 2,
            "Low": 1,
        }

    def generate_executive_summary(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate executive summary for scan results"""
        vulnerabilities = scan_results.get("vulnerabilities", [])
        
        # Count vulnerabilities by severity
        severity_counts = {
            "Critical": 0,
            "High": 0,
            "Medium": 0,
            "Low": 0,
        }
        
        for vuln in vulnerabilities:
            severity = vuln.get("severity", "Low")
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        # Calculate risk score
        total_vulns = sum(severity_counts.values())
        risk_score = sum(
            self.severity_weights.get(sev, 0) * count 
            for sev, count in severity_counts.items()
        )
        
        # Determine overall risk level
        if severity_counts["Critical"] > 0:
            risk_level = "Critical"
        elif severity_counts["High"] > 2:
            risk_level = "High"
        elif risk_score > 10:
            risk_level = "Medium"
        elif total_vulns > 0:
            risk_level = "Low"
        else:
            risk_level = "Minimal"
        
        # Generate recommendations
        recommendations = self._generate_recommendations(severity_counts, vulnerabilities)
        
        return {
            "total_vulnerabilities": total_vulns,
            "severity_breakdown": severity_counts,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "scan_timestamp": scan_results.get("timestamp", ""),
            "target_url": scan_results.get("url", ""),
            "platform_type": scan_results.get("platform_type", "Unknown"),
            "key_findings": self._extract_key_findings(vulnerabilities),
            "recommendations": recommendations,
            "compliance_status": self._assess_compliance(vulnerabilities),
        }

    def generate_recommendations_matrix(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate recommendations matrix based on vulnerabilities"""
        if not vulnerabilities:
            return {
                "immediate_actions": [],
                "short_term_actions": [],
                "long_term_actions": [],
                "strategic_recommendations": [],
            }
        
        # Categorize vulnerabilities by severity and type
        immediate_actions = []
        short_term_actions = []
        long_term_actions = []
        strategic_recommendations = []
        
        # Group by category
        categories = {}
        for vuln in vulnerabilities:
            category = vuln.get("category", "General")
            if category not in categories:
                categories[category] = []
            categories[category].append(vuln)
        
        # Generate recommendations for each category
        for category, vulns in categories.items():
            critical_high = [v for v in vulns if v.get("severity") in ["Critical", "High"]]
            medium_vulns = [v for v in vulns if v.get("severity") == "Medium"]
            low_vulns = [v for v in vulns if v.get("severity") == "Low"]
            
            if critical_high:
                immediate_actions.append({
                    "category": category,
                    "priority": "Critical",
                    "action": f"Address {len(critical_high)} critical/high severity {category.lower()} issues",
                    "details": [v.get("recommendation", "") for v in critical_high[:3]],
                    "affected_items": len(critical_high),
                })
            
            if medium_vulns:
                short_term_actions.append({
                    "category": category,
                    "priority": "Medium",
                    "action": f"Remediate {len(medium_vulns)} medium severity {category.lower()} issues",
                    "details": [v.get("recommendation", "") for v in medium_vulns[:3]],
                    "affected_items": len(medium_vulns),
                })
            
            if low_vulns:
                long_term_actions.append({
                    "category": category,
                    "priority": "Low",
                    "action": f"Review and fix {len(low_vulns)} low severity {category.lower()} issues",
                    "details": [v.get("recommendation", "") for v in low_vulns[:3]],
                    "affected_items": len(low_vulns),
                })
        
        # Strategic recommendations
        strategic_recommendations = self._generate_strategic_recommendations(categories)
        
        return {
            "immediate_actions": immediate_actions,
            "short_term_actions": short_term_actions,
            "long_term_actions": long_term_actions,
            "strategic_recommendations": strategic_recommendations,
            "total_recommendations": len(immediate_actions) + len(short_term_actions) + len(long_term_actions),
        }

    def _generate_recommendations(self, severity_counts: Dict[str, int], vulnerabilities: List[Dict[str, Any]]) -> List[str]:
        """Generate prioritized recommendations"""
        recommendations = []
        
        if severity_counts["Critical"] > 0:
            recommendations.append("IMMEDIATE: Address all Critical severity vulnerabilities")
        
        if severity_counts["High"] > 0:
            recommendations.append(f"HIGH: Remediate {severity_counts['High']} High severity issues within 30 days")
        
        if severity_counts["Medium"] > 3:
            recommendations.append("MEDIUM: Multiple medium-risk issues require attention")
        
        # Check for specific vulnerability types
        vuln_types = [v.get("type", "") for v in vulnerabilities]
        
        if "Missing CSRF Protection" in vuln_types:
            recommendations.append("SECURITY: Implement CSRF protection for all forms")
        
        if "Missing Content Security Policy" in vuln_types:
            recommendations.append("HEADERS: Implement Content Security Policy to prevent XSS")
        
        if "Insecure Cookie" in vuln_types:
            recommendations.append("COOKIES: Set Secure and HttpOnly flags for all cookies")
        
        if not recommendations:
            recommendations.append("GOOD: No critical security issues detected")
        
        return recommendations

    def _extract_key_findings(self, vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Extract key findings from vulnerabilities"""
        if not vulnerabilities:
            return []
        
        # Sort by severity and get top findings
        sorted_vulns = sorted(
            vulnerabilities,
            key=lambda x: self.severity_weights.get(x.get("severity", "Low"), 0),
            reverse=True
        )
        
        key_findings = []
        for vuln in sorted_vulns[:5]:  # Top 5 findings
            key_findings.append({
                "type": vuln.get("type", ""),
                "severity": vuln.get("severity", ""),
                "description": vuln.get("description", "")[:100] + "...",
                "category": vuln.get("category", ""),
                "owasp": vuln.get("owasp", ""),
            })
        
        return key_findings

    def _assess_compliance(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, str]:
        """Assess compliance status based on vulnerabilities"""
        compliance_status = {
            "OWASP": "Compliant",
            "NIST": "Compliant",
            "GDPR": "Compliant",
            "PCI_DSS": "Not Applicable",
        }
        
        # Check for OWASP Top 10 violations
        owasp_violations = [v for v in vulnerabilities if v.get("owasp", "").startswith("A")]
        if owasp_violations:
            compliance_status["OWASP"] = "Partial Compliance"
        
        # Check for data protection issues (GDPR)
        data_vulns = [v for v in vulnerabilities if v.get("category") in ["Data Exposure", "Secret Management"]]
        if data_vulns:
            compliance_status["GDPR"] = "Non-Compliant"
        
        # Check for security header issues (NIST)
        header_vulns = [v for v in vulnerabilities if v.get("category") == "Security Headers"]
        if header_vulns:
            compliance_status["NIST"] = "Partial Compliance"
        
        # Check for payment-related issues (PCI DSS)
        payment_vulns = [v for v in vulnerabilities if any(keyword in v.get("description", "").lower() for keyword in ["payment", "credit", "card", "pci"])]
        if payment_vulns:
            compliance_status["PCI_DSS"] = "Non-Compliant"
        
        return compliance_status

    def _generate_strategic_recommendations(self, categories: Dict[str, List[Dict[str, Any]]]) -> List[str]:
        """Generate strategic recommendations based on vulnerability categories"""
        recommendations = []
        
        # Analyze patterns across categories
        if "Security Headers" in categories:
            recommendations.append("Implement comprehensive security header policy across all applications")
        
        if "Data Exposure" in categories:
            recommendations.append("Review and strengthen data protection and privacy controls")
        
        if "Access Control" in categories:
            recommendations.append("Implement robust authentication and authorization framework")
        
        if "API Security" in categories:
            recommendations.append("Establish API security governance and testing procedures")
        
        if "Session Management" in categories:
            recommendations.append("Standardize secure session management practices")
        
        if "Secret Management" in categories:
            recommendations.append("Implement enterprise-wide secret management solution")
        
        # General strategic recommendations
        total_vulns = sum(len(vulns) for vulns in categories.values())
        if total_vulns > 20:
            recommendations.append("Establish regular security assessment and monitoring program")
        
        if len(categories) > 5:
            recommendations.append("Implement security-by-design principles in development lifecycle")
        
        # Add default recommendations if none were generated
        if not recommendations:
            recommendations = [
                "Continue following security best practices",
                "Implement regular security testing",
                "Stay updated with latest security trends and threats",
            ]
        
        return recommendations

    def calculate_security_score(self, vulnerabilities: List[Dict[str, Any]]) -> int:
        """Calculate overall security score (0-100)"""
        if not vulnerabilities:
            return 100
        
        # Start with perfect score and deduct points
        score = 100
        
        for vuln in vulnerabilities:
            severity = vuln.get("severity", "Low")
            if severity == "Critical":
                score -= 25
            elif severity == "High":
                score -= 15
            elif severity == "Medium":
                score -= 10
            elif severity == "Low":
                score -= 5
        
        return max(0, score)

    def get_impact_level(self, severity: str) -> str:
        """Get business impact level for severity"""
        impact_mapping = {
            "Critical": "Critical Business Impact",
            "High": "High Business Impact", 
            "Medium": "Moderate Business Impact",
            "Low": "Low Business Impact",
        }
        return impact_mapping.get(severity, "Unknown impact")
