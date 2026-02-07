#!/usr/bin/env python3
"""
Evidence Builder
Low-Code Platform Security Scanner

Standardized evidence handling for vulnerability reporting.

Author: Bachelor Thesis Project - Low-Code Platforms Security Analysis
"""

from typing import Any, Dict, List, Optional, Union


class EvidenceBuilder:
    """Standardized evidence builder for consistent vulnerability reporting"""

    @staticmethod
    def regex_pattern(pattern: str, description: str = None) -> Dict[str, Any]:
        """Create regex pattern evidence for highlighting"""
        return {
            "type": "regex",
            "pattern": pattern,
            "description": description or f"Matches pattern: {pattern}"
        }

    @staticmethod
    def exact_match(text: str, context: str = None) -> Dict[str, Any]:
        """Create exact match evidence for highlighting"""
        evidence = {
            "type": "exact",
            "text": text
        }
        if context:
            evidence["context"] = context
        return evidence

    @staticmethod
    def url_parameter(param: str, value: str = None) -> Dict[str, Any]:
        """Create URL parameter evidence"""
        evidence = {
            "type": "url_param",
            "parameter": param
        }
        if value:
            evidence["value"] = value
        return evidence

    @staticmethod
    def header_evidence(header_name: str, header_value: str = None) -> Dict[str, Any]:
        """Create HTTP header evidence"""
        evidence = {
            "type": "header",
            "name": header_name
        }
        if header_value:
            evidence["value"] = header_value
        return evidence

    @staticmethod
    def javascript_variable(var_name: str, var_value: str = None) -> Dict[str, Any]:
        """Create JavaScript variable evidence"""
        evidence = {
            "type": "js_var",
            "name": var_name
        }
        if var_value:
            evidence["value"] = var_value
        return evidence

    @staticmethod
    def combine(*evidence_items: Union[Dict[str, Any], str]) -> List[Union[Dict[str, Any], str]]:
        """Combine multiple evidence items into a list"""
        return list(evidence_items)