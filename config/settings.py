#!/usr/bin/env python3
"""
Scanner Configuration Management
Low-Code Platform Security Scanner

Centralized configuration management system for scan parameters.

Author: Bachelor Thesis Project - Low-Code Platforms Security Analysis
"""

import os
from typing import Any, Dict, List, Optional
from pathlib import Path

import yaml


class ScannerConfig:
    """Centralized configuration management for the security scanner"""

    def __init__(self, config_path: Optional[str] = None):
        self.config_path = config_path or self._get_default_config_path()
        self._config = self._load_config()

    def _get_default_config_path(self) -> str:
        """Get the default configuration file path"""
        # Assume we're in src/website_security_scanner/config/config.yaml
        current_dir = Path(__file__).parent
        config_path = current_dir / "config.yaml"
        return str(config_path)

    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from YAML file"""
        try:
            with open(self.config_path, 'r', encoding='utf-8') as f:
                return yaml.safe_load(f)
        except FileNotFoundError:
            print(f"Warning: Configuration file not found at {self.config_path}")
            return self._get_default_config()
        except yaml.YAMLError as e:
            print(f"Error parsing configuration file: {e}")
            return self._get_default_config()

    def _get_default_config(self) -> Dict[str, Any]:
        """Get default configuration values"""
        return {
            "scanner": {
                "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "timeout": 10,
                "max_redirects": 5,
                "verify_ssl": False,
                "delay_between_requests": 2,
                "max_concurrent_scans": 3
            },
            "logging": {
                "level": "INFO",
                "console_output": True
            }
        }

    # Scanner settings
    @property
    def user_agent(self) -> str:
        return self._config.get("scanner", {}).get("user_agent", "")

    @property
    def timeout(self) -> int:
        return self._config.get("scanner", {}).get("timeout", 10)

    @property
    def max_redirects(self) -> int:
        return self._config.get("scanner", {}).get("max_redirects", 5)

    @property
    def verify_ssl(self) -> bool:
        return self._config.get("scanner", {}).get("verify_ssl", False)

    @property
    def delay_between_requests(self) -> int:
        return self._config.get("scanner", {}).get("delay_between_requests", 2)

    @property
    def max_concurrent_scans(self) -> int:
        return self._config.get("scanner", {}).get("max_concurrent_scans", 3)

    # Target URLs
    @property
    def targets(self) -> Dict[str, List[str]]:
        return self._config.get("targets", {})

    # Security headers
    @property
    def security_headers(self) -> Dict[str, List[str]]:
        return self._config.get("security_headers", {})

    # Platform configurations
    @property
    def platforms(self) -> Dict[str, Any]:
        return self._config.get("platforms", {})

    # Vulnerability rules
    @property
    def vulnerability_rules(self) -> Dict[str, List[str]]:
        return self._config.get("vulnerability_rules", {})

    # Report settings
    @property
    def reports(self) -> Dict[str, Any]:
        return self._config.get("reports", {})

    # Module settings
    @property
    def modules(self) -> Dict[str, Any]:
        return self._config.get("modules", {})

    # Logging settings
    @property
    def logging_config(self) -> Dict[str, Any]:
        return self._config.get("logging", {})

    # Rate limiting
    @property
    def rate_limiting(self) -> Dict[str, Any]:
        return self._config.get("rate_limiting", {})

    # Error handling
    @property
    def error_handling(self) -> Dict[str, Any]:
        return self._config.get("error_handling", {})

    def get_platform_config(self, platform: str) -> Dict[str, Any]:
        """Get configuration for a specific platform"""
        return self.platforms.get(platform, {})

    def get_vulnerability_severity(self, vuln_type: str) -> str:
        """Determine severity level for a vulnerability type"""
        for severity, vuln_list in self.vulnerability_rules.items():
            if vuln_type in vuln_list:
                return severity
        return "info"  # Default severity

    def is_module_enabled(self, module_name: str) -> bool:
        """Check if a scanning module is enabled"""
        return self.modules.get(module_name, {}).get("enabled", True)

    def get_custom_delay(self, platform: str) -> int:
        """Get custom delay for a specific platform"""
        return self.rate_limiting.get("custom_delays", {}).get(platform, self.delay_between_requests)


# Global configuration instance
config = ScannerConfig()