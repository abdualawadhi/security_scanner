"""
Scanner Configuration Settings
Low-Code Platform Security Scanner

Professional configuration management for enterprise-grade security scanning.

Author: Bachelor Thesis Project - Low-Code Platforms Security Analysis
"""

import os
from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class ScannerConfig:
    """
    Centralized configuration for security scanner operations.
    
    This class manages all configurable parameters for the security scanner,
    supporting both programmatic configuration and environment variable overrides.
    """
    
    # Network Configuration
    request_timeout: int = 30
    max_retries: int = 3
    verify_ssl: bool = False  # For testing environments
    follow_redirects: bool = True
    max_redirects: int = 5
    
    # Concurrency Configuration
    max_concurrent_scans: int = 5
    max_concurrent_requests: int = 10
    rate_limit_delay: float = 0.5
    
    # Scanner Behavior
    enable_advanced_checks: bool = True
    enable_aggressive_scanning: bool = False
    scan_timeout: int = 300
    deep_scan: bool = False
    
    # User Agent Configuration
    user_agent: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    rotate_user_agents: bool = False
    
    # Output Configuration
    output_format: str = "html"
    output_directory: str = "./scan_results"
    verbose_logging: bool = True
    save_raw_responses: bool = False
    
    # Report Configuration
    generate_executive_summary: bool = True
    include_remediation_details: bool = True
    include_code_examples: bool = True
    include_references: bool = True
    
    # Platform-Specific Settings
    bubble_check_workflows: bool = True
    bubble_check_privacy_rules: bool = True
    outsystems_check_rest_apis: bool = True
    outsystems_check_permissions: bool = True
    airtable_check_schema: bool = True
    airtable_check_api_keys: bool = True
    
    # Security Standards Compliance
    check_owasp_top_10: bool = True
    check_cwe_compliance: bool = True
    check_pci_dss: bool = False
    check_hipaa: bool = False
    
    # Custom Headers
    custom_headers: Dict[str, str] = field(default_factory=dict)
    
    # Excluded Paths
    excluded_paths: List[str] = field(default_factory=lambda: [
        "/logout",
        "/signout",
        "/delete",
        "/remove",
    ])
    
    # Cache Configuration
    enable_caching: bool = True
    cache_ttl: int = 3600
    
    @classmethod
    def from_env(cls) -> "ScannerConfig":
        """
        Create configuration from environment variables.
        
        Environment variables should be prefixed with SCANNER_
        Example: SCANNER_REQUEST_TIMEOUT=60
        """
        config = cls()
        
        # Override with environment variables if present
        if timeout := os.getenv("SCANNER_REQUEST_TIMEOUT"):
            config.request_timeout = int(timeout)
        
        if retries := os.getenv("SCANNER_MAX_RETRIES"):
            config.max_retries = int(retries)
        
        if verify_ssl := os.getenv("SCANNER_VERIFY_SSL"):
            config.verify_ssl = verify_ssl.lower() in ("true", "1", "yes")
        
        if user_agent := os.getenv("SCANNER_USER_AGENT"):
            config.user_agent = user_agent
        
        if output_format := os.getenv("SCANNER_OUTPUT_FORMAT"):
            config.output_format = output_format
        
        if output_dir := os.getenv("SCANNER_OUTPUT_DIRECTORY"):
            config.output_directory = output_dir
        
        if verbose := os.getenv("SCANNER_VERBOSE_LOGGING"):
            config.verbose_logging = verbose.lower() in ("true", "1", "yes")
        
        return config
    
    def validate(self) -> List[str]:
        """
        Validate configuration settings.
        
        Returns:
            List of validation error messages (empty if valid)
        """
        errors = []
        
        if self.request_timeout <= 0:
            errors.append("request_timeout must be positive")
        
        if self.max_retries < 0:
            errors.append("max_retries must be non-negative")
        
        if self.max_concurrent_scans <= 0:
            errors.append("max_concurrent_scans must be positive")
        
        if self.scan_timeout <= 0:
            errors.append("scan_timeout must be positive")
        
        if self.output_format not in ["json", "yaml", "html", "text"]:
            errors.append(f"invalid output_format: {self.output_format}")
        
        if self.rate_limit_delay < 0:
            errors.append("rate_limit_delay must be non-negative")
        
        return errors


@dataclass
class SecurityStandards:
    """
    Security standards and compliance requirements configuration.
    
    Manages thresholds and requirements for various security standards.
    """
    
    # OWASP ASVS Levels
    asvs_level: int = 2  # Level 1, 2, or 3
    
    # Minimum Security Scores
    min_security_header_score: float = 0.75
    min_ssl_tls_score: float = 0.80
    min_cookie_security_score: float = 0.70
    
    # Password Policy Requirements
    min_password_length: int = 12
    require_password_complexity: bool = True
    
    # Session Management
    max_session_timeout: int = 3600
    require_session_regeneration: bool = True
    
    # TLS/SSL Requirements
    min_tls_version: str = "TLSv1.2"
    allowed_cipher_suites: List[str] = field(default_factory=lambda: [
        "TLS_AES_128_GCM_SHA256",
        "TLS_AES_256_GCM_SHA384",
        "TLS_CHACHA20_POLY1305_SHA256",
    ])
    
    # CSP Requirements
    require_csp: bool = True
    csp_min_directives: int = 3
    
    # CORS Requirements
    check_cors_misconfigurations: bool = True
    
    def get_severity_threshold(self, level: str) -> bool:
        """
        Check if a severity level meets the threshold for reporting.
        
        Args:
            level: Severity level (Critical, High, Medium, Low, Info)
            
        Returns:
            True if the severity meets reporting threshold
        """
        severity_map = {
            "Critical": 4,
            "High": 3,
            "Medium": 2,
            "Low": 1,
            "Info": 0,
        }
        
        threshold_map = {
            1: 2,  # Level 1: Report Medium and above
            2: 1,  # Level 2: Report Low and above
            3: 0,  # Level 3: Report all including Info
        }
        
        severity_value = severity_map.get(level, 0)
        threshold = threshold_map.get(self.asvs_level, 1)
        
        return severity_value >= threshold


# Default configuration instance for use throughout the application
config = ScannerConfig()
