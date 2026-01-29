"""
Scanner Exception Classes
Low-Code Platform Security Scanner

Comprehensive exception hierarchy for professional error handling and reporting.

Author: Bachelor Thesis Project - Low-Code Platforms Security Analysis
"""

from typing import Optional, Dict, Any


class ScannerError(Exception):
    """
    Base exception class for all scanner-related errors.
    
    This provides a common base for all scanner exceptions with enhanced
    error reporting capabilities for professional debugging and logging.
    """
    
    def __init__(
        self,
        message: str,
        error_code: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None
    ):
        """
        Initialize scanner error with enhanced error information.
        
        Args:
            message: Human-readable error message
            error_code: Machine-readable error code for automated handling
            details: Additional context information about the error
        """
        self.message = message
        self.error_code = error_code or self.__class__.__name__
        self.details = details or {}
        super().__init__(self.message)
    
    def __str__(self) -> str:
        """Format error message with code and details."""
        base = f"[{self.error_code}] {self.message}"
        if self.details:
            detail_str = ", ".join(f"{k}={v}" for k, v in self.details.items())
            return f"{base} ({detail_str})"
        return base
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert exception to dictionary for structured logging.
        
        Returns:
            Dictionary representation of the error
        """
        return {
            "error_type": self.__class__.__name__,
            "error_code": self.error_code,
            "message": self.message,
            "details": self.details,
        }


class ScannerConfigurationError(ScannerError):
    """
    Raised when scanner configuration is invalid or incomplete.
    
    This error indicates issues with scanner setup, configuration parameters,
    or initialization that prevent the scanner from operating correctly.
    """
    
    def __init__(
        self,
        message: str,
        config_key: Optional[str] = None,
        expected_value: Optional[str] = None
    ):
        """
        Initialize configuration error.
        
        Args:
            message: Description of configuration error
            config_key: The configuration key that caused the error
            expected_value: Description of expected value or format
        """
        details = {}
        if config_key:
            details["config_key"] = config_key
        if expected_value:
            details["expected"] = expected_value
        
        super().__init__(
            message=message,
            error_code="CONFIG_ERROR",
            details=details
        )


class ScannerNetworkError(ScannerError):
    """
    Raised when network operations fail during scanning.
    
    This covers connection failures, DNS resolution errors, and other
    network-related issues that prevent successful HTTP communication.
    """
    
    def __init__(
        self,
        message: str,
        url: Optional[str] = None,
        status_code: Optional[int] = None,
        retry_count: int = 0
    ):
        """
        Initialize network error.
        
        Args:
            message: Description of network error
            url: The URL that failed
            status_code: HTTP status code if received
            retry_count: Number of retries attempted
        """
        details = {"retry_count": retry_count}
        if url:
            details["url"] = url
        if status_code:
            details["status_code"] = status_code
        
        super().__init__(
            message=message,
            error_code="NETWORK_ERROR",
            details=details
        )


class ScannerTimeoutError(ScannerError):
    """
    Raised when scanning operations exceed time limits.
    
    This indicates that a scan operation took longer than the configured
    timeout period and was terminated to prevent hanging.
    """
    
    def __init__(
        self,
        message: str,
        timeout_seconds: Optional[int] = None,
        operation: Optional[str] = None
    ):
        """
        Initialize timeout error.
        
        Args:
            message: Description of timeout
            timeout_seconds: The timeout limit that was exceeded
            operation: Name of the operation that timed out
        """
        details = {}
        if timeout_seconds:
            details["timeout"] = timeout_seconds
        if operation:
            details["operation"] = operation
        
        super().__init__(
            message=message,
            error_code="TIMEOUT_ERROR",
            details=details
        )


class ScannerAuthenticationError(ScannerError):
    """
    Raised when authentication or authorization fails during scanning.
    
    This covers scenarios where the scanner lacks necessary permissions
    or credentials to access target resources.
    """
    
    def __init__(
        self,
        message: str,
        auth_type: Optional[str] = None,
        required_permission: Optional[str] = None
    ):
        """
        Initialize authentication error.
        
        Args:
            message: Description of authentication failure
            auth_type: Type of authentication that failed (e.g., 'Bearer', 'Basic')
            required_permission: Permission or scope that is required
        """
        details = {}
        if auth_type:
            details["auth_type"] = auth_type
        if required_permission:
            details["required_permission"] = required_permission
        
        super().__init__(
            message=message,
            error_code="AUTH_ERROR",
            details=details
        )


class AnalysisError(ScannerError):
    """
    Raised when vulnerability analysis encounters an error.
    
    This covers errors during the analysis phase, such as parsing failures,
    invalid response formats, or analysis logic errors.
    """
    
    def __init__(
        self,
        message: str,
        analyzer: Optional[str] = None,
        analysis_type: Optional[str] = None
    ):
        """
        Initialize analysis error.
        
        Args:
            message: Description of analysis error
            analyzer: Name of analyzer that failed
            analysis_type: Type of analysis being performed
        """
        details = {}
        if analyzer:
            details["analyzer"] = analyzer
        if analysis_type:
            details["analysis_type"] = analysis_type
        
        super().__init__(
            message=message,
            error_code="ANALYSIS_ERROR",
            details=details
        )


class PlatformDetectionError(ScannerError):
    """
    Raised when platform detection fails or produces ambiguous results.
    
    This indicates issues identifying the target low-code platform,
    which may affect the selection of appropriate security checks.
    """
    
    def __init__(
        self,
        message: str,
        url: Optional[str] = None,
        detected_platforms: Optional[list] = None
    ):
        """
        Initialize platform detection error.
        
        Args:
            message: Description of detection error
            url: URL being analyzed
            detected_platforms: List of potentially detected platforms
        """
        details = {}
        if url:
            details["url"] = url
        if detected_platforms:
            details["candidates"] = detected_platforms
        
        super().__init__(
            message=message,
            error_code="PLATFORM_DETECTION_ERROR",
            details=details
        )


class ReportGenerationError(ScannerError):
    """
    Raised when report generation fails.
    
    This covers errors during the creation of scan reports, such as
    template errors, file I/O issues, or data formatting problems.
    """
    
    def __init__(
        self,
        message: str,
        report_format: Optional[str] = None,
        output_path: Optional[str] = None
    ):
        """
        Initialize report generation error.
        
        Args:
            message: Description of report error
            report_format: Format being generated (e.g., 'html', 'json')
            output_path: Intended output path for report
        """
        details = {}
        if report_format:
            details["format"] = report_format
        if output_path:
            details["output_path"] = output_path
        
        super().__init__(
            message=message,
            error_code="REPORT_ERROR",
            details=details
        )


class ValidationError(ScannerError):
    """
    Raised when input validation fails.
    
    This covers validation errors for URLs, configuration parameters,
    or other input data that doesn't meet expected formats or constraints.
    """
    
    def __init__(
        self,
        message: str,
        field: Optional[str] = None,
        value: Optional[Any] = None,
        constraint: Optional[str] = None
    ):
        """
        Initialize validation error.
        
        Args:
            message: Description of validation failure
            field: Name of field that failed validation
            value: The invalid value (if safe to include)
            constraint: Description of validation constraint
        """
        details = {}
        if field:
            details["field"] = field
        if value is not None:
            details["value"] = str(value)[:100]  # Limit length
        if constraint:
            details["constraint"] = constraint
        
        super().__init__(
            message=message,
            error_code="VALIDATION_ERROR",
            details=details
        )
