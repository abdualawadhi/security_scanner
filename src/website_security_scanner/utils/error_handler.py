#!/usr/bin/env python3
"""
Comprehensive Error Handling Utility

Provides standardized error handling, sanitization, and logging
for the security scanner components.

Author: Bachelor Thesis Project - Low-Code Platforms Security Analysis
"""

import logging
import traceback
import hashlib
from typing import Dict, Any, Optional, Union
from enum import Enum


class ErrorSeverity(Enum):
    """Error severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ErrorCategory(Enum):
    """Error categories for better classification."""
    NETWORK = "network"
    PARSING = "parsing"
    VALIDATION = "validation"
    AUTHENTICATION = "authentication"
    RATE_LIMIT = "rate_limit"
    SYSTEM = "system"
    SECURITY = "security"
    BUSINESS_LOGIC = "business_logic"


class SecurityScannerError(Exception):
    """Base exception for security scanner errors."""
    
    def __init__(self, message: str, category: ErrorCategory = ErrorCategory.SYSTEM,
                 severity: ErrorSeverity = ErrorSeverity.MEDIUM,
                 error_code: Optional[str] = None,
                 details: Optional[Dict[str, Any]] = None):
        super().__init__(message)
        self.message = message
        self.category = category
        self.severity = severity
        self.error_code = error_code
        self.details = details or {}
        self.traceback_hash = self._generate_traceback_hash()
    
    def _generate_traceback_hash(self) -> str:
        """Generate a hash of the traceback for correlation."""
        try:
            tb_str = ''.join(traceback.format_tb(self.__traceback__))
            return hashlib.md5(tb_str.encode()).hexdigest()[:8]
        except Exception:
            return "unknown"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert error to dictionary for logging/serialization."""
        return {
            'error_type': self.__class__.__name__,
            'message': self.message,
            'category': self.category.value,
            'severity': self.severity.value,
            'error_code': self.error_code,
            'details': self.details,
            'traceback_hash': self.traceback_hash
        }


class ValidationError(SecurityScannerError):
    """Raised when input validation fails."""
    
    def __init__(self, message: str, field: Optional[str] = None, **kwargs):
        super().__init__(
            message,
            category=ErrorCategory.VALIDATION,
            severity=ErrorSeverity.MEDIUM,
            **kwargs
        )
        self.field = field


class NetworkError(SecurityScannerError):
    """Raised when network operations fail."""
    
    def __init__(self, message: str, url: Optional[str] = None, 
                 status_code: Optional[int] = None, **kwargs):
        super().__init__(
            message,
            category=ErrorCategory.NETWORK,
            severity=ErrorSeverity.HIGH,
            **kwargs
        )
        self.url = url
        self.status_code = status_code


class RateLimitError(SecurityScannerError):
    """Raised when rate limits are exceeded."""
    
    def __init__(self, message: str = "Rate limit exceeded", **kwargs):
        super().__init__(
            message,
            category=ErrorCategory.RATE_LIMIT,
            severity=ErrorSeverity.MEDIUM,
            error_code="RATE_LIMIT_EXCEEDED",
            **kwargs
        )


class SecurityError(SecurityScannerError):
    """Raised when security violations are detected."""
    
    def __init__(self, message: str, **kwargs):
        super().__init__(
            message,
            category=ErrorCategory.SECURITY,
            severity=ErrorSeverity.HIGH,
            **kwargs
        )


class ErrorHandler:
    """
    Comprehensive error handling utility for the security scanner.
    """
    
    def __init__(self, logger_name: str = __name__):
        self.logger = logging.getLogger(logger_name)
        self.error_counts = {}
        self.error_thresholds = {
            ErrorSeverity.CRITICAL: 1,
            ErrorSeverity.HIGH: 5,
            ErrorSeverity.MEDIUM: 20,
            ErrorSeverity.LOW: 50
        }
    
    def handle_exception(self, exception: Exception, 
                        context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Handle an exception and return a standardized error response.
        
        Args:
            exception: The exception to handle
            context: Additional context information
            
        Returns:
            Standardized error response dictionary
        """
        context = context or {}
        
        # Convert to SecurityScannerError if needed
        if not isinstance(exception, SecurityScannerError):
            scanner_error = SecurityScannerError(
                str(exception),
                category=self._categorize_exception(exception),
                severity=self._determine_severity(exception)
            )
        else:
            scanner_error = exception
        
        # Log the error
        self._log_error(scanner_error, context)
        
        # Track error counts
        self._track_error(scanner_error)
        
        # Generate error response
        error_response = self._generate_error_response(scanner_error, context)
        
        return error_response
    
    def _categorize_exception(self, exception: Exception) -> ErrorCategory:
        """Categorize a generic exception."""
        exception_type = type(exception).__name__.lower()
        
        if any(net_type in exception_type for net_type in ['connection', 'timeout', 'http']):
            return ErrorCategory.NETWORK
        elif any(parse_type in exception_type for parse_type in ['parse', 'json', 'xml']):
            return ErrorCategory.PARSING
        elif any(auth_type in exception_type for auth_type in ['auth', 'permission']):
            return ErrorCategory.AUTHENTICATION
        elif 'value' in exception_type or 'key' in exception_type:
            return ErrorCategory.VALIDATION
        else:
            return ErrorCategory.SYSTEM
    
    def _determine_severity(self, exception: Exception) -> ErrorSeverity:
        """Determine severity of a generic exception."""
        exception_type = type(exception).__name__.lower()
        
        if any(critical in exception_type for critical in ['critical', 'fatal']):
            return ErrorSeverity.CRITICAL
        elif any(high in exception_type for high in ['connection', 'timeout', 'permission']):
            return ErrorSeverity.HIGH
        elif any(medium in exception_type for medium in ['value', 'parse']):
            return ErrorSeverity.MEDIUM
        else:
            return ErrorSeverity.LOW
    
    def _log_error(self, error: SecurityScannerError, context: Dict[str, Any]):
        """Log the error with appropriate level."""
        log_message = f"{error.category.value.upper()}: {error.message}"
        
        if context:
            log_message += f" | Context: {context}"
        
        if error.error_code:
            log_message += f" | Code: {error.error_code}"
        
        # Add traceback for debugging
        if error.severity in [ErrorSeverity.CRITICAL, ErrorSeverity.HIGH]:
            log_message += f" | Traceback: {error.traceback_hash}"
        
        # Log with appropriate level
        if error.severity == ErrorSeverity.CRITICAL:
            self.logger.critical(log_message)
        elif error.severity == ErrorSeverity.HIGH:
            self.logger.error(log_message)
        elif error.severity == ErrorSeverity.MEDIUM:
            self.logger.warning(log_message)
        else:
            self.logger.info(log_message)
    
    def _track_error(self, error: SecurityScannerError):
        """Track error counts for monitoring."""
        error_key = f"{error.category.value}:{error.error_code or 'unknown'}"
        self.error_counts[error_key] = self.error_counts.get(error_key, 0) + 1
        
        # Check thresholds
        threshold = self.error_thresholds.get(error.severity, 10)
        if self.error_counts[error_key] >= threshold:
            self.logger.warning(
                f"Error threshold exceeded for {error_key}: "
                f"{self.error_counts[error_key]} occurrences"
            )
    
    def _generate_error_response(self, error: SecurityScannerError, 
                               context: Dict[str, Any]) -> Dict[str, Any]:
        """Generate a standardized error response."""
        response = {
            'success': False,
            'error': {
                'type': error.__class__.__name__,
                'message': self._sanitize_error_message(error.message),
                'category': error.category.value,
                'severity': error.severity.value,
                'error_code': error.error_code
            }
        }
        
        # Add non-sensitive details
        if error.details:
            safe_details = self._sanitize_details(error.details)
            if safe_details:
                response['error']['details'] = safe_details
        
        # Add context if provided
        if context:
            safe_context = self._sanitize_details(context)
            if safe_context:
                response['context'] = safe_context
        
        return response
    
    def _sanitize_error_message(self, message: str) -> str:
        """Sanitize error message to prevent information disclosure."""
        if not isinstance(message, str):
            return str(message)
        
        # Remove potential sensitive information with comprehensive patterns
        sensitive_patterns = [
            # Direct patterns
            r'password["\']?\s*[:=]\s*["\'][^"\']*["\']',
            r'secret["\']?\s*[:=]\s*["\'][^"\']*["\']',
            r'token["\']?\s*[:=]\s*["\'][^"\']*["\']',
            r'key["\']?\s*[:=]\s*["\'][^"\']*["\']',
            r'authorization["\']?\s*[:=]\s*["\'][^"\']*["\']',
            r'credential["\']?\s*[:=]\s*["\'][^"\']*["\']',
            r'private["\']?\s*[:=]\s*["\'][^"\']*["\']',
            r'api[_-]?key["\']?\s*[:=]\s*["\'][^"\']*["\']',
            r'access[_-]?token["\']?\s*[:=]\s*["\'][^"\']*["\']',
            
            # URL-encoded patterns
            r'password%5B[^%]*%5D%3D%5B[^%]*%5D',
            r'secret%5B[^%]*%5D%3D%5B[^%]*%5D',
            r'token%5B[^%]*%5D%3D%5B[^%]*%5D',
            r'key%5B[^%]*%5D%3D%5B[^%]*%5D',
            
            # Base64-like patterns (common for encoded secrets)
            r'["\']?[A-Za-z0-9+/]{32,}={0,2}["\']?(?=\s*(?:==|=|;|,|\)|\]|\}|\n|$))',
            
            # Hex patterns
            r'["\']?[0-9a-fA-F]{32,}["\']?(?=\s*(?:;|,|\)|\]|\}|\n|$))',
            
            # JWT tokens
            r'["\']?[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+["\']?',
            
            # AWS keys
            r'AKIA[0-9A-Z]{16}',
            r'["\']?[A-Za-z0-9/+=]{40}["\']?(?=\s*(?:aws|secret))',
            
            # Strip potential file paths that could reveal system structure
            r'[A-Za-z]:\\[^\\]*\\[^\\]*',
            r'/[^/\s]*/[^/\s]*',
            
            # Remove stack traces and debug info
            r'Traceback \(most recent call last\):.*',
            r'File ".*", line \d+.*',
            r'\s+at\s+.*\(.*:\d+\)',
        ]
        
        sanitized = message
        import re
        
        for pattern in sensitive_patterns:
            sanitized = re.sub(pattern, '[REDACTED]', sanitized, flags=re.IGNORECASE | re.DOTALL)
        
        # Additional sanitization for overly long values that might be secrets
        words = sanitized.split()
        for i, word in enumerate(words):
            if len(word) > 50 and self._looks_like_secret(word):
                words[i] = '[REDACTED]'
        
        sanitized = ' '.join(words)
        
        # Limit message length to prevent information disclosure
        if len(sanitized) > 500:
            sanitized = sanitized[:500] + '...'
        
        return sanitized
    
    def _sanitize_details(self, details: Dict[str, Any]) -> Dict[str, Any]:
        """Sanitize details dictionary to remove sensitive information."""
        if not isinstance(details, dict):
            return {}
        
        sanitized = {}
        sensitive_keys = [
            'password', 'secret', 'token', 'key', 'authorization',
            'credential', 'private', 'confidential'
        ]
        
        for key, value in details.items():
            key_lower = key.lower()
            
            # Check for sensitive keys
            if any(sensitive in key_lower for sensitive in sensitive_keys):
                sanitized[key] = '[REDACTED]'
            # Check for sensitive values
            elif isinstance(value, str) and len(value) > 20:
                # Check if value looks like a secret
                if self._looks_like_secret(value):
                    sanitized[key] = '[REDACTED]'
                else:
                    sanitized[key] = value[:50] + '...' if len(value) > 50 else value
            else:
                sanitized[key] = value
        
        return sanitized
    
    def _looks_like_secret(self, value: str) -> bool:
        """Check if a string looks like a secret/key."""
        if len(value) < 10:
            return False
        
        # Check for common secret patterns
        import re
        secret_patterns = [
            r'^[a-zA-Z0-9]{20,}$',  # Long alphanumeric
            r'^[a-zA-Z0-9_-]{20,}$',  # API key format
            r'^[a-zA-Z0-9+/=]{20,}$',  # Base64-like
        ]
        
        for pattern in secret_patterns:
            if re.match(pattern, value):
                return True
        
        return False
    
    def create_error(self, message: str, category: ErrorCategory = ErrorCategory.SYSTEM,
                    severity: ErrorSeverity = ErrorSeverity.MEDIUM,
                    error_code: Optional[str] = None,
                    **details) -> SecurityScannerError:
        """Create a standardized error."""
        return SecurityScannerError(
            message=message,
            category=category,
            severity=severity,
            error_code=error_code,
            details=details
        )
    
    def validate_and_handle(self, condition: bool, message: str, 
                          category: ErrorCategory = ErrorCategory.VALIDATION,
                          field: Optional[str] = None) -> None:
        """
        Validate a condition and raise ValidationError if it fails.
        
        Args:
            condition: Condition to validate
            message: Error message if validation fails
            category: Error category
            field: Field name that failed validation
            
        Raises:
            ValidationError: If condition is False
        """
        if not condition:
            raise ValidationError(message, field=field)
    
    def safe_execute(self, func, *args, default_return=None, 
                    context: Optional[Dict[str, Any]] = None, **kwargs):
        """
        Safely execute a function and handle any exceptions.
        
        Args:
            func: Function to execute
            *args: Function arguments
            default_return: Default return value if execution fails
            context: Context for error reporting
            **kwargs: Function keyword arguments
            
        Returns:
            Function result or default_return if execution fails
        """
        try:
            return func(*args, **kwargs)
        except Exception as e:
            error_response = self.handle_exception(e, context)
            self.logger.debug(f"Safe execution failed: {error_response}")
            return default_return


# Global error handler instance
global_error_handler = ErrorHandler(__name__)


def handle_error(exception: Exception, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Global error handling function."""
    return global_error_handler.handle_exception(exception, context)


def create_error(message: str, category: ErrorCategory = ErrorCategory.SYSTEM,
                severity: ErrorSeverity = ErrorSeverity.MEDIUM,
                error_code: Optional[str] = None, **details) -> SecurityScannerError:
    """Global error creation function."""
    return global_error_handler.create_error(message, category, severity, error_code, **details)


def safe_execute(func, *args, default_return=None, 
                context: Optional[Dict[str, Any]] = None, **kwargs):
    """Global safe execution function."""
    return global_error_handler.safe_execute(func, *args, default_return, context, **kwargs)
