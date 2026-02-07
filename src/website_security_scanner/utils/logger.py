"""
Professional Logging Infrastructure
Low-Code Platform Security Scanner

Enterprise-grade logging system for security scanning operations with
structured logging, multiple handlers, and contextual information.

Author: Bachelor Thesis Project - Low-Code Platforms Security Analysis
"""

import logging
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional
import json


class StructuredFormatter(logging.Formatter):
    """
    Custom formatter for structured logging output.
    
    Formats log records as JSON for easy parsing and integration with
    log aggregation systems while maintaining human readability.
    """
    
    def format(self, record: logging.LogRecord) -> str:
        """Format log record as structured JSON."""
        log_data = {
            "timestamp": datetime.utcnow().isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }
        
        # Add exception information if present
        if record.exc_info:
            log_data["exception"] = self.formatException(record.exc_info)
        
        # Add extra fields from record
        if hasattr(record, "extra_data"):
            log_data.update(record.extra_data)
        
        return json.dumps(log_data, ensure_ascii=False)


class ColoredConsoleFormatter(logging.Formatter):
    """
    Colored console formatter for enhanced terminal output readability.
    
    Uses ANSI color codes to highlight different log levels in console output.
    """
    
    COLORS = {
        "DEBUG": "\033[36m",      # Cyan
        "INFO": "\033[32m",       # Green
        "WARNING": "\033[33m",    # Yellow
        "ERROR": "\033[31m",      # Red
        "CRITICAL": "\033[35m",   # Magenta
    }
    RESET = "\033[0m"
    
    def format(self, record: logging.LogRecord) -> str:
        """Format log record with color codes."""
        color = self.COLORS.get(record.levelname, self.RESET)
        record.levelname = f"{color}{record.levelname}{self.RESET}"
        return super().format(record)


class ScannerLogger:
    """
    Professional logger manager for security scanner.
    
    Provides centralized logging configuration with multiple output handlers,
    log rotation, and contextual logging capabilities.
    """
    
    def __init__(
        self,
        name: str = "website_security_scanner",
        log_level: int = logging.INFO,
        log_dir: Optional[Path] = None,
        enable_console: bool = True,
        enable_file: bool = True,
        enable_json: bool = False,
    ):
        """
        Initialize scanner logger.
        
        Args:
            name: Logger name
            log_level: Minimum logging level
            log_dir: Directory for log files
            enable_console: Enable console output
            enable_file: Enable file output
            enable_json: Enable JSON structured logging
        """
        self.logger = logging.getLogger(name)
        self.logger.setLevel(log_level)
        self.logger.propagate = False
        
        # Clear existing handlers to avoid duplicates
        self.logger.handlers.clear()
        
        # Console Handler
        if enable_console:
            console_handler = logging.StreamHandler(sys.stdout)
            console_handler.setLevel(log_level)
            
            if sys.stdout.isatty():
                console_format = ColoredConsoleFormatter(
                    "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
                    datefmt="%Y-%m-%d %H:%M:%S"
                )
            else:
                console_format = logging.Formatter(
                    "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
                    datefmt="%Y-%m-%d %H:%M:%S"
                )
            
            console_handler.setFormatter(console_format)
            self.logger.addHandler(console_handler)
        
        # File Handler
        if enable_file and log_dir:
            log_dir = Path(log_dir)
            log_dir.mkdir(parents=True, exist_ok=True)
            
            timestamp = datetime.now().strftime("%Y%m%d")
            log_file = log_dir / f"scanner_{timestamp}.log"
            
            file_handler = logging.FileHandler(log_file, mode="a", encoding="utf-8")
            file_handler.setLevel(log_level)
            
            file_format = logging.Formatter(
                "%(asctime)s - %(name)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S"
            )
            file_handler.setFormatter(file_format)
            self.logger.addHandler(file_handler)
        
        # JSON Handler (for structured logging)
        if enable_json and log_dir:
            log_dir = Path(log_dir)
            log_dir.mkdir(parents=True, exist_ok=True)
            
            timestamp = datetime.now().strftime("%Y%m%d")
            json_log_file = log_dir / f"scanner_{timestamp}.json"
            
            json_handler = logging.FileHandler(json_log_file, mode="a", encoding="utf-8")
            json_handler.setLevel(log_level)
            json_handler.setFormatter(StructuredFormatter())
            self.logger.addHandler(json_handler)
    
    def get_logger(self) -> logging.Logger:
        """Get the configured logger instance."""
        return self.logger
    
    def log_scan_start(self, url: str, platform: str, scan_id: Optional[str] = None):
        """Log scan start with context."""
        self.logger.info(
            f"Starting security scan: URL={url}, Platform={platform}",
            extra={"extra_data": {"url": url, "platform": platform, "event": "scan_start", "scan_id": scan_id}}
        )
    
    def log_scan_complete(self, url: str, vulnerability_count: int, duration: float, scan_id: Optional[str] = None):
        """Log scan completion with metrics."""
        self.logger.info(
            f"Scan completed: URL={url}, Vulnerabilities={vulnerability_count}, Duration={duration:.2f}s",
            extra={
                "extra_data": {
                    "url": url,
                    "vulnerability_count": vulnerability_count,
                    "duration": duration,
                    "event": "scan_complete",
                    "scan_id": scan_id
                }
            }
        )
    
    def log_vulnerability_found(self, vuln_type: str, severity: str, url: str):
        """Log vulnerability discovery."""
        self.logger.warning(
            f"Vulnerability found: {vuln_type} ({severity}) at {url}",
            extra={
                "extra_data": {
                    "vuln_type": vuln_type,
                    "severity": severity,
                    "url": url,
                    "event": "vulnerability_found"
                }
            }
        )
    
    def log_error(self, error: Exception, context: Optional[dict] = None):
        """Log error with full context."""
        context = context or {}
        self.logger.error(
            f"Error occurred: {str(error)}",
            exc_info=True,
            extra={"extra_data": {"error_type": type(error).__name__, **context}}
        )


def setup_scanner_logger(
    level: int = logging.INFO,
    log_dir: Optional[str] = None,
    enable_json: bool = False
) -> logging.Logger:
    """
    Setup and configure the scanner logger.
    
    This is a convenience function for quick logger setup with sensible defaults.
    
    Args:
        level: Logging level (default: INFO)
        log_dir: Directory for log files (default: ./logs)
        enable_json: Enable JSON structured logging (default: False)
        
    Returns:
        Configured logger instance
    """
    if log_dir is None:
        log_dir = Path("./logs")
    else:
        log_dir = Path(log_dir)
    
    scanner_logger = ScannerLogger(
        log_level=level,
        log_dir=log_dir,
        enable_console=True,
        enable_file=True,
        enable_json=enable_json,
    )
    
    return scanner_logger.get_logger()


# Create a default logger instance for module-level use
_default_logger: Optional[logging.Logger] = None


def get_logger(name: Optional[str] = None) -> logging.Logger:
    """
    Get logger instance for a specific module.
    
    Args:
        name: Logger name (typically __name__ from calling module)
        
    Returns:
        Logger instance
    """
    global _default_logger
    
    if _default_logger is None:
        _default_logger = setup_scanner_logger()
    
    if name:
        return logging.getLogger(name)
    
    return _default_logger
