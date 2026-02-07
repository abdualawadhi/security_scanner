#!/usr/bin/env python3
"""
Plugin Architecture for Security Scanner

Extensible plugin system extracted from ultra_low_code_scanner.py
for adding custom vulnerability detection and analysis capabilities.

Author: Bachelor Thesis Project - Low-Code Platforms Security Analysis
"""

import os
import importlib
import inspect
from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional
from pathlib import Path


class ScannerPlugin(ABC):
    """
    Base class for scanner plugins.
    
    All plugins must inherit from this class and implement the execute method.
    """
    
    def __init__(self, name: str, description: str):
        self.name = name
        self.description = description
        self.enabled = True
        self.config = {}
    
    @abstractmethod
    def execute(self, url: str, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute plugin logic.
        
        Args:
            url: Target URL
            scan_results: Current scan results
            
        Returns:
            Plugin execution results
        """
        pass
    
    def configure(self, config: Dict[str, Any]):
        """Configure plugin with custom settings."""
        self.config = config
    
    def validate_config(self) -> bool:
        """Validate plugin configuration."""
        return True
    
    def get_info(self) -> Dict[str, Any]:
        """Get plugin information."""
        return {
            'name': self.name,
            'description': self.description,
            'enabled': self.enabled,
            'config': self.config
        }


class PluginManager:
    """
    Plugin manager for loading and executing scanner plugins.
    """
    
    def __init__(self, plugin_directory: Optional[str] = None):
        self.plugin_directory = plugin_directory or os.path.join(os.path.dirname(__file__), 'built_in')
        self.plugins: Dict[str, ScannerPlugin] = {}
        self.plugin_results: Dict[str, Any] = {}
        
        # Create plugin directory if it doesn't exist
        Path(self.plugin_directory).mkdir(parents=True, exist_ok=True)
        
        # Load built-in plugins
        self._load_built_in_plugins()
    
    def _load_built_in_plugins(self):
        """Load built-in plugins."""
        try:
            # Import built-in plugins from the same module
            self.register_plugin(AdvancedXSSPlugin())
            self.register_plugin(APIDiscoveryPlugin())
            self.register_plugin(ConfigAuditPlugin())
            self.register_plugin(SSLAnalysisPlugin())
            self.register_plugin(PerformanceAnalysisPlugin())
            
        except Exception as e:
            print(f"Warning: Could not load built-in plugins: {e}")
    
    def register_plugin(self, plugin: ScannerPlugin):
        """Register a plugin."""
        self.plugins[plugin.name] = plugin
    
    def unregister_plugin(self, name: str):
        """Unregister a plugin."""
        if name in self.plugins:
            del self.plugins[name]
    
    def enable_plugin(self, name: str):
        """Enable a plugin."""
        if name in self.plugins:
            self.plugins[name].enabled = True
    
    def disable_plugin(self, name: str):
        """Disable a plugin."""
        if name in self.plugins:
            self.plugins[name].enabled = False
    
    def execute_plugin(self, name: str, url: str, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a specific plugin."""
        if name not in self.plugins:
            return {'error': f'Plugin {name} not found'}
        
        plugin = self.plugins[name]
        if not plugin.enabled:
            return {'error': f'Plugin {name} is disabled'}
        
        try:
            result = plugin.execute(url, scan_results)
            self.plugin_results[name] = result
            return result
        except Exception as e:
            return {'error': f'Plugin {name} execution failed: {str(e)}'}
    
    def execute_all_plugins(self, url: str, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """Execute all enabled plugins."""
        results = {}
        
        for name, plugin in self.plugins.items():
            if plugin.enabled:
                try:
                    result = plugin.execute(url, scan_results)
                    results[name] = result
                    self.plugin_results[name] = result
                except Exception as e:
                    results[name] = {'error': f'Execution failed: {str(e)}'}
        
        return results
    
    def get_plugin_list(self) -> List[Dict[str, Any]]:
        """Get list of all registered plugins."""
        return [plugin.get_info() for plugin in self.plugins.values()]
    
    def get_plugin_results(self) -> Dict[str, Any]:
        """Get results from all plugin executions."""
        return self.plugin_results
    
    def clear_results(self):
        """Clear all plugin results."""
        self.plugin_results.clear()
    
    def load_external_plugins(self, directory: str):
        """Load external plugins from directory."""
        if not os.path.exists(directory):
            return
        
        for filename in os.listdir(directory):
            if filename.endswith('.py') and not filename.startswith('__'):
                module_name = filename[:-3]
                try:
                    spec = importlib.util.spec_from_file_location(
                        module_name, os.path.join(directory, filename)
                    )
                    module = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(module)
                    
                    # Look for plugin classes in the module
                    for name, obj in inspect.getmembers(module):
                        if (inspect.isclass(obj) and 
                            issubclass(obj, ScannerPlugin) and 
                            obj != ScannerPlugin):
                            plugin_instance = obj()
                            self.register_plugin(plugin_instance)
                            break
                            
                except Exception as e:
                    print(f"Warning: Could not load plugin {filename}: {e}")


# Built-in plugin implementations
class AdvancedXSSPlugin(ScannerPlugin):
    """Advanced XSS vulnerability detection plugin."""
    
    def __init__(self):
        super().__init__("advanced_xss", "Advanced XSS vulnerability detection")
    
    def execute(self, url: str, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """Execute advanced XSS detection."""
        findings = []
        
        # Look for XSS vulnerabilities in existing results
        vulnerabilities = scan_results.get('vulnerabilities', [])
        for vuln in vulnerabilities:
            if 'xss' in vuln.get('type', '').lower():
                findings.append({
                    'type': 'xss',
                    'severity': vuln.get('severity', 'Unknown'),
                    'description': vuln.get('description', ''),
                    'enhanced_analysis': True
                })
        
        return {
            'findings': findings,
            'status': 'completed',
            'count': len(findings)
        }


class APIDiscoveryPlugin(ScannerPlugin):
    """API endpoint discovery and analysis plugin."""
    
    def __init__(self):
        super().__init__("api_discovery", "API endpoint discovery and analysis")
    
    def execute(self, url: str, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """Discover and analyze API endpoints."""
        endpoints = []
        
        # Extract potential API endpoints from scan results
        content = scan_results.get('content', '')
        if content:
            import re
            # Look for API patterns
            api_patterns = [
                r'/api/[a-zA-Z0-9/_-]+',
                r'/v[0-9]+/[a-zA-Z0-9/_-]+',
                r'/rest/[a-zA-Z0-9/_-]+'
            ]
            
            for pattern in api_patterns:
                matches = re.findall(pattern, content)
                for match in matches:
                    endpoints.append({
                        'endpoint': match,
                        'method': 'GET',
                        'discovered_by': 'pattern_matching'
                    })
        
        return {
            'endpoints': endpoints,
            'status': 'completed',
            'count': len(endpoints)
        }


class ConfigAuditPlugin(ScannerPlugin):
    """Configuration security audit plugin."""
    
    def __init__(self):
        super().__init__("config_audit", "Configuration security audit")
    
    def execute(self, url: str, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """Audit configuration security."""
        issues = []
        
        # Check for configuration issues
        headers = scan_results.get('security_headers', {})
        
        if headers.get('Content-Security-Policy') == 'Missing':
            issues.append({
                'type': 'missing_csp',
                'severity': 'Medium',
                'description': 'Content Security Policy header is missing'
            })
        
        if headers.get('X-Frame-Options') == 'Missing':
            issues.append({
                'type': 'missing_xfo',
                'severity': 'Low',
                'description': 'X-Frame-Options header is missing'
            })
        
        return {
            'issues': issues,
            'status': 'completed',
            'count': len(issues)
        }


class SSLAnalysisPlugin(ScannerPlugin):
    """SSL/TLS analysis plugin."""
    
    def __init__(self):
        super().__init__("ssl_analysis", "SSL/TLS security analysis")
    
    def execute(self, url: str, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze SSL/TLS configuration."""
        ssl_info = scan_results.get('ssl_analysis', {})
        
        return {
            'ssl_info': ssl_info,
            'status': 'completed',
            'protocol': ssl_info.get('version', 'Unknown'),
            'certificate_valid': ssl_info.get('valid', False)
        }


class PerformanceAnalysisPlugin(ScannerPlugin):
    """Performance analysis plugin."""
    
    def __init__(self):
        super().__init__("performance_analysis", "Performance and response analysis")
    
    def execute(self, url: str, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze performance metrics."""
        response_time = scan_results.get('response_time', 0)
        
        return {
            'response_time': response_time,
            'status': 'completed',
            'performance_grade': self._calculate_performance_grade(response_time)
        }
    
    def _calculate_performance_grade(self, response_time: float) -> str:
        """Calculate performance grade based on response time."""
        if response_time < 200:
            return 'A'
        elif response_time < 500:
            return 'B'
        elif response_time < 1000:
            return 'C'
        else:
            return 'D'
