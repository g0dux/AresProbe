"""
Example Custom Scanner Plugin
Demonstrates how to create a custom security scanner plugin
"""

import re
import requests
from typing import Dict, List, Any

from ..base import ScannerPlugin, PluginInfo, PluginType
from ...core.logger import Logger


class CustomScannerPlugin(ScannerPlugin):
    """
    Example custom scanner plugin for demonstration
    """
    
    def get_info(self) -> PluginInfo:
        """Get plugin information"""
        return PluginInfo(
            name="CustomScanner",
            version="1.0.0",
            description="Example custom security scanner",
            author="AresProbe Team",
            plugin_type=PluginType.SCANNER,
            dependencies=[],
            config_schema={
                "timeout": {"type": "integer", "default": 30},
                "follow_redirects": {"type": "boolean", "default": True}
            }
        )
    
    def initialize(self, config: Dict[str, Any] = None) -> bool:
        """Initialize the plugin"""
        try:
            self.config = config or {}
            self.timeout = self.config.get('timeout', 30)
            self.follow_redirects = self.config.get('follow_redirects', True)
            
            self.logger.info("[*] Custom scanner plugin initialized")
            return True
        except Exception as e:
            self.logger.error(f"[-] Failed to initialize custom scanner: {e}")
            return False
    
    def scan(self, target: str, **kwargs) -> List[Dict[str, Any]]:
        """Perform custom security scan"""
        vulnerabilities = []
        
        try:
            # Example: Check for common security headers
            response = requests.get(
                target, 
                timeout=self.timeout,
                allow_redirects=self.follow_redirects
            )
            
            # Check for missing security headers
            security_headers = {
                'X-Content-Type-Options': 'nosniff',
                'X-Frame-Options': 'DENY',
                'X-XSS-Protection': '1; mode=block',
                'Strict-Transport-Security': 'max-age=31536000',
                'Content-Security-Policy': 'default-src \'self\''
            }
            
            missing_headers = []
            for header, expected_value in security_headers.items():
                if header not in response.headers:
                    missing_headers.append(header)
            
            if missing_headers:
                vulnerabilities.append({
                    'type': 'missing_security_headers',
                    'severity': 'medium',
                    'description': f'Missing security headers: {", ".join(missing_headers)}',
                    'url': target,
                    'details': {
                        'missing_headers': missing_headers,
                        'status_code': response.status_code
                    }
                })
            
            # Example: Check for sensitive information disclosure
            sensitive_patterns = [
                r'password\s*[:=]\s*["\']?[^"\'\s]+["\']?',
                r'api[_-]?key\s*[:=]\s*["\']?[^"\'\s]+["\']?',
                r'secret\s*[:=]\s*["\']?[^"\'\s]+["\']?',
                r'token\s*[:=]\s*["\']?[^"\'\s]+["\']?'
            ]
            
            for pattern in sensitive_patterns:
                matches = re.findall(pattern, response.text, re.IGNORECASE)
                if matches:
                    vulnerabilities.append({
                        'type': 'sensitive_data_disclosure',
                        'severity': 'high',
                        'description': f'Potential sensitive data disclosure found: {pattern}',
                        'url': target,
                        'details': {
                            'pattern': pattern,
                            'matches': matches[:5],  # Limit to first 5 matches
                            'status_code': response.status_code
                        }
                    })
            
            # Example: Check for error pages with stack traces
            if response.status_code >= 500:
                error_indicators = [
                    'stack trace',
                    'exception',
                    'error in',
                    'fatal error',
                    'internal server error'
                ]
                
                found_indicators = []
                for indicator in error_indicators:
                    if indicator.lower() in response.text.lower():
                        found_indicators.append(indicator)
                
                if found_indicators:
                    vulnerabilities.append({
                        'type': 'error_page_disclosure',
                        'severity': 'medium',
                        'description': f'Error page with potential information disclosure',
                        'url': target,
                        'details': {
                            'status_code': response.status_code,
                            'indicators': found_indicators
                        }
                    })
            
            self.logger.success(f"[+] Custom scan completed on {target}: {len(vulnerabilities)} vulnerabilities found")
            
        except requests.exceptions.RequestException as e:
            self.logger.error(f"[-] Request failed for {target}: {e}")
        except Exception as e:
            self.logger.error(f"[-] Custom scan failed for {target}: {e}")
        
        return vulnerabilities
