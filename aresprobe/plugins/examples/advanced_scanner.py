"""
Advanced Scanner Plugin Example
Demonstrates how to create custom vulnerability scanners for AresProbe
"""

import re
import time
from typing import Dict, List, Any
import requests

from ..base import ScannerPlugin, PluginInfo, PluginType, PluginPriority


class AdvancedScannerPlugin(ScannerPlugin):
    """
    Advanced vulnerability scanner plugin with custom detection techniques
    """
    
    def get_plugin_info(self) -> PluginInfo:
        """Return plugin information"""
        return PluginInfo(
            name="Advanced Scanner",
            version="1.0.0",
            description="Advanced vulnerability scanner with custom detection techniques",
            author="AresProbe Team",
            plugin_type=PluginType.SCANNER,
            priority=PluginPriority.HIGH,
            dependencies=[]
        )
    
    def initialize(self) -> bool:
        """Initialize the plugin"""
        try:
            self.logger.info("[*] Initializing Advanced Scanner Plugin...")
            self.session = requests.Session()
            self.session.headers.update({
                'User-Agent': 'AresProbe-AdvancedScanner/1.0'
            })
            self.initialized = True
            self.logger.success("[+] Advanced Scanner Plugin initialized")
            return True
        except Exception as e:
            self.logger.error(f"[-] Failed to initialize Advanced Scanner Plugin: {e}")
            return False
    
    def cleanup(self):
        """Cleanup plugin resources"""
        if hasattr(self, 'session'):
            self.session.close()
        self.logger.info("[*] Advanced Scanner Plugin cleaned up")
    
    def scan(self, target: str, config: Dict[str, Any]) -> Dict[str, Any]:
        """Perform advanced vulnerability scan"""
        results = {
            'target': target,
            'vulnerabilities': [],
            'scan_time': 0,
            'total_tests': 0,
            'plugin_name': self.get_name()
        }
        
        start_time = time.time()
        
        try:
            # Custom vulnerability checks
            self._check_http_methods(target, results)
            self._check_security_headers(target, results)
            self._check_information_disclosure(target, results)
            self._check_authentication_bypass(target, results)
            
            results['scan_time'] = time.time() - start_time
            self.logger.success(f"[+] Advanced scan completed in {results['scan_time']:.2f} seconds")
            
        except Exception as e:
            self.logger.error(f"[-] Advanced scan failed: {e}")
            results['error'] = str(e)
        
        return results
    
    def get_supported_vulnerabilities(self) -> List[str]:
        """Get list of supported vulnerability types"""
        return [
            'http_methods',
            'security_headers',
            'information_disclosure',
            'authentication_bypass'
        ]
    
    def _check_http_methods(self, target: str, results: Dict[str, Any]):
        """Check for dangerous HTTP methods"""
        dangerous_methods = ['PUT', 'DELETE', 'PATCH', 'TRACE', 'OPTIONS']
        
        for method in dangerous_methods:
            try:
                results['total_tests'] += 1
                response = self.session.request(method, target, timeout=10)
                
                if response.status_code not in [405, 501]:  # Method not allowed
                    vulnerability = {
                        'type': 'http_methods',
                        'severity': 'medium',
                        'description': f'Dangerous HTTP method {method} is allowed',
                        'method': method,
                        'status_code': response.status_code,
                        'confidence': 0.8
                    }
                    results['vulnerabilities'].append(vulnerability)
                    self.logger.warning(f"[!] Dangerous HTTP method {method} allowed")
                    
            except Exception as e:
                self.logger.debug(f"[-] Error checking {method}: {e}")
    
    def _check_security_headers(self, target: str, results: Dict[str, Any]):
        """Check for missing security headers"""
        security_headers = {
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': 'DENY',
            'X-XSS-Protection': '1; mode=block',
            'Strict-Transport-Security': 'max-age=31536000',
            'Content-Security-Policy': 'default-src \'self\''
        }
        
        try:
            results['total_tests'] += 1
            response = self.session.get(target, timeout=10)
            
            missing_headers = []
            for header, expected_value in security_headers.items():
                if header not in response.headers:
                    missing_headers.append(header)
            
            if missing_headers:
                vulnerability = {
                    'type': 'security_headers',
                    'severity': 'low',
                    'description': f'Missing security headers: {", ".join(missing_headers)}',
                    'missing_headers': missing_headers,
                    'confidence': 0.9
                }
                results['vulnerabilities'].append(vulnerability)
                self.logger.warning(f"[!] Missing security headers: {missing_headers}")
                
        except Exception as e:
            self.logger.debug(f"[-] Error checking security headers: {e}")
    
    def _check_information_disclosure(self, target: str, results: Dict[str, Any]):
        """Check for information disclosure"""
        sensitive_patterns = [
            r'Server:\s*([^\r\n]+)',
            r'X-Powered-By:\s*([^\r\n]+)',
            r'X-AspNet-Version:\s*([^\r\n]+)',
            r'X-AspNetMvc-Version:\s*([^\r\n]+)'
        ]
        
        try:
            results['total_tests'] += 1
            response = self.session.get(target, timeout=10)
            
            disclosed_info = []
            for pattern in sensitive_patterns:
                matches = re.findall(pattern, response.text, re.IGNORECASE)
                if matches:
                    disclosed_info.extend(matches)
            
            if disclosed_info:
                vulnerability = {
                    'type': 'information_disclosure',
                    'severity': 'low',
                    'description': f'Information disclosure detected: {", ".join(disclosed_info)}',
                    'disclosed_info': disclosed_info,
                    'confidence': 0.7
                }
                results['vulnerabilities'].append(vulnerability)
                self.logger.warning(f"[!] Information disclosure: {disclosed_info}")
                
        except Exception as e:
            self.logger.debug(f"[-] Error checking information disclosure: {e}")
    
    def _check_authentication_bypass(self, target: str, results: Dict[str, Any]):
        """Check for authentication bypass vulnerabilities"""
        bypass_payloads = [
            'admin',
            'administrator',
            'root',
            'test',
            'guest',
            'user',
            'demo'
        ]
        
        for payload in bypass_payloads:
            try:
                results['total_tests'] += 1
                
                # Test common authentication bypass techniques
                test_urls = [
                    f"{target}/admin",
                    f"{target}/administrator",
                    f"{target}/login",
                    f"{target}/auth"
                ]
                
                for test_url in test_urls:
                    response = self.session.get(test_url, timeout=10)
                    
                    # Check for admin panel or sensitive content
                    if any(keyword in response.text.lower() for keyword in ['admin', 'dashboard', 'control panel']):
                        vulnerability = {
                            'type': 'authentication_bypass',
                            'severity': 'high',
                            'description': f'Potential authentication bypass at {test_url}',
                            'url': test_url,
                            'payload': payload,
                            'confidence': 0.6
                        }
                        results['vulnerabilities'].append(vulnerability)
                        self.logger.warning(f"[!] Potential authentication bypass: {test_url}")
                        break
                        
            except Exception as e:
                self.logger.debug(f"[-] Error checking authentication bypass: {e}")
