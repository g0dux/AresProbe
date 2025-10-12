"""
AresProbe Security Testing Engines
SAST, DAST, IAST, and SCA implementations
"""

import os
import re
import ast
import json
import hashlib
import subprocess
import asyncio
import time
from typing import Dict, List, Optional, Any, Tuple, Union
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urljoin, urlparse
import logging
from collections import defaultdict

import requests
from bs4 import BeautifulSoup
import xml.etree.ElementTree as ET

from .logger import Logger
from .async_engine import AsyncEngine, RequestResult


@dataclass
class SecurityFinding:
    """Security finding from testing engines"""
    id: str
    type: str  # 'sast', 'dast', 'iast', 'sca'
    severity: str  # 'critical', 'high', 'medium', 'low', 'info'
    title: str
    description: str
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    column_number: Optional[int] = None
    code_snippet: Optional[str] = None
    url: Optional[str] = None
    parameter: Optional[str] = None
    payload: Optional[str] = None
    cwe_id: Optional[str] = None
    owasp_category: Optional[str] = None
    remediation: Optional[str] = None
    false_positive: bool = False
    confidence: float = 1.0


@dataclass
class ComponentVulnerability:
    """Vulnerability in a software component"""
    component_name: str
    version: str
    vulnerability_id: str
    severity: str
    description: str
    cve_id: Optional[str] = None
    cvss_score: Optional[float] = None
    fixed_version: Optional[str] = None
    references: List[str] = field(default_factory=list)


class SASTEngine:
    """Static Application Security Testing Engine"""
    
    def __init__(self, logger: Logger):
        self.logger = logger
        self.rules: Dict[str, List[Dict]] = {}
        self.findings: List[SecurityFinding] = []
        self._load_default_rules()
    
    def _load_default_rules(self):
        """Load default SAST rules"""
        # Python security rules
        self.rules['python'] = [
            {
                'name': 'SQL Injection',
                'pattern': r'execute\s*\(\s*["\'].*%.*["\']',
                'severity': 'high',
                'description': 'Potential SQL injection vulnerability',
                'cwe': 'CWE-89',
                'owasp': 'A03:2021'
            },
            {
                'name': 'Command Injection',
                'pattern': r'(os\.system|subprocess\.call|subprocess\.run|os\.popen)',
                'severity': 'high',
                'description': 'Potential command injection vulnerability',
                'cwe': 'CWE-78',
                'owasp': 'A03:2021'
            },
            {
                'name': 'Path Traversal',
                'pattern': r'open\s*\(\s*["\'][^"\']*\.\./',
                'severity': 'medium',
                'description': 'Potential path traversal vulnerability',
                'cwe': 'CWE-22',
                'owasp': 'A01:2021'
            },
            {
                'name': 'Hardcoded Password',
                'pattern': r'password\s*=\s*["\'][^"\']+["\']',
                'severity': 'high',
                'description': 'Hardcoded password found',
                'cwe': 'CWE-798',
                'owasp': 'A07:2021'
            },
            {
                'name': 'Weak Cryptography',
                'pattern': r'hashlib\.md5|hashlib\.sha1',
                'severity': 'medium',
                'description': 'Weak cryptographic hash function used',
                'cwe': 'CWE-327',
                'owasp': 'A02:2021'
            }
        ]
        
        # JavaScript security rules
        self.rules['javascript'] = [
            {
                'name': 'XSS Vulnerability',
                'pattern': r'innerHTML\s*=.*\+.*',
                'severity': 'high',
                'description': 'Potential XSS vulnerability',
                'cwe': 'CWE-79',
                'owasp': 'A03:2021'
            },
            {
                'name': 'DOM-based XSS',
                'pattern': r'document\.location|window\.location',
                'severity': 'medium',
                'description': 'Potential DOM-based XSS vulnerability',
                'cwe': 'CWE-79',
                'owasp': 'A03:2021'
            },
            {
                'name': 'Eval Usage',
                'pattern': r'eval\s*\(',
                'severity': 'high',
                'description': 'Use of eval() function',
                'cwe': 'CWE-95',
                'owasp': 'A03:2021'
            }
        ]
        
        # PHP security rules
        self.rules['php'] = [
            {
                'name': 'SQL Injection',
                'pattern': r'mysql_query\s*\(\s*["\'].*\$',
                'severity': 'critical',
                'description': 'SQL injection vulnerability',
                'cwe': 'CWE-89',
                'owasp': 'A03:2021'
            },
            {
                'name': 'File Inclusion',
                'pattern': r'(include|require)\s*\(\s*\$',
                'severity': 'high',
                'description': 'Potential file inclusion vulnerability',
                'cwe': 'CWE-98',
                'owasp': 'A01:2021'
            },
            {
                'name': 'Command Injection',
                'pattern': r'(system|exec|shell_exec|passthru)\s*\(',
                'severity': 'high',
                'description': 'Command injection vulnerability',
                'cwe': 'CWE-78',
                'owasp': 'A03:2021'
            }
        ]
    
    def analyze_file(self, file_path: str) -> List[SecurityFinding]:
        """Analyze a single file for security issues"""
        findings = []
        file_ext = Path(file_path).suffix.lower()
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Determine language
            language = self._detect_language(file_ext, content)
            
            if language not in self.rules:
                return findings
            
            # Apply rules
            for rule in self.rules[language]:
                matches = self._apply_rule(content, rule, file_path)
                findings.extend(matches)
            
        except Exception as e:
            self.logger.error(f"[-] Error analyzing file {file_path}: {e}")
        
        return findings
    
    def analyze_directory(self, directory: str) -> List[SecurityFinding]:
        """Analyze entire directory for security issues"""
        all_findings = []
        directory_path = Path(directory)
        
        if not directory_path.exists():
            self.logger.error(f"[-] Directory not found: {directory}")
            return all_findings
        
        # Supported file extensions
        supported_extensions = {'.py', '.js', '.php', '.java', '.c', '.cpp', '.cs', '.rb', '.go'}
        
        for file_path in directory_path.rglob('*'):
            if file_path.is_file() and file_path.suffix.lower() in supported_extensions:
                # Skip certain directories
                if any(part.startswith('.') or part in {'node_modules', '__pycache__', 'vendor'} 
                       for part in file_path.parts):
                    continue
                
                file_findings = self.analyze_file(str(file_path))
                all_findings.extend(file_findings)
        
        self.logger.info(f"[+] SAST analysis completed: {len(all_findings)} findings")
        return all_findings
    
    def _detect_language(self, file_ext: str, content: str) -> str:
        """Detect programming language from file extension and content"""
        language_map = {
            '.py': 'python',
            '.js': 'javascript',
            '.php': 'php',
            '.java': 'java',
            '.c': 'c',
            '.cpp': 'cpp',
            '.cs': 'csharp',
            '.rb': 'ruby',
            '.go': 'go'
        }
        
        return language_map.get(file_ext, 'unknown')
    
    def _apply_rule(self, content: str, rule: Dict, file_path: str) -> List[SecurityFinding]:
        """Apply a single security rule to content"""
        findings = []
        lines = content.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            if re.search(rule['pattern'], line):
                finding = SecurityFinding(
                    id=self._generate_finding_id(file_path, line_num, rule['name']),
                    type='sast',
                    severity=rule['severity'],
                    title=rule['name'],
                    description=rule['description'],
                    file_path=file_path,
                    line_number=line_num,
                    code_snippet=line.strip(),
                    cwe_id=rule.get('cwe'),
                    owasp_category=rule.get('owasp')
                )
                findings.append(finding)
        
        return findings
    
    def _generate_finding_id(self, file_path: str, line_num: int, rule_name: str) -> str:
        """Generate unique finding ID"""
        content = f"{file_path}:{line_num}:{rule_name}"
        return hashlib.md5(content.encode()).hexdigest()[:16]
    
    def get_findings_summary(self) -> Dict[str, Any]:
        """Get summary of SAST findings"""
        severity_counts = defaultdict(int)
        for finding in self.findings:
            severity_counts[finding.severity] += 1
        
        return {
            'total_findings': len(self.findings),
            'severity_breakdown': dict(severity_counts),
            'files_analyzed': len(set(f.file_path for f in self.findings if f.file_path))
        }


class DASTEngine:
    """Dynamic Application Security Testing Engine"""
    
    def __init__(self, logger: Logger, async_engine: AsyncEngine):
        self.logger = logger
        self.async_engine = async_engine
        self.findings: List[SecurityFinding] = []
        self.test_payloads = self._load_test_payloads()
    
    def _load_test_payloads(self) -> Dict[str, List[str]]:
        """Load test payloads for DAST"""
        return {
            'sql_injection': [
                "' OR '1'='1",
                "' UNION SELECT NULL--",
                "'; DROP TABLE users--",
                "' OR 1=1--",
                "' AND (SELECT COUNT(*) FROM information_schema.tables)>0--"
            ],
            'xss': [
                "<script>alert('XSS')</script>",
                "javascript:alert('XSS')",
                "<img src=x onerror=alert('XSS')>",
                "'><script>alert('XSS')</script>",
                "<svg onload=alert('XSS')>"
            ],
            'command_injection': [
                "; ls",
                "| whoami",
                "& dir",
                "; cat /etc/passwd",
                "| ping -c 1 127.0.0.1"
            ],
            'path_traversal': [
                "../../../etc/passwd",
                "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
                "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
                "....//....//....//etc/passwd"
            ]
        }
    
    async def scan_url(self, base_url: str) -> List[SecurityFinding]:
        """Scan a URL for vulnerabilities"""
        self.logger.info(f"[*] Starting DAST scan of {base_url}")
        findings = []
        
        try:
            # Get initial response
            response = await self.async_engine.get(base_url)
            
            # Extract forms and parameters
            forms = self._extract_forms(response.content)
            parameters = self._extract_parameters(base_url)
            
            # Test for SQL Injection
            sql_findings = await self._test_sql_injection(base_url, forms, parameters)
            findings.extend(sql_findings)
            
            # Test for XSS
            xss_findings = await self._test_xss(base_url, forms, parameters)
            findings.extend(xss_findings)
            
            # Test for Command Injection
            cmd_findings = await self._test_command_injection(base_url, forms, parameters)
            findings.extend(cmd_findings)
            
            # Test for Path Traversal
            path_findings = await self._test_path_traversal(base_url)
            findings.extend(path_findings)
            
            # Test for Information Disclosure
            info_findings = await self._test_information_disclosure(base_url, response)
            findings.extend(info_findings)
            
            self.findings.extend(findings)
            self.logger.info(f"[+] DAST scan completed: {len(findings)} findings")
            
        except Exception as e:
            self.logger.error(f"[-] DAST scan failed: {e}")
        
        return findings
    
    def _extract_forms(self, content: bytes) -> List[Dict[str, Any]]:
        """Extract forms from HTML content"""
        forms = []
        try:
            soup = BeautifulSoup(content, 'html.parser')
            for form in soup.find_all('form'):
                form_data = {
                    'action': form.get('action', ''),
                    'method': form.get('method', 'GET').upper(),
                    'inputs': []
                }
                
                for input_tag in form.find_all(['input', 'textarea', 'select']):
                    input_data = {
                        'name': input_tag.get('name', ''),
                        'type': input_tag.get('type', 'text'),
                        'value': input_tag.get('value', '')
                    }
                    form_data['inputs'].append(input_data)
                
                forms.append(form_data)
        except Exception as e:
            self.logger.error(f"[-] Error extracting forms: {e}")
        
        return forms
    
    def _extract_parameters(self, url: str) -> List[str]:
        """Extract parameters from URL"""
        parameters = []
        try:
            parsed = urlparse(url)
            if parsed.query:
                for param in parsed.query.split('&'):
                    if '=' in param:
                        parameters.append(param.split('=')[0])
        except Exception as e:
            self.logger.error(f"[-] Error extracting parameters: {e}")
        
        return parameters
    
    async def _test_sql_injection(self, base_url: str, forms: List[Dict], parameters: List[str]) -> List[SecurityFinding]:
        """Test for SQL injection vulnerabilities"""
        findings = []
        
        for payload in self.test_payloads['sql_injection']:
            # Test URL parameters
            for param in parameters:
                test_url = f"{base_url}?{param}={payload}"
                response = await self.async_engine.get(test_url)
                
                if self._is_sql_error(response.content):
                    finding = SecurityFinding(
                        id=self._generate_dast_id(base_url, 'sql_injection', param),
                        type='dast',
                        severity='high',
                        title='SQL Injection',
                        description='SQL injection vulnerability detected',
                        url=test_url,
                        parameter=param,
                        payload=payload,
                        cwe_id='CWE-89',
                        owasp_category='A03:2021'
                    )
                    findings.append(finding)
            
            # Test form parameters
            for form in forms:
                if form['method'] == 'GET':
                    form_url = urljoin(base_url, form['action'])
                    for input_field in form['inputs']:
                        if input_field['name']:
                            test_url = f"{form_url}?{input_field['name']}={payload}"
                            response = await self.async_engine.get(test_url)
                            
                            if self._is_sql_error(response.content):
                                finding = SecurityFinding(
                                    id=self._generate_dast_id(base_url, 'sql_injection', input_field['name']),
                                    type='dast',
                                    severity='high',
                                    title='SQL Injection',
                                    description='SQL injection vulnerability detected in form',
                                    url=test_url,
                                    parameter=input_field['name'],
                                    payload=payload,
                                    cwe_id='CWE-89',
                                    owasp_category='A03:2021'
                                )
                                findings.append(finding)
        
        return findings
    
    async def _test_xss(self, base_url: str, forms: List[Dict], parameters: List[str]) -> List[SecurityFinding]:
        """Test for XSS vulnerabilities"""
        findings = []
        
        for payload in self.test_payloads['xss']:
            # Test URL parameters
            for param in parameters:
                test_url = f"{base_url}?{param}={payload}"
                response = await self.async_engine.get(test_url)
                
                if payload in response.content.decode('utf-8', errors='ignore'):
                    finding = SecurityFinding(
                        id=self._generate_dast_id(base_url, 'xss', param),
                        type='dast',
                        severity='high',
                        title='Cross-Site Scripting (XSS)',
                        description='XSS vulnerability detected',
                        url=test_url,
                        parameter=param,
                        payload=payload,
                        cwe_id='CWE-79',
                        owasp_category='A03:2021'
                    )
                    findings.append(finding)
        
        return findings
    
    async def _test_command_injection(self, base_url: str, forms: List[Dict], parameters: List[str]) -> List[SecurityFinding]:
        """Test for command injection vulnerabilities"""
        findings = []
        
        for payload in self.test_payloads['command_injection']:
            for param in parameters:
                test_url = f"{base_url}?{param}={payload}"
                response = await self.async_engine.get(test_url)
                
                if self._is_command_error(response.content):
                    finding = SecurityFinding(
                        id=self._generate_dast_id(base_url, 'command_injection', param),
                        type='dast',
                        severity='high',
                        title='Command Injection',
                        description='Command injection vulnerability detected',
                        url=test_url,
                        parameter=param,
                        payload=payload,
                        cwe_id='CWE-78',
                        owasp_category='A03:2021'
                    )
                    findings.append(finding)
        
        return findings
    
    async def _test_path_traversal(self, base_url: str) -> List[SecurityFinding]:
        """Test for path traversal vulnerabilities"""
        findings = []
        
        # Common path traversal endpoints
        endpoints = ['file', 'path', 'include', 'page', 'doc', 'document']
        
        for endpoint in endpoints:
            for payload in self.test_payloads['path_traversal']:
                test_url = f"{base_url}?{endpoint}={payload}"
                response = await self.async_engine.get(test_url)
                
                if self._is_path_traversal_success(response.content):
                    finding = SecurityFinding(
                        id=self._generate_dast_id(base_url, 'path_traversal', endpoint),
                        type='dast',
                        severity='medium',
                        title='Path Traversal',
                        description='Path traversal vulnerability detected',
                        url=test_url,
                        parameter=endpoint,
                        payload=payload,
                        cwe_id='CWE-22',
                        owasp_category='A01:2021'
                    )
                    findings.append(finding)
        
        return findings
    
    async def _test_information_disclosure(self, base_url: str, response: RequestResult) -> List[SecurityFinding]:
        """Test for information disclosure vulnerabilities"""
        findings = []
        content = response.content.decode('utf-8', errors='ignore')
        
        # Check for sensitive information in response
        sensitive_patterns = [
            (r'password\s*[:=]\s*["\'][^"\']+["\']', 'Hardcoded Password'),
            (r'api[_-]?key\s*[:=]\s*["\'][^"\']+["\']', 'API Key Exposure'),
            (r'secret\s*[:=]\s*["\'][^"\']+["\']', 'Secret Exposure'),
            (r'debug\s*[:=]\s*true', 'Debug Mode Enabled'),
            (r'stack\s*trace', 'Stack Trace Exposure'),
            (r'error\s*message.*line\s*\d+', 'Error Message with Line Numbers')
        ]
        
        for pattern, title in sensitive_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                finding = SecurityFinding(
                    id=self._generate_dast_id(base_url, 'information_disclosure', 'response'),
                    type='dast',
                    severity='medium',
                    title=title,
                    description='Sensitive information disclosed in response',
                    url=base_url,
                    cwe_id='CWE-200',
                    owasp_category='A05:2021'
                )
                findings.append(finding)
        
        return findings
    
    def _is_sql_error(self, content: bytes) -> bool:
        """Check if response contains SQL error indicators"""
        sql_errors = [
            b'mysql_fetch_array',
            b'ORA-01756',
            b'microsoft jet database',
            b'mysql_num_rows',
            b'mysql error',
            b'postgresql',
            b'sqlite3',
            b'syntax error',
            b'warning: mysql',
            b'valid mysql result'
        ]
        
        content_lower = content.lower()
        return any(error in content_lower for error in sql_errors)
    
    def _is_command_error(self, content: bytes) -> bool:
        """Check if response contains command execution error indicators"""
        cmd_errors = [
            b'command not found',
            b'syntax error',
            b'permission denied',
            b'no such file or directory',
            b'access is denied',
            b'is not recognized as an internal or external command'
        ]
        
        content_lower = content.lower()
        return any(error in content_lower for error in cmd_errors)
    
    def _is_path_traversal_success(self, content: bytes) -> bool:
        """Check if path traversal was successful"""
        success_indicators = [
            b'root:x:0:0:',
            b'[boot loader]',
            b'localhost',
            b'127.0.0.1',
            b'# This is a comment'
        ]
        
        return any(indicator in content for indicator in success_indicators)
    
    def _generate_dast_id(self, url: str, vuln_type: str, parameter: str) -> str:
        """Generate unique DAST finding ID"""
        content = f"{url}:{vuln_type}:{parameter}"
        return hashlib.md5(content.encode()).hexdigest()[:16]


class IASTEngine:
    """Interactive Application Security Testing Engine"""
    
    def __init__(self, logger: Logger):
        self.logger = logger
        self.findings: List[SecurityFinding] = []
        self.instrumented_endpoints: List[str] = []
        self.runtime_data: Dict[str, Any] = {}
    
    async def instrument_application(self, base_url: str) -> bool:
        """Instrument application for runtime analysis"""
        try:
            # This is a simplified IAST implementation
            # In a real scenario, this would involve:
            # 1. Deploying agents to the application
            # 2. Modifying application code for instrumentation
            # 3. Setting up runtime monitoring
            
            self.logger.info(f"[*] Instrumenting application at {base_url}")
            
            # Simulate instrumentation
            endpoints = await self._discover_endpoints(base_url)
            self.instrumented_endpoints = endpoints
            
            self.logger.info(f"[+] Application instrumented: {len(endpoints)} endpoints")
            return True
            
        except Exception as e:
            self.logger.error(f"[-] Failed to instrument application: {e}")
            return False
    
    async def _discover_endpoints(self, base_url: str) -> List[str]:
        """Discover application endpoints"""
        endpoints = [base_url]
        
        # Common endpoint patterns
        common_paths = [
            '/api/', '/admin/', '/login/', '/register/', '/profile/',
            '/search/', '/upload/', '/download/', '/api/users',
            '/api/products', '/api/orders', '/api/auth'
        ]
        
        # In a real implementation, this would use web crawling
        # or API discovery techniques
        for path in common_paths:
            endpoints.append(urljoin(base_url, path))
        
        return endpoints
    
    async def analyze_runtime_data(self, runtime_data: Dict[str, Any]) -> List[SecurityFinding]:
        """Analyze runtime data for security issues"""
        findings = []
        
        # Analyze SQL queries for injection
        if 'sql_queries' in runtime_data:
            sql_findings = self._analyze_sql_queries(runtime_data['sql_queries'])
            findings.extend(sql_findings)
        
        # Analyze HTTP requests/responses
        if 'http_data' in runtime_data:
            http_findings = self._analyze_http_data(runtime_data['http_data'])
            findings.extend(http_findings)
        
        # Analyze file operations
        if 'file_operations' in runtime_data:
            file_findings = self._analyze_file_operations(runtime_data['file_operations'])
            findings.extend(file_findings)
        
        self.findings.extend(findings)
        return findings
    
    def _analyze_sql_queries(self, queries: List[Dict[str, Any]]) -> List[SecurityFinding]:
        """Analyze SQL queries for vulnerabilities"""
        findings = []
        
        for query_data in queries:
            query = query_data.get('query', '')
            params = query_data.get('parameters', [])
            
            # Check for dynamic SQL construction
            if any(param in query for param in params):
                finding = SecurityFinding(
                    id=self._generate_iast_id('sql_injection', query_data.get('endpoint', '')),
                    type='iast',
                    severity='high',
                    title='Dynamic SQL Construction',
                    description='SQL query constructed dynamically with user input',
                    cwe_id='CWE-89',
                    owasp_category='A03:2021'
                )
                findings.append(finding)
        
        return findings
    
    def _analyze_http_data(self, http_data: List[Dict[str, Any]]) -> List[SecurityFinding]:
        """Analyze HTTP requests/responses for vulnerabilities"""
        findings = []
        
        for data in http_data:
            # Check for sensitive data in responses
            response_body = data.get('response_body', '')
            if self._contains_sensitive_data(response_body):
                finding = SecurityFinding(
                    id=self._generate_iast_id('information_disclosure', data.get('endpoint', '')),
                    type='iast',
                    severity='medium',
                    title='Sensitive Data Exposure',
                    description='Sensitive data exposed in HTTP response',
                    cwe_id='CWE-200',
                    owasp_category='A05:2021'
                )
                findings.append(finding)
        
        return findings
    
    def _analyze_file_operations(self, file_ops: List[Dict[str, Any]]) -> List[SecurityFinding]:
        """Analyze file operations for vulnerabilities"""
        findings = []
        
        for op in file_ops:
            file_path = op.get('path', '')
            
            # Check for path traversal
            if '../' in file_path or '..\\' in file_path:
                finding = SecurityFinding(
                    id=self._generate_iast_id('path_traversal', op.get('operation', '')),
                    type='iast',
                    severity='medium',
                    title='Path Traversal',
                    description='File operation with potential path traversal',
                    cwe_id='CWE-22',
                    owasp_category='A01:2021'
                )
                findings.append(finding)
        
        return findings
    
    def _contains_sensitive_data(self, content: str) -> bool:
        """Check if content contains sensitive data"""
        sensitive_patterns = [
            r'password\s*[:=]\s*["\'][^"\']+["\']',
            r'api[_-]?key\s*[:=]\s*["\'][^"\']+["\']',
            r'secret\s*[:=]\s*["\'][^"\']+["\']',
            r'credit[_-]?card',
            r'social[_-]?security',
            r'ssn\s*[:=]'
        ]
        
        return any(re.search(pattern, content, re.IGNORECASE) for pattern in sensitive_patterns)
    
    def _generate_iast_id(self, vuln_type: str, endpoint: str) -> str:
        """Generate unique IAST finding ID"""
        content = f"iast:{vuln_type}:{endpoint}"
        return hashlib.md5(content.encode()).hexdigest()[:16]


class SCAEngine:
    """Software Composition Analysis Engine"""
    
    def __init__(self, logger: Logger):
        self.logger = logger
        self.vulnerabilities: List[ComponentVulnerability] = []
        self.components: Dict[str, Dict[str, str]] = {}
        self.vulnerability_db = self._load_vulnerability_database()
    
    def _load_vulnerability_database(self) -> Dict[str, List[ComponentVulnerability]]:
        """Load vulnerability database"""
        # This would typically load from a real vulnerability database
        # like NVD, GitHub Security Advisories, etc.
        return {
            'log4j': [
                ComponentVulnerability(
                    component_name='log4j',
                    version='2.0.0',
                    vulnerability_id='CVE-2021-44228',
                    severity='critical',
                    description='Log4Shell - Remote code execution vulnerability',
                    cve_id='CVE-2021-44228',
                    cvss_score=10.0,
                    fixed_version='2.17.0'
                )
            ],
            'spring': [
                ComponentVulnerability(
                    component_name='spring-framework',
                    version='5.3.0',
                    vulnerability_id='CVE-2022-22965',
                    severity='high',
                    description='Spring4Shell - Remote code execution vulnerability',
                    cve_id='CVE-2022-22965',
                    cvss_score=9.8,
                    fixed_version='5.3.18'
                )
            ]
        }
    
    def scan_dependencies(self, project_path: str) -> List[ComponentVulnerability]:
        """Scan project dependencies for vulnerabilities"""
        vulnerabilities = []
        
        # Scan different package managers
        package_managers = ['requirements.txt', 'package.json', 'composer.json', 'pom.xml', 'Gemfile']
        
        for manager_file in package_managers:
            file_path = Path(project_path) / manager_file
            if file_path.exists():
                if manager_file == 'requirements.txt':
                    python_vulns = self._scan_python_dependencies(file_path)
                    vulnerabilities.extend(python_vulns)
                elif manager_file == 'package.json':
                    node_vulns = self._scan_node_dependencies(file_path)
                    vulnerabilities.extend(node_vulns)
                elif manager_file == 'composer.json':
                    php_vulns = self._scan_php_dependencies(file_path)
                    vulnerabilities.extend(php_vulns)
        
        self.vulnerabilities.extend(vulnerabilities)
        return vulnerabilities
    
    def _scan_python_dependencies(self, requirements_file: Path) -> List[ComponentVulnerability]:
        """Scan Python dependencies from requirements.txt"""
        vulnerabilities = []
        
        try:
            with open(requirements_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        # Parse package name and version
                        package_info = self._parse_python_package(line)
                        if package_info:
                            name, version = package_info
                            
                            # Check for vulnerabilities
                            if name in self.vulnerability_db:
                                for vuln in self.vulnerability_db[name]:
                                    if self._is_version_vulnerable(version, vuln.version, vuln.fixed_version):
                                        vulnerabilities.append(vuln)
        except Exception as e:
            self.logger.error(f"[-] Error scanning Python dependencies: {e}")
        
        return vulnerabilities
    
    def _scan_node_dependencies(self, package_json: Path) -> List[ComponentVulnerability]:
        """Scan Node.js dependencies from package.json"""
        vulnerabilities = []
        
        try:
            with open(package_json, 'r') as f:
                data = json.load(f)
            
            dependencies = data.get('dependencies', {})
            dev_dependencies = data.get('devDependencies', {})
            all_deps = {**dependencies, **dev_dependencies}
            
            for package_name, version_spec in all_deps.items():
                # Extract version number from version spec
                version = self._extract_version_from_spec(version_spec)
                
                # Check for vulnerabilities
                if package_name in self.vulnerability_db:
                    for vuln in self.vulnerability_db[package_name]:
                        if self._is_version_vulnerable(version, vuln.version, vuln.fixed_version):
                            vulnerabilities.append(vuln)
        except Exception as e:
            self.logger.error(f"[-] Error scanning Node.js dependencies: {e}")
        
        return vulnerabilities
    
    def _scan_php_dependencies(self, composer_json: Path) -> List[ComponentVulnerability]:
        """Scan PHP dependencies from composer.json"""
        vulnerabilities = []
        
        try:
            with open(composer_json, 'r') as f:
                data = json.load(f)
            
            require = data.get('require', {})
            require_dev = data.get('require-dev', {})
            all_deps = {**require, **require_dev}
            
            for package_name, version_spec in all_deps.items():
                version = self._extract_version_from_spec(version_spec)
                
                if package_name in self.vulnerability_db:
                    for vuln in self.vulnerability_db[package_name]:
                        if self._is_version_vulnerable(version, vuln.version, vuln.fixed_version):
                            vulnerabilities.append(vuln)
        except Exception as e:
            self.logger.error(f"[-] Error scanning PHP dependencies: {e}")
        
        return vulnerabilities
    
    def _parse_python_package(self, line: str) -> Optional[Tuple[str, str]]:
        """Parse Python package line from requirements.txt"""
        # Handle various formats: package==1.0.0, package>=1.0.0, package~=1.0.0
        parts = re.split(r'[>=<~!]', line)
        if len(parts) >= 2:
            name = parts[0].strip()
            version = parts[1].strip()
            return name, version
        return None
    
    def _extract_version_from_spec(self, version_spec: str) -> str:
        """Extract version number from version specification"""
        # Remove version specifiers like ^, ~, >=, etc.
        version = re.sub(r'[\^~>=<!\s]', '', version_spec)
        return version.strip()
    
    def _is_version_vulnerable(self, current_version: str, vuln_version: str, fixed_version: str) -> bool:
        """Check if current version is vulnerable"""
        # Simplified version comparison
        # In a real implementation, this would use proper semantic versioning
        try:
            current_parts = [int(x) for x in current_version.split('.')]
            vuln_parts = [int(x) for x in vuln_version.split('.')]
            fixed_parts = [int(x) for x in fixed_version.split('.')]
            
            # Check if current version is between vulnerable and fixed versions
            return (current_parts >= vuln_parts and current_parts < fixed_parts)
        except:
            return False
    
    def get_vulnerability_summary(self) -> Dict[str, Any]:
        """Get summary of SCA vulnerabilities"""
        severity_counts = defaultdict(int)
        for vuln in self.vulnerabilities:
            severity_counts[vuln.severity] += 1
        
        return {
            'total_vulnerabilities': len(self.vulnerabilities),
            'severity_breakdown': dict(severity_counts),
            'components_scanned': len(self.components)
        }


class SecurityTestingEngines:
    """Main class combining all security testing engines"""
    
    def __init__(self, logger: Optional[Logger] = None, async_engine: Optional[AsyncEngine] = None):
        self.logger = logger or Logger()
        self.async_engine = async_engine or AsyncEngine()
        
        # Initialize engines
        self.sast = SASTEngine(self.logger)
        self.dast = DASTEngine(self.logger, self.async_engine)
        self.iast = IASTEngine(self.logger)
        self.sca = SCAEngine(self.logger)
    
    async def run_comprehensive_scan(self, target: str, scan_types: List[str] = None) -> Dict[str, List[SecurityFinding]]:
        """Run comprehensive security scan using multiple engines"""
        if scan_types is None:
            scan_types = ['sast', 'dast', 'sca']
        
        results = {}
        
        self.logger.info(f"[*] Starting comprehensive security scan of {target}")
        
        # Determine if target is URL or file path
        is_url = target.startswith(('http://', 'https://'))
        
        if 'sast' in scan_types and not is_url:
            self.logger.info("[*] Running SAST analysis...")
            sast_findings = self.sast.analyze_directory(target)
            results['sast'] = sast_findings
        
        if 'dast' in scan_types and is_url:
            self.logger.info("[*] Running DAST analysis...")
            dast_findings = await self.dast.scan_url(target)
            results['dast'] = dast_findings
        
        if 'iast' in scan_types and is_url:
            self.logger.info("[*] Running IAST analysis...")
            if await self.iast.instrument_application(target):
                # In a real implementation, this would collect runtime data
                runtime_data = {}  # Placeholder
                iast_findings = await self.iast.analyze_runtime_data(runtime_data)
                results['iast'] = iast_findings
        
        if 'sca' in scan_types:
            self.logger.info("[*] Running SCA analysis...")
            sca_vulnerabilities = self.sca.scan_dependencies(target)
            # Convert SCA vulnerabilities to SecurityFinding format
            sca_findings = []
            for vuln in sca_vulnerabilities:
                finding = SecurityFinding(
                    id=f"sca_{vuln.vulnerability_id}",
                    type='sca',
                    severity=vuln.severity,
                    title=f"Vulnerable Component: {vuln.component_name}",
                    description=vuln.description,
                    cwe_id=vuln.cve_id,
                    remediation=f"Update to version {vuln.fixed_version} or later"
                )
                sca_findings.append(finding)
            results['sca'] = sca_findings
        
        # Generate summary
        total_findings = sum(len(findings) for findings in results.values())
        self.logger.info(f"[+] Comprehensive scan completed: {total_findings} total findings")
        
        return results
    
    def get_scan_summary(self) -> Dict[str, Any]:
        """Get summary of all scan results"""
        return {
            'sast': self.sast.get_findings_summary(),
            'sca': self.sca.get_vulnerability_summary(),
            'total_engines': 4,
            'available_engines': ['sast', 'dast', 'iast', 'sca']
        }
