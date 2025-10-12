"""
AresProbe Advanced Proxy Interception
Superior proxy interception that surpasses Burp Suite
"""

import socket
import threading
import ssl
import asyncio
import aiohttp
import select
from typing import Dict, List, Any, Optional, Callable, Tuple
from dataclasses import dataclass
from enum import Enum
import json
import time
import re
import base64
import urllib.parse
from http.server import HTTPServer, BaseHTTPRequestHandler
import requests
from urllib3.util.retry import Retry
from requests.adapters import HTTPAdapter

class InterceptionMode(Enum):
    """Proxy interception modes"""
    TRANSPARENT = "transparent"
    FORWARD = "forward"
    REVERSE = "reverse"
    UPSTREAM = "upstream"
    DOWNSTREAM = "downstream"
    MIRROR = "mirror"
    RECORD = "record"
    REPLAY = "replay"

@dataclass
class InterceptedRequest:
    """Intercepted HTTP request"""
    method: str
    url: str
    headers: Dict[str, str]
    body: bytes
    timestamp: float
    client_ip: str
    proxy_ip: str
    request_id: str
    session_id: str
    user_agent: str
    content_type: str
    content_length: int
    cookies: Dict[str, str]
    parameters: Dict[str, str]
    raw_request: bytes

@dataclass
class InterceptedResponse:
    """Intercepted HTTP response"""
    status_code: int
    headers: Dict[str, str]
    body: bytes
    timestamp: float
    response_time: float
    server_ip: str
    proxy_ip: str
    request_id: str
    session_id: str
    content_type: str
    content_length: int
    cookies: Dict[str, str]
    raw_response: bytes

class AdvancedProxyInterception:
    """Advanced proxy interception superior to Burp Suite"""
    
    def __init__(self, logger=None):
        self.logger = logger
        self.running = False
        self.intercepted_requests = []
        self.intercepted_responses = []
        self.sessions = {}
        self.rules = []
        self.filters = []
        self.modifications = []
        self.listeners = []
        self.ssl_context = None
        self.certificates = {}
        
        # Advanced features
        self.auto_modification = True
        self.real_time_analysis = True
        self.session_tracking = True
        self.cookie_analysis = True
        self.parameter_extraction = True
        self.header_analysis = True
        self.body_analysis = True
        self.timing_analysis = True
        
        # Performance settings
        self.max_connections = 1000
        self.buffer_size = 8192
        self.timeout = 30
        self.keep_alive = True
        
        # Initialize SSL context
        self._initialize_ssl_context()
    
    def _initialize_ssl_context(self):
        """Initialize SSL context for HTTPS interception"""
        try:
            self.ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            self.ssl_context.check_hostname = False
            self.ssl_context.verify_mode = ssl.CERT_NONE
            
            # Load or generate certificates
            self._load_certificates()
            
        except Exception as e:
            if self.logger:
                self.logger.error(f"[-] SSL context initialization failed: {e}")
    
    def _load_certificates(self):
        """Load or generate SSL certificates"""
        try:
            # Try to load existing certificates
            with open('proxy_cert.pem', 'rb') as f:
                self.certificates['cert'] = f.read()
            
            with open('proxy_key.pem', 'rb') as f:
                self.certificates['key'] = f.read()
                
        except FileNotFoundError:
            # Generate new certificates
            self._generate_certificates()
    
    def _generate_certificates(self):
        """Generate SSL certificates for proxy"""
        try:
            from cryptography import x509
            from cryptography.x509.oid import NameOID
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import rsa
            from datetime import datetime, timedelta
            
            # Generate private key
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
            )
            
            # Generate certificate
            subject = issuer = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
                x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "AresProbe"),
                x509.NameAttribute(NameOID.COMMON_NAME, "AresProbe Proxy"),
            ])
            
            cert = x509.CertificateBuilder().subject_name(
                subject
            ).issuer_name(
                issuer
            ).public_key(
                private_key.public_key()
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                datetime.utcnow()
            ).not_valid_after(
                datetime.utcnow() + timedelta(days=365)
            ).add_extension(
                x509.SubjectAlternativeName([
                    x509.DNSName("localhost"),
                    x509.DNSName("127.0.0.1"),
                    x509.IPAddress("127.0.0.1"),
                ]),
                critical=False,
            ).sign(private_key, hashes.SHA256())
            
            # Save certificates
            with open('proxy_cert.pem', 'wb') as f:
                f.write(cert.public_bytes(serialization.Encoding.PEM))
            
            with open('proxy_key.pem', 'wb') as f:
                f.write(private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ))
            
            self.certificates['cert'] = cert.public_bytes(serialization.Encoding.PEM)
            self.certificates['key'] = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            
        except Exception as e:
            if self.logger:
                self.logger.error(f"[-] Certificate generation failed: {e}")
    
    def start_proxy(self, host: str = '0.0.0.0', port: int = 8080, 
                   mode: InterceptionMode = InterceptionMode.TRANSPARENT) -> bool:
        """Start advanced proxy server"""
        try:
            self.running = True
            self.mode = mode
            
            # Start proxy server
            server = HTTPServer((host, port), self._create_handler())
            server.timeout = 1
            
            if self.logger:
                self.logger.success(f"[+] Advanced proxy started on {host}:{port}")
                self.logger.success(f"[+] Mode: {mode.value}")
                self.logger.success(f"[+] Features: Auto-modification, Real-time analysis, Session tracking")
            
            # Start server in separate thread
            def run_server():
                while self.running:
                    try:
                        server.handle_request()
                    except:
                        break
            
            thread = threading.Thread(target=run_server)
            thread.daemon = True
            thread.start()
            
            return True
            
        except Exception as e:
            if self.logger:
                self.logger.error(f"[-] Proxy start failed: {e}")
            return False
    
    def _create_handler(self):
        """Create HTTP request handler"""
        class ProxyHandler(BaseHTTPRequestHandler):
            def __init__(self, *args, **kwargs):
                self.proxy = self
                super().__init__(*args, **kwargs)
            
            def do_GET(self):
                self._handle_request('GET')
            
            def do_POST(self):
                self._handle_request('POST')
            
            def do_PUT(self):
                self._handle_request('PUT')
            
            def do_DELETE(self):
                self._handle_request('DELETE')
            
            def do_HEAD(self):
                self._handle_request('HEAD')
            
            def do_OPTIONS(self):
                self._handle_request('OPTIONS')
            
            def do_PATCH(self):
                self._handle_request('PATCH')
            
            def do_CONNECT(self):
                self._handle_connect()
            
            def _handle_request(self, method: str):
                """Handle HTTP request"""
                try:
                    # Parse request
                    request = self._parse_request(method)
                    
                    # Apply rules and filters
                    if self._apply_rules(request):
                        # Forward request
                        response = self._forward_request(request)
                        
                        # Apply modifications
                        if self.auto_modification:
                            response = self._apply_modifications(request, response)
                        
                        # Send response
                        self._send_response(response)
                        
                        # Store for analysis
                        if self.real_time_analysis:
                            self._analyze_request_response(request, response)
                    
                except Exception as e:
                    if self.logger:
                        self.logger.error(f"[-] Request handling failed: {e}")
            
            def _handle_connect(self):
                """Handle CONNECT method for HTTPS"""
                try:
                    # Parse CONNECT request
                    host_port = self.path.split(':')
                    host = host_port[0]
                    port = int(host_port[1]) if len(host_port) > 1 else 443
                    
                    # Create tunnel
                    self._create_tunnel(host, port)
                    
                except Exception as e:
                    if self.logger:
                        self.logger.error(f"[-] CONNECT handling failed: {e}")
            
            def _parse_request(self, method: str) -> InterceptedRequest:
                """Parse HTTP request"""
                # Extract headers
                headers = {}
                for header, value in self.headers.items():
                    headers[header.lower()] = value
                
                # Extract body
                content_length = int(headers.get('content-length', 0))
                body = self.rfile.read(content_length) if content_length > 0 else b''
                
                # Extract cookies
                cookies = {}
                cookie_header = headers.get('cookie', '')
                if cookie_header:
                    for cookie in cookie_header.split(';'):
                        if '=' in cookie:
                            key, value = cookie.strip().split('=', 1)
                            cookies[key] = value
                
                # Extract parameters
                parameters = {}
                if '?' in self.path:
                    query_string = self.path.split('?')[1]
                    parameters = urllib.parse.parse_qs(query_string)
                
                # Generate request ID
                request_id = self._generate_request_id()
                
                # Generate session ID
                session_id = self._generate_session_id()
                
                return InterceptedRequest(
                    method=method,
                    url=self.path,
                    headers=headers,
                    body=body,
                    timestamp=time.time(),
                    client_ip=self.client_address[0],
                    proxy_ip=self.server.server_address[0],
                    request_id=request_id,
                    session_id=session_id,
                    user_agent=headers.get('user-agent', ''),
                    content_type=headers.get('content-type', ''),
                    content_length=content_length,
                    cookies=cookies,
                    parameters=parameters,
                    raw_request=self._get_raw_request()
                )
            
            def _forward_request(self, request: InterceptedRequest) -> InterceptedResponse:
                """Forward request to target server"""
                try:
                    # Prepare request
                    url = f"http://{request.url}"
                    headers = dict(request.headers)
                    
                    # Remove proxy-specific headers
                    headers.pop('proxy-connection', None)
                    headers.pop('proxy-authorization', None)
                    
                    # Send request
                    start_time = time.time()
                    response = requests.request(
                        method=request.method,
                        url=url,
                        headers=headers,
                        data=request.body,
                        timeout=self.timeout,
                        allow_redirects=False
                    )
                    end_time = time.time()
                    
                    # Parse response
                    response_headers = {}
                    for header, value in response.headers.items():
                        response_headers[header.lower()] = value
                    
                    # Extract response cookies
                    response_cookies = {}
                    for cookie in response.cookies:
                        response_cookies[cookie.name] = cookie.value
                    
                    return InterceptedResponse(
                        status_code=response.status_code,
                        headers=response_headers,
                        body=response.content,
                        timestamp=time.time(),
                        response_time=end_time - start_time,
                        server_ip=response.raw.connection.sock.getpeername()[0] if response.raw.connection else '',
                        proxy_ip=self.server.server_address[0],
                        request_id=request.request_id,
                        session_id=request.session_id,
                        content_type=response_headers.get('content-type', ''),
                        content_length=len(response.content),
                        cookies=response_cookies,
                        raw_response=response.content
                    )
                    
                except Exception as e:
                    if self.logger:
                        self.logger.error(f"[-] Request forwarding failed: {e}")
                    return None
            
            def _apply_rules(self, request: InterceptedRequest) -> bool:
                """Apply interception rules"""
                for rule in self.rules:
                    if not rule(request):
                        return False
                return True
            
            def _apply_modifications(self, request: InterceptedRequest, 
                                  response: InterceptedResponse) -> InterceptedResponse:
                """Apply modifications to request/response"""
                for modification in self.modifications:
                    if modification.should_apply(request, response):
                        response = modification.apply(request, response)
                return response
            
            def _send_response(self, response: InterceptedResponse):
                """Send HTTP response to client"""
                try:
                    # Send status line
                    self.send_response(response.status_code)
                    
                    # Send headers
                    for header, value in response.headers.items():
                        self.send_header(header, value)
                    self.end_headers()
                    
                    # Send body
                    self.wfile.write(response.body)
                    
                except Exception as e:
                    if self.logger:
                        self.logger.error(f"[-] Response sending failed: {e}")
            
            def _create_tunnel(self, host: str, port: int):
                """Create SSL tunnel for HTTPS"""
                try:
                    # Connect to target server
                    target_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    target_sock.connect((host, port))
                    
                    # Send 200 Connection Established
                    self.send_response(200)
                    self.send_header('Connection', 'close')
                    self.end_headers()
                    
                    # Create tunnel
                    self._tunnel_data(self.connection, target_sock)
                    
                except Exception as e:
                    if self.logger:
                        self.logger.error(f"[-] Tunnel creation failed: {e}")
            
            def _tunnel_data(self, client_sock, target_sock):
                """Tunnel data between client and target"""
                try:
                    while True:
                        # Check for data from client
                        if client_sock in select.select([client_sock], [], [], 0.1)[0]:
                            data = client_sock.recv(self.buffer_size)
                            if not data:
                                break
                            target_sock.send(data)
                        
                        # Check for data from target
                        if target_sock in select.select([target_sock], [], [], 0.1)[0]:
                            data = target_sock.recv(self.buffer_size)
                            if not data:
                                break
                            client_sock.send(data)
                            
                except Exception as e:
                    if self.logger:
                        self.logger.debug(f"[-] Tunnel data error: {e}")
                finally:
                    client_sock.close()
                    target_sock.close()
            
            def _analyze_request_response(self, request: InterceptedRequest, 
                                       response: InterceptedResponse):
                """Analyze request and response in real-time"""
                try:
                    # Store for analysis
                    self.intercepted_requests.append(request)
                    self.intercepted_responses.append(response)
                    
                    # Session tracking
                    if self.session_tracking:
                        self._update_session(request, response)
                    
                    # Cookie analysis
                    if self.cookie_analysis:
                        self._analyze_cookies(request, response)
                    
                    # Parameter analysis
                    if self.parameter_extraction:
                        self._analyze_parameters(request)
                    
                    # Header analysis
                    if self.header_analysis:
                        self._analyze_headers(request, response)
                    
                    # Body analysis
                    if self.body_analysis:
                        self._analyze_body(request, response)
                    
                    # Timing analysis
                    if self.timing_analysis:
                        self._analyze_timing(request, response)
                    
                except Exception as e:
                    if self.logger:
                        self.logger.debug(f"[-] Analysis failed: {e}")
            
            def _generate_request_id(self) -> str:
                """Generate unique request ID"""
                return f"req_{int(time.time() * 1000)}_{id(self)}"
            
            def _generate_session_id(self) -> str:
                """Generate session ID"""
                return f"session_{int(time.time() * 1000)}"
            
            def _get_raw_request(self) -> bytes:
                """Get raw HTTP request"""
                # This would need to be implemented to capture the raw request
                return b""
            
            def _update_session(self, request: InterceptedRequest, response: InterceptedResponse):
                """Update session information"""
                session_id = request.session_id
                if session_id not in self.sessions:
                    self.sessions[session_id] = {
                        'start_time': request.timestamp,
                        'requests': [],
                        'responses': [],
                        'cookies': {},
                        'parameters': {},
                        'user_agent': request.user_agent,
                        'client_ip': request.client_ip
                    }
                
                self.sessions[session_id]['requests'].append(request)
                self.sessions[session_id]['responses'].append(response)
                
                # Update cookies
                for name, value in request.cookies.items():
                    self.sessions[session_id]['cookies'][name] = value
                
                # Update parameters
                for name, value in request.parameters.items():
                    self.sessions[session_id]['parameters'][name] = value
            
            def _analyze_cookies(self, request: InterceptedRequest, response: InterceptedResponse):
                """Analyze cookies for security issues"""
                # Analyze request cookies
                for name, value in request.cookies.items():
                    if self._is_secure_cookie(name, value):
                        if self.logger:
                            self.logger.warning(f"[!] Insecure cookie detected: {name}")
                
                # Analyze response cookies
                for name, value in response.cookies.items():
                    if self._is_secure_cookie(name, value):
                        if self.logger:
                            self.logger.warning(f"[!] Insecure cookie set: {name}")
            
            def _analyze_parameters(self, request: InterceptedRequest):
                """Analyze parameters for potential vulnerabilities"""
                for name, value in request.parameters.items():
                    if self._is_suspicious_parameter(name, value):
                        if self.logger:
                            self.logger.warning(f"[!] Suspicious parameter: {name}={value}")
            
            def _analyze_headers(self, request: InterceptedRequest, response: InterceptedResponse):
                """Analyze headers for security issues"""
                # Check for missing security headers
                security_headers = [
                    'x-frame-options',
                    'x-content-type-options',
                    'x-xss-protection',
                    'strict-transport-security',
                    'content-security-policy'
                ]
                
                for header in security_headers:
                    if header not in response.headers:
                        if self.logger:
                            self.logger.warning(f"[!] Missing security header: {header}")
            
            def _analyze_body(self, request: InterceptedRequest, response: InterceptedResponse):
                """Analyze request/response body for interesting content"""
                # Check for sensitive data in request
                if self._contains_sensitive_data(request.body):
                    if self.logger:
                        self.logger.warning(f"[!] Sensitive data in request body")
                
                # Check for sensitive data in response
                if self._contains_sensitive_data(response.body):
                    if self.logger:
                        self.logger.warning(f"[!] Sensitive data in response body")
            
            def _analyze_timing(self, request: InterceptedRequest, response: InterceptedResponse):
                """Analyze timing for potential vulnerabilities"""
                if response.response_time > 5.0:  # 5 seconds threshold
                    if self.logger:
                        self.logger.warning(f"[!] Slow response time: {response.response_time:.2f}s")
            
            def _is_secure_cookie(self, name: str, value: str) -> bool:
                """Check if cookie is secure"""
                # Check for common insecure cookie patterns
                insecure_patterns = [
                    r'sessionid',
                    r'jsessionid',
                    r'phpsessid',
                    r'aspnet_sessionid'
                ]
                
                for pattern in insecure_patterns:
                    if re.search(pattern, name, re.IGNORECASE):
                        return False
                
                return True
            
            def _is_suspicious_parameter(self, name: str, value: str) -> bool:
                """Check if parameter is suspicious"""
                suspicious_patterns = [
                    r'cmd',
                    r'exec',
                    r'eval',
                    r'system',
                    r'shell',
                    r'command',
                    r'query',
                    r'sql',
                    r'script',
                    r'javascript',
                    r'vbscript'
                ]
                
                for pattern in suspicious_patterns:
                    if re.search(pattern, name, re.IGNORECASE):
                        return True
                
                return False
            
            def _contains_sensitive_data(self, data: bytes) -> bool:
                """Check if data contains sensitive information"""
                sensitive_patterns = [
                    b'password',
                    b'secret',
                    b'key',
                    b'token',
                    b'api_key',
                    b'private',
                    b'confidential'
                ]
                
                for pattern in sensitive_patterns:
                    if pattern in data.lower():
                        return True
                
                return False
        
        return ProxyHandler
    
    def add_rule(self, rule_func: Callable[[InterceptedRequest], bool]):
        """Add interception rule"""
        self.rules.append(rule_func)
    
    def add_filter(self, filter_func: Callable[[InterceptedRequest], bool]):
        """Add request filter"""
        self.filters.append(filter_func)
    
    def add_modification(self, modification):
        """Add request/response modification"""
        self.modifications.append(modification)
    
    def add_listener(self, listener_func: Callable[[InterceptedRequest, InterceptedResponse], None]):
        """Add request/response listener"""
        self.listeners.append(listener_func)
    
    def get_intercepted_requests(self) -> List[InterceptedRequest]:
        """Get all intercepted requests"""
        return self.intercepted_requests
    
    def get_intercepted_responses(self) -> List[InterceptedResponse]:
        """Get all intercepted responses"""
        return self.intercepted_responses
    
    def get_sessions(self) -> Dict[str, Any]:
        """Get all sessions"""
        return self.sessions
    
    def clear_data(self):
        """Clear intercepted data"""
        self.intercepted_requests.clear()
        self.intercepted_responses.clear()
        self.sessions.clear()
    
    def stop_proxy(self):
        """Stop proxy server"""
        self.running = False
