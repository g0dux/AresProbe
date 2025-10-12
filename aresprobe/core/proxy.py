"""
AresProbe HTTP/HTTPS Proxy Server
Advanced proxy server for intercepting and analyzing web traffic
"""

import socket
import threading
import ssl
import base64
import re
from typing import Dict, List, Optional, Callable
from urllib.parse import urlparse, parse_qs
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from .logger import Logger


class ProxyRequest:
    """Represents an intercepted HTTP request"""
    
    def __init__(self, method: str, url: str, headers: Dict[str, str], 
                 body: str = "", version: str = "HTTP/1.1"):
        self.method = method
        self.url = url
        self.headers = headers
        self.body = body
        self.version = version
        self.timestamp = None
        self.response = None
    
    def to_dict(self) -> Dict:
        """Convert request to dictionary"""
        return {
            'method': self.method,
            'url': self.url,
            'headers': self.headers,
            'body': self.body,
            'version': self.version,
            'timestamp': self.timestamp
        }


class ProxyResponse:
    """Represents an HTTP response"""
    
    def __init__(self, status_code: int, headers: Dict[str, str], 
                 body: str = "", version: str = "HTTP/1.1"):
        self.status_code = status_code
        self.headers = headers
        self.body = body
        self.version = version
        self.timestamp = None
    
    def to_dict(self) -> Dict:
        """Convert response to dictionary"""
        return {
            'status_code': self.status_code,
            'headers': self.headers,
            'body': self.body,
            'version': self.version,
            'timestamp': self.timestamp
        }


class ProxyServer:
    """
    Advanced HTTP/HTTPS proxy server for traffic interception and analysis
    """
    
    def __init__(self, port: int = 8080, logger: Logger = None):
        self.port = port
        self.logger = logger or Logger()
        self.socket = None
        self.running = False
        self.threads = []
        self.request_handlers = []
        self.response_handlers = []
        self.intercepted_requests = []
        self.intercepted_responses = []
        
        # SSL context for HTTPS
        self.ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        self.ssl_context.check_hostname = False
        self.ssl_context.verify_mode = ssl.CERT_NONE
        
        # Session for making requests
        self.session = requests.Session()
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
    
    def add_request_handler(self, handler: Callable[[ProxyRequest], None]):
        """Add a request handler function"""
        self.request_handlers.append(handler)
    
    def add_response_handler(self, handler: Callable[[ProxyResponse], None]):
        """Add a response handler function"""
        self.response_handlers.append(handler)
    
    def start(self):
        """Start the proxy server"""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket.bind(('0.0.0.0', self.port))
            self.socket.listen(100)
            self.running = True
            
            self.logger.info(f"[*] Proxy server listening on port {self.port}")
            
            # Start main server loop in a separate thread
            server_thread = threading.Thread(target=self._server_loop, daemon=True)
            server_thread.start()
            self.threads.append(server_thread)
            
        except Exception as e:
            self.logger.error(f"[-] Failed to start proxy server: {e}")
            raise
    
    def stop(self):
        """Stop the proxy server"""
        self.running = False
        if self.socket:
            self.socket.close()
        
        # Wait for threads to finish
        for thread in self.threads:
            thread.join(timeout=1)
        
        self.logger.info("[*] Proxy server stopped")
    
    def _server_loop(self):
        """Main server loop for handling connections"""
        while self.running:
            try:
                client_socket, addr = self.socket.accept()
                client_thread = threading.Thread(
                    target=self._handle_client,
                    args=(client_socket, addr),
                    daemon=True
                )
                client_thread.start()
                self.threads.append(client_thread)
                
            except Exception as e:
                if self.running:
                    self.logger.error(f"[-] Error accepting connection: {e}")
    
    def _handle_client(self, client_socket: socket.socket, addr):
        """Handle a client connection"""
        try:
            # Read the request
            request_data = client_socket.recv(4096).decode('utf-8', errors='ignore')
            if not request_data:
                return
            
            # Parse the request
            request = self._parse_request(request_data)
            if not request:
                return
            
            # Handle CONNECT method for HTTPS
            if request.method == 'CONNECT':
                self._handle_connect(client_socket, request)
            else:
                self._handle_http_request(client_socket, request)
                
        except Exception as e:
            self.logger.error(f"[-] Error handling client {addr}: {e}")
        finally:
            client_socket.close()
    
    def _parse_request(self, request_data: str) -> Optional[ProxyRequest]:
        """Parse HTTP request data"""
        try:
            lines = request_data.split('\r\n')
            if not lines:
                return None
            
            # Parse request line
            request_line = lines[0].split()
            if len(request_line) < 3:
                return None
            
            method, url, version = request_line[0], request_line[1], request_line[2]
            
            # Parse headers
            headers = {}
            body_start = 0
            for i, line in enumerate(lines[1:], 1):
                if line == '':
                    body_start = i + 1
                    break
                if ':' in line:
                    key, value = line.split(':', 1)
                    headers[key.strip().lower()] = value.strip()
            
            # Parse body
            body = '\r\n'.join(lines[body_start:]) if body_start < len(lines) else ''
            
            return ProxyRequest(method, url, headers, body, version)
            
        except Exception as e:
            self.logger.error(f"[-] Error parsing request: {e}")
            return None
    
    def _handle_connect(self, client_socket: socket.socket, request: ProxyRequest):
        """Handle HTTPS CONNECT requests"""
        try:
            # Extract host and port from URL
            host_port = request.url.split(':')
            host = host_port[0]
            port = int(host_port[1]) if len(host_port) > 1 else 443
            
            # Connect to target server
            target_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            target_socket.connect((host, port))
            
            # Send 200 Connection established
            client_socket.send(b'HTTP/1.1 200 Connection established\r\n\r\n')
            
            # Start tunneling
            self._tunnel_data(client_socket, target_socket)
            
        except Exception as e:
            self.logger.error(f"[-] Error handling CONNECT: {e}")
            client_socket.send(b'HTTP/1.1 500 Internal Server Error\r\n\r\n')
        finally:
            client_socket.close()
    
    def _handle_http_request(self, client_socket: socket.socket, request: ProxyRequest):
        """Handle regular HTTP requests"""
        try:
            # Process request through handlers
            for handler in self.request_handlers:
                try:
                    handler(request)
                except Exception as e:
                    self.logger.error(f"[-] Error in request handler: {e}")
            
            # Store intercepted request
            self.intercepted_requests.append(request)
            
            # Forward request to target server
            response = self._forward_request(request)
            
            # Process response through handlers
            for handler in self.response_handlers:
                try:
                    handler(response)
                except Exception as e:
                    self.logger.error(f"[-] Error in response handler: {e}")
            
            # Store intercepted response
            self.intercepted_responses.append(response)
            
            # Send response to client
            self._send_response(client_socket, response)
            
        except Exception as e:
            self.logger.error(f"[-] Error handling HTTP request: {e}")
            error_response = ProxyResponse(500, {}, "Internal Server Error")
            self._send_response(client_socket, error_response)
    
    def _forward_request(self, request: ProxyRequest) -> ProxyResponse:
        """Forward request to target server and return response"""
        try:
            # Parse URL
            parsed_url = urlparse(request.url)
            if not parsed_url.scheme:
                # Assume HTTP if no scheme
                url = f"http://{request.url}"
            else:
                url = request.url
            
            # Prepare headers
            headers = dict(request.headers)
            headers.pop('proxy-connection', None)
            headers.pop('connection', None)
            
            # Make request
            response = self.session.request(
                method=request.method,
                url=url,
                headers=headers,
                data=request.body if request.body else None,
                allow_redirects=False,
                verify=False,
                timeout=30
            )
            
            # Create response object
            proxy_response = ProxyResponse(
                status_code=response.status_code,
                headers=dict(response.headers),
                body=response.text,
                version="HTTP/1.1"
            )
            
            return proxy_response
            
        except Exception as e:
            self.logger.error(f"[-] Error forwarding request: {e}")
            return ProxyResponse(500, {}, f"Error: {str(e)}")
    
    def _tunnel_data(self, client_socket: socket.socket, target_socket: socket.socket):
        """Tunnel data between client and target for HTTPS"""
        def forward_data(source, destination):
            try:
                while True:
                    data = source.recv(4096)
                    if not data:
                        break
                    destination.send(data)
            except:
                pass
            finally:
                source.close()
                destination.close()
        
        # Start bidirectional tunneling
        client_to_target = threading.Thread(
            target=forward_data, 
            args=(client_socket, target_socket),
            daemon=True
        )
        target_to_client = threading.Thread(
            target=forward_data,
            args=(target_socket, client_socket),
            daemon=True
        )
        
        client_to_target.start()
        target_to_client.start()
        
        # Wait for either thread to finish
        client_to_target.join()
        target_to_client.join()
    
    def _send_response(self, client_socket: socket.socket, response: ProxyResponse):
        """Send HTTP response to client"""
        try:
            # Build response
            response_line = f"{response.version} {response.status_code} OK\r\n"
            headers = "\r\n".join([f"{k}: {v}" for k, v in response.headers.items()])
            if headers:
                headers += "\r\n"
            
            response_data = f"{response_line}{headers}\r\n{response.body}"
            client_socket.send(response_data.encode('utf-8'))
            
        except Exception as e:
            self.logger.error(f"[-] Error sending response: {e}")
    
    def get_intercepted_requests(self) -> List[ProxyRequest]:
        """Get all intercepted requests"""
        return self.intercepted_requests.copy()
    
    def get_intercepted_responses(self) -> List[ProxyResponse]:
        """Get all intercepted responses"""
        return self.intercepted_responses.copy()
    
    def clear_intercepted_data(self):
        """Clear all intercepted data"""
        self.intercepted_requests.clear()
        self.intercepted_responses.clear()
    
    def is_running(self) -> bool:
        """Check if proxy server is running"""
        return self.running
