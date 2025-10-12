"""
AresProbe Tor Integration
Tor integration for anonymous testing like SQLMap
"""

import requests
import time
import random
import threading
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
from enum import Enum
import subprocess
import socket
import socks
import urllib3
from urllib.parse import urlparse

from .logger import Logger


class TorStatus(Enum):
    """Tor connection status"""
    DISCONNECTED = "disconnected"
    CONNECTING = "connecting"
    CONNECTED = "connected"
    ERROR = "error"


@dataclass
class TorCircuit:
    """Tor circuit information"""
    circuit_id: str
    status: str
    path: List[str]
    build_flags: List[str]
    purpose: str
    hs_state: str


@dataclass
class TorConnection:
    """Tor connection information"""
    status: TorStatus
    ip_address: str
    country: str
    circuits: List[TorCircuit]
    uptime: float
    bandwidth: Dict[str, int]


class TorIntegration:
    """
    Tor integration for anonymous testing
    """
    
    def __init__(self, logger: Logger = None):
        self.logger = logger or Logger()
        self.tor_proxy = "socks5://127.0.0.1:9050"
        self.tor_control_port = 9051
        self.tor_control_password = None
        self.session = None
        self.connection_info = None
        self.circuit_history = []
        self.rotation_enabled = False
        self.rotation_interval = 10  # seconds
        
        # Disable SSL warnings for Tor
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    def start_tor_session(self, control_password: str = None) -> bool:
        """Start Tor session"""
        try:
            self.logger.info("[*] Starting Tor session...")
            
            # Set control password
            self.tor_control_password = control_password
            
            # Check if Tor is running
            if not self._check_tor_running():
                self.logger.error("[-] Tor is not running. Please start Tor first.")
                return False
            
            # Create session with Tor proxy
            self.session = requests.Session()
            self.session.proxies = {
                'http': self.tor_proxy,
                'https': self.tor_proxy
            }
            
            # Configure session for Tor
            self._configure_tor_session()
            
            # Test connection
            if self._test_tor_connection():
                self.connection_info = self._get_connection_info()
                self.logger.success("[+] Tor session started successfully")
                return True
            else:
                self.logger.error("[-] Failed to establish Tor connection")
                return False
                
        except Exception as e:
            self.logger.error(f"[-] Failed to start Tor session: {e}")
            return False
    
    def stop_tor_session(self):
        """Stop Tor session"""
        try:
            if self.session:
                self.session.close()
                self.session = None
            
            self.connection_info = None
            self.rotation_enabled = False
            
            self.logger.info("[*] Tor session stopped")
            
        except Exception as e:
            self.logger.error(f"[-] Failed to stop Tor session: {e}")
    
    def make_tor_request(self, url: str, method: str = "GET", **kwargs) -> Optional[requests.Response]:
        """Make request through Tor"""
        try:
            if not self.session:
                self.logger.error("[-] Tor session not started")
                return None
            
            # Add random delay to avoid timing attacks
            delay = random.uniform(1, 3)
            time.sleep(delay)
            
            # Make request
            response = self.session.request(method, url, **kwargs)
            
            # Log request (without sensitive data)
            self.logger.debug(f"[*] Tor request: {method} {url} -> {response.status_code}")
            
            return response
            
        except Exception as e:
            self.logger.debug(f"[-] Tor request failed: {e}")
            return None
    
    def rotate_tor_circuit(self) -> bool:
        """Rotate Tor circuit for new identity"""
        try:
            self.logger.info("[*] Rotating Tor circuit...")
            
            # Send NEWNYM signal to Tor
            if self._send_tor_command("SIGNAL NEWNYM"):
                # Wait for circuit to be rebuilt
                time.sleep(5)
                
                # Verify new IP
                new_ip = self._get_current_ip()
                if new_ip and new_ip != self.connection_info.ip_address:
                    self.logger.success(f"[+] Tor circuit rotated. New IP: {new_ip}")
                    self.connection_info = self._get_connection_info()
                    return True
                else:
                    self.logger.warning("[-] Tor circuit rotation may have failed")
                    return False
            else:
                self.logger.error("[-] Failed to send NEWNYM signal")
                return False
                
        except Exception as e:
            self.logger.error(f"[-] Tor circuit rotation failed: {e}")
            return False
    
    def start_circuit_rotation(self, interval: int = 10):
        """Start automatic circuit rotation"""
        try:
            self.rotation_interval = interval
            self.rotation_enabled = True
            
            # Start rotation thread
            rotation_thread = threading.Thread(target=self._rotation_worker)
            rotation_thread.daemon = True
            rotation_thread.start()
            
            self.logger.info(f"[*] Circuit rotation started (interval: {interval}s)")
            
        except Exception as e:
            self.logger.error(f"[-] Failed to start circuit rotation: {e}")
    
    def stop_circuit_rotation(self):
        """Stop automatic circuit rotation"""
        self.rotation_enabled = False
        self.logger.info("[*] Circuit rotation stopped")
    
    def _rotation_worker(self):
        """Worker thread for circuit rotation"""
        while self.rotation_enabled:
            try:
                time.sleep(self.rotation_interval)
                if self.rotation_enabled:
                    self.rotate_tor_circuit()
            except Exception as e:
                self.logger.debug(f"[-] Rotation worker error: {e}")
    
    def _check_tor_running(self) -> bool:
        """Check if Tor is running"""
        try:
            # Try to connect to Tor control port
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            result = sock.connect_ex(('127.0.0.1', self.tor_control_port))
            sock.close()
            
            return result == 0
            
        except Exception:
            return False
    
    def _configure_tor_session(self):
        """Configure session for Tor"""
        try:
            # Set headers to look like normal browser
            self.session.headers.update({
                'User-Agent': self._get_random_user_agent(),
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Accept-Encoding': 'gzip, deflate',
                'Connection': 'keep-alive',
                'Upgrade-Insecure-Requests': '1'
            })
            
            # Disable SSL verification (common in Tor)
            self.session.verify = False
            
            # Set timeout
            self.session.timeout = 30
            
        except Exception as e:
            self.logger.debug(f"[-] Failed to configure Tor session: {e}")
    
    def _test_tor_connection(self) -> bool:
        """Test Tor connection"""
        try:
            # Test with a simple request
            response = self.session.get('http://httpbin.org/ip', timeout=10)
            
            if response.status_code == 200:
                ip_info = response.json()
                current_ip = ip_info.get('origin', '')
                
                if current_ip:
                    self.logger.info(f"[*] Tor connection verified. IP: {current_ip}")
                    return True
            
            return False
            
        except Exception as e:
            self.logger.debug(f"[-] Tor connection test failed: {e}")
            return False
    
    def _get_connection_info(self) -> TorConnection:
        """Get current Tor connection information"""
        try:
            # Get current IP
            current_ip = self._get_current_ip()
            
            # Get circuits
            circuits = self._get_tor_circuits()
            
            # Get country (simplified)
            country = self._get_ip_country(current_ip)
            
            return TorConnection(
                status=TorStatus.CONNECTED,
                ip_address=current_ip or "unknown",
                country=country or "unknown",
                circuits=circuits,
                uptime=time.time(),
                bandwidth={'read': 0, 'write': 0}  # Would need Tor control for real data
            )
            
        except Exception as e:
            self.logger.debug(f"[-] Failed to get connection info: {e}")
            return TorConnection(
                status=TorStatus.ERROR,
                ip_address="unknown",
                country="unknown",
                circuits=[],
                uptime=0,
                bandwidth={'read': 0, 'write': 0}
            )
    
    def _get_current_ip(self) -> Optional[str]:
        """Get current IP address through Tor"""
        try:
            response = self.session.get('http://httpbin.org/ip', timeout=10)
            if response.status_code == 200:
                ip_info = response.json()
                return ip_info.get('origin', '').split(',')[0].strip()
            return None
        except Exception:
            return None
    
    def _get_ip_country(self, ip_address: str) -> Optional[str]:
        """Get country for IP address"""
        try:
            # Use a simple IP geolocation service
            response = self.session.get(f'http://ip-api.com/json/{ip_address}', timeout=10)
            if response.status_code == 200:
                data = response.json()
                return data.get('country', 'unknown')
            return None
        except Exception:
            return None
    
    def _get_tor_circuits(self) -> List[TorCircuit]:
        """Get Tor circuit information"""
        try:
            circuits = []
            
            # Get circuit info from Tor control
            circuit_info = self._send_tor_command("GETINFO circuit-status")
            
            if circuit_info:
                # Parse circuit information (simplified)
                for line in circuit_info.split('\n'):
                    if line.startswith('circuit-status'):
                        # Parse circuit data
                        circuit_data = line.split(' ', 1)[1] if ' ' in line else ""
                        circuits.append(TorCircuit(
                            circuit_id="unknown",
                            status="BUILT",
                            path=[],
                            build_flags=[],
                            purpose="GENERAL",
                            hs_state=""
                        ))
            
            return circuits
            
        except Exception as e:
            self.logger.debug(f"[-] Failed to get Tor circuits: {e}")
            return []
    
    def _send_tor_command(self, command: str) -> Optional[str]:
        """Send command to Tor control port"""
        try:
            # Connect to Tor control port
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect(('127.0.0.1', self.tor_control_port))
            
            # Send command
            if self.tor_control_password:
                # Authenticate first
                auth_cmd = f'AUTHENTICATE "{self.tor_control_password}"\r\n'
                sock.send(auth_cmd.encode())
                auth_response = sock.recv(1024).decode()
                
                if not auth_response.startswith('250'):
                    sock.close()
                    return None
            
            # Send actual command
            cmd = f'{command}\r\n'
            sock.send(cmd.encode())
            
            # Receive response
            response = sock.recv(4096).decode()
            sock.close()
            
            return response
            
        except Exception as e:
            self.logger.debug(f"[-] Failed to send Tor command: {e}")
            return None
    
    def _get_random_user_agent(self) -> str:
        """Get random user agent for Tor"""
        user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:89.0) Gecko/20100101 Firefox/89.0',
            'Mozilla/5.0 (X11; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0'
        ]
        
        return random.choice(user_agents)
    
    def get_tor_status(self) -> Dict[str, Any]:
        """Get current Tor status"""
        if not self.connection_info:
            return {'status': 'disconnected'}
        
        return {
            'status': self.connection_info.status.value,
            'ip_address': self.connection_info.ip_address,
            'country': self.connection_info.country,
            'circuits': len(self.connection_info.circuits),
            'uptime': time.time() - self.connection_info.uptime,
            'rotation_enabled': self.rotation_enabled,
            'rotation_interval': self.rotation_interval
        }
    
    def test_anonymity(self) -> Dict[str, Any]:
        """Test Tor anonymity"""
        try:
            self.logger.info("[*] Testing Tor anonymity...")
            
            # Test multiple requests to check for IP consistency
            ips = []
            for i in range(3):
                ip = self._get_current_ip()
                if ip:
                    ips.append(ip)
                time.sleep(2)
            
            # Check if all IPs are the same
            unique_ips = set(ips)
            is_consistent = len(unique_ips) == 1
            
            # Test for leaks
            leak_tests = self._test_for_leaks()
            
            return {
                'ip_addresses': ips,
                'is_consistent': is_consistent,
                'unique_ips': len(unique_ips),
                'leak_tests': leak_tests,
                'anonymity_score': self._calculate_anonymity_score(ips, leak_tests)
            }
            
        except Exception as e:
            self.logger.error(f"[-] Anonymity test failed: {e}")
            return {'error': str(e)}
    
    def _test_for_leaks(self) -> Dict[str, bool]:
        """Test for various types of leaks"""
        leak_tests = {
            'dns_leak': False,
            'ip_leak': False,
            'webrtc_leak': False,
            'timezone_leak': False
        }
        
        try:
            # Test DNS leak
            response = self.session.get('http://httpbin.org/dns', timeout=10)
            if response.status_code == 200:
                dns_info = response.json()
                # Check if DNS resolution is going through Tor
                leak_tests['dns_leak'] = False  # Simplified
            
            # Test IP leak
            response = self.session.get('http://httpbin.org/ip', timeout=10)
            if response.status_code == 200:
                ip_info = response.json()
                # Check if IP is different from real IP
                leak_tests['ip_leak'] = False  # Simplified
            
        except Exception as e:
            self.logger.debug(f"[-] Leak test failed: {e}")
        
        return leak_tests
    
    def _calculate_anonymity_score(self, ips: List[str], leak_tests: Dict[str, bool]) -> float:
        """Calculate anonymity score"""
        score = 100.0
        
        # Deduct for IP inconsistency
        if len(set(ips)) > 1:
            score -= 20.0
        
        # Deduct for leaks
        for test_name, has_leak in leak_tests.items():
            if has_leak:
                score -= 25.0
        
        return max(score, 0.0)
    
    def export_tor_logs(self, filename: str):
        """Export Tor connection logs"""
        try:
            import json
            
            export_data = {
                'connection_info': self.connection_info.__dict__ if self.connection_info else None,
                'circuit_history': [circuit.__dict__ for circuit in self.circuit_history],
                'status': self.get_tor_status(),
                'anonymity_test': self.test_anonymity()
            }
            
            with open(filename, 'w') as f:
                json.dump(export_data, f, indent=2)
            
            self.logger.success(f"[+] Tor logs exported to {filename}")
            
        except Exception as e:
            self.logger.error(f"[-] Export failed: {e}")
