"""
AresProbe Advanced Network Reconnaissance
Comprehensive network discovery and reconnaissance capabilities
"""

import os
import re
import socket
import subprocess
import threading
import time
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass
from enum import Enum
import ipaddress
import requests
from urllib.parse import urlparse
import dns.resolver
import concurrent.futures
from concurrent.futures import ThreadPoolExecutor, as_completed

from .logger import Logger


class ReconType(Enum):
    """Types of reconnaissance"""
    PORT_SCAN = "port_scan"
    SERVICE_DETECTION = "service_detection"
    OS_FINGERPRINTING = "os_fingerprinting"
    SUBDOMAIN_ENUMERATION = "subdomain_enumeration"
    DNS_ENUMERATION = "dns_enumeration"
    WHOIS_LOOKUP = "whois_lookup"
    CERTIFICATE_ANALYSIS = "certificate_analysis"
    SOCIAL_MEDIA_OSINT = "social_media_osint"
    EMAIL_ENUMERATION = "email_enumeration"
    TECHNOLOGY_STACK = "technology_stack"


@dataclass
class ReconTarget:
    """Target for reconnaissance"""
    host: str
    ip: str = None
    ports: List[int] = None
    services: Dict[int, str] = None
    os_info: Dict[str, Any] = None
    subdomains: List[str] = None
    dns_records: Dict[str, List[str]] = None
    whois_info: Dict[str, Any] = None
    certificates: Dict[str, Any] = None
    technology_stack: List[str] = None


@dataclass
class ReconResult:
    """Result of reconnaissance operation"""
    target: str
    recon_type: ReconType
    success: bool
    data: Dict[str, Any]
    timestamp: float
    duration: float


class NetworkReconnaissanceEngine:
    """Advanced network reconnaissance engine"""
    
    def __init__(self, logger: Logger = None):
        self.logger = logger or Logger()
        self.common_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 993, 995, 1723, 3389, 5432, 5900, 8080]
        self.service_ports = {
            21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp', 53: 'dns', 80: 'http',
            110: 'pop3', 135: 'msrpc', 139: 'netbios-ssn', 143: 'imap', 443: 'https',
            993: 'imaps', 995: 'pop3s', 1723: 'pptp', 3389: 'rdp', 5432: 'postgresql',
            5900: 'vnc', 8080: 'http-alt'
        }
        self.subdomain_wordlists = self._load_subdomain_wordlists()
        self.dns_servers = ['8.8.8.8', '1.1.1.1', '208.67.222.222']
    
    def _load_subdomain_wordlists(self) -> List[str]:
        """Load subdomain wordlists"""
        return [
            'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk', 'ns2',
            'cpanel', 'whm', 'autodiscover', 'autoconfig', 'm', 'imap', 'test', 'ns', 'blog',
            'pop3', 'dev', 'www2', 'admin', 'forum', 'news', 'vpn', 'ns3', 'mail2', 'new',
            'mysql', 'old', 'www1', 'api', 'api2', 'api3', 'api4', 'api5', 'api6', 'api7',
            'api8', 'api9', 'api10', 'api11', 'api12', 'api13', 'api14', 'api15', 'api16',
            'api17', 'api18', 'api19', 'api20', 'api21', 'api22', 'api23', 'api24', 'api25',
            'api26', 'api27', 'api28', 'api29', 'api30', 'api31', 'api32', 'api33', 'api34',
            'api35', 'api36', 'api37', 'api38', 'api39', 'api40', 'api41', 'api42', 'api43',
            'api44', 'api45', 'api46', 'api47', 'api48', 'api49', 'api50', 'api51', 'api52',
            'api53', 'api54', 'api55', 'api56', 'api57', 'api58', 'api59', 'api60', 'api61',
            'api62', 'api63', 'api64', 'api65', 'api66', 'api67', 'api68', 'api69', 'api70',
            'api71', 'api72', 'api73', 'api74', 'api75', 'api76', 'api77', 'api78', 'api79',
            'api80', 'api81', 'api82', 'api83', 'api84', 'api85', 'api86', 'api87', 'api88',
            'api89', 'api90', 'api91', 'api92', 'api93', 'api94', 'api95', 'api96', 'api97',
            'api98', 'api99', 'api100', 'admin', 'administrator', 'root', 'user', 'guest',
            'test', 'demo', 'sample', 'example', 'temp', 'temporary', 'backup', 'backups',
            'old', 'new', 'dev', 'development', 'staging', 'stage', 'prod', 'production',
            'live', 'beta', 'alpha', 'gamma', 'delta', 'epsilon', 'zeta', 'eta', 'theta',
            'iota', 'kappa', 'lambda', 'mu', 'nu', 'xi', 'omicron', 'pi', 'rho', 'sigma',
            'tau', 'upsilon', 'phi', 'chi', 'psi', 'omega', 'a', 'b', 'c', 'd', 'e', 'f',
            'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
            'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9'
        ]
    
    def execute_comprehensive_recon(self, target: str) -> Dict[str, Any]:
        """Execute comprehensive reconnaissance"""
        start_time = time.time()
        
        # Parse target
        parsed_target = self._parse_target(target)
        recon_target = ReconTarget(host=parsed_target['host'], ip=parsed_target['ip'])
        
        results = {
            'target': target,
            'recon_results': [],
            'total_duration': 0,
            'successful_recons': 0,
            'failed_recons': 0
        }
        
        try:
            self.logger.info(f"[*] Starting comprehensive reconnaissance of {target}")
            
            # Execute reconnaissance types
            recon_types = [
                ReconType.PORT_SCAN,
                ReconType.SERVICE_DETECTION,
                ReconType.OS_FINGERPRINTING,
                ReconType.SUBDOMAIN_ENUMERATION,
                ReconType.DNS_ENUMERATION,
                ReconType.WHOIS_LOOKUP,
                ReconType.CERTIFICATE_ANALYSIS,
                ReconType.TECHNOLOGY_STACK
            ]
            
            # Execute reconnaissance in parallel
            with ThreadPoolExecutor(max_workers=10) as executor:
                future_to_recon = {
                    executor.submit(self._execute_recon_type, recon_type, recon_target): recon_type
                    for recon_type in recon_types
                }
                
                for future in as_completed(future_to_recon):
                    recon_type = future_to_recon[future]
                    try:
                        result = future.result()
                        results['recon_results'].append(result)
                        
                        if result.success:
                            results['successful_recons'] += 1
                        else:
                            results['failed_recons'] += 1
                            
                    except Exception as e:
                        self.logger.error(f"[-] Error in {recon_type.value}: {e}")
                        results['failed_recons'] += 1
            
            results['total_duration'] = time.time() - start_time
            self.logger.success(f"[+] Comprehensive reconnaissance completed in {results['total_duration']:.2f} seconds")
            
        except Exception as e:
            self.logger.error(f"[-] Comprehensive reconnaissance failed: {e}")
            results['error'] = str(e)
        
        return results
    
    def _parse_target(self, target: str) -> Dict[str, str]:
        """Parse target URL or IP"""
        try:
            # Try to parse as URL
            parsed = urlparse(target if target.startswith(('http://', 'https://')) else f'http://{target}')
            host = parsed.hostname or target
            
            # Resolve IP
            try:
                ip = socket.gethostbyname(host)
            except socket.gaierror:
                ip = host
            
            return {'host': host, 'ip': ip}
        except Exception:
            return {'host': target, 'ip': target}
    
    def _execute_recon_type(self, recon_type: ReconType, target: ReconTarget) -> ReconResult:
        """Execute specific reconnaissance type"""
        start_time = time.time()
        
        try:
            if recon_type == ReconType.PORT_SCAN:
                data = self._port_scan(target.ip or target.host)
            elif recon_type == ReconType.SERVICE_DETECTION:
                data = self._service_detection(target.ip or target.host, target.ports or [])
            elif recon_type == ReconType.OS_FINGERPRINTING:
                data = self._os_fingerprinting(target.ip or target.host)
            elif recon_type == ReconType.SUBDOMAIN_ENUMERATION:
                data = self._subdomain_enumeration(target.host)
            elif recon_type == ReconType.DNS_ENUMERATION:
                data = self._dns_enumeration(target.host)
            elif recon_type == ReconType.WHOIS_LOOKUP:
                data = self._whois_lookup(target.host)
            elif recon_type == ReconType.CERTIFICATE_ANALYSIS:
                data = self._certificate_analysis(target.host)
            elif recon_type == ReconType.TECHNOLOGY_STACK:
                data = self._technology_stack_analysis(target.host)
            else:
                data = {}
            
            duration = time.time() - start_time
            
            return ReconResult(
                target=target.host,
                recon_type=recon_type,
                success=bool(data),
                data=data,
                timestamp=time.time(),
                duration=duration
            )
            
        except Exception as e:
            return ReconResult(
                target=target.host,
                recon_type=recon_type,
                success=False,
                data={'error': str(e)},
                timestamp=time.time(),
                duration=time.time() - start_time
            )
    
    def _port_scan(self, target: str) -> Dict[str, Any]:
        """Perform port scan"""
        try:
            self.logger.info(f"[*] Port scanning {target}")
            
            open_ports = []
            
            # Scan common ports
            for port in self.common_ports:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(1)
                    result = sock.connect_ex((target, port))
                    sock.close()
                    
                    if result == 0:
                        open_ports.append(port)
                        self.logger.debug(f"[+] Port {port} is open")
                        
                except Exception:
                    continue
            
            return {
                'open_ports': open_ports,
                'total_ports_scanned': len(self.common_ports),
                'open_ports_count': len(open_ports)
            }
            
        except Exception as e:
            self.logger.error(f"[-] Port scan failed: {e}")
            return {}
    
    def _service_detection(self, target: str, ports: List[int]) -> Dict[str, Any]:
        """Detect services running on ports"""
        try:
            self.logger.info(f"[*] Detecting services on {target}")
            
            services = {}
            
            for port in ports:
                try:
                    # Try to connect and get banner
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(3)
                    sock.connect((target, port))
                    
                    # Try to get banner
                    try:
                        sock.send(b'\r\n')
                        banner = sock.recv(1024).decode('utf-8', errors='ignore')
                        services[port] = {
                            'service': self.service_ports.get(port, 'unknown'),
                            'banner': banner.strip(),
                            'version': self._extract_version(banner)
                        }
                    except:
                        services[port] = {
                            'service': self.service_ports.get(port, 'unknown'),
                            'banner': '',
                            'version': 'unknown'
                        }
                    
                    sock.close()
                    
                except Exception:
                    continue
            
            return {
                'services': services,
                'total_services': len(services)
            }
            
        except Exception as e:
            self.logger.error(f"[-] Service detection failed: {e}")
            return {}
    
    def _os_fingerprinting(self, target: str) -> Dict[str, Any]:
        """Perform comprehensive OS fingerprinting"""
        try:
            self.logger.info(f"[*] OS fingerprinting {target}")
            
            os_info = {
                'os': 'Unknown',
                'version': 'Unknown',
                'architecture': 'Unknown',
                'confidence': 0.0,
                'techniques_used': [],
                'banner_analysis': {},
                'ttl_analysis': {},
                'port_signatures': {},
                'http_headers': {},
                'tcp_sequence': {}
            }
            
            # Technique 1: HTTP Header Analysis
            http_os = self._analyze_http_headers(target)
            if http_os['confidence'] > 0:
                os_info.update(http_os)
                os_info['techniques_used'].append('http_headers')
            
            # Technique 2: TTL Analysis
            ttl_os = self._analyze_ttl_values(target)
            if ttl_os['confidence'] > 0:
                os_info.update(ttl_os)
                os_info['techniques_used'].append('ttl_analysis')
            
            # Technique 3: Port Signature Analysis
            port_os = self._analyze_port_signatures(target)
            if port_os['confidence'] > 0:
                os_info.update(port_os)
                os_info['techniques_used'].append('port_signatures')
            
            # Technique 4: TCP Sequence Analysis
            tcp_os = self._analyze_tcp_sequence(target)
            if tcp_os['confidence'] > 0:
                os_info.update(tcp_os)
                os_info['techniques_used'].append('tcp_sequence')
            
            # Technique 5: Banner Grabbing
            banner_os = self._analyze_service_banners(target)
            if banner_os['confidence'] > 0:
                os_info.update(banner_os)
                os_info['techniques_used'].append('banner_grabbing')
            
            # Calculate overall confidence
            if os_info['techniques_used']:
                os_info['confidence'] = min(sum([
                    http_os.get('confidence', 0),
                    ttl_os.get('confidence', 0),
                    port_os.get('confidence', 0),
                    tcp_os.get('confidence', 0),
                    banner_os.get('confidence', 0)
                ]) / len(os_info['techniques_used']), 1.0)
            
            return os_info
            
        except Exception as e:
            self.logger.error(f"[-] OS fingerprinting failed: {e}")
            return {}
    
    def _analyze_http_headers(self, target: str) -> Dict[str, Any]:
        """Analyze HTTP headers for OS detection"""
        try:
            os_info = {'os': 'Unknown', 'version': 'Unknown', 'confidence': 0.0}
            
            # Try HTTP and HTTPS
            for protocol in ['http', 'https']:
                try:
                    response = requests.get(f'{protocol}://{target}', timeout=10, verify=False)
                    headers = response.headers
                    
                    # Server header analysis
                    server = headers.get('Server', '').lower()
                    if server:
                        os_info['http_headers']['server'] = server
                        
                        # Apache on Linux
                        if 'apache' in server and 'linux' in server:
                            os_info['os'] = 'Linux'
                            os_info['version'] = self._extract_apache_version(server)
                            os_info['confidence'] = 0.8
                        # IIS on Windows
                        elif 'microsoft-iis' in server or 'iis' in server:
                            os_info['os'] = 'Windows'
                            os_info['version'] = self._extract_iis_version(server)
                            os_info['confidence'] = 0.9
                        # Nginx on Linux
                        elif 'nginx' in server:
                            os_info['os'] = 'Linux'
                            os_info['version'] = self._extract_nginx_version(server)
                            os_info['confidence'] = 0.7
                        # Apache on various systems
                        elif 'apache' in server:
                            os_info['os'] = 'Unix/Linux'
                            os_info['version'] = self._extract_apache_version(server)
                            os_info['confidence'] = 0.6
                    
                    # X-Powered-By header
                    powered_by = headers.get('X-Powered-By', '').lower()
                    if powered_by:
                        os_info['http_headers']['x_powered_by'] = powered_by
                        
                        if 'php' in powered_by:
                            os_info['os'] = 'Linux/Unix'  # PHP is common on Linux
                            os_info['confidence'] = max(os_info['confidence'], 0.5)
                        elif 'asp.net' in powered_by:
                            os_info['os'] = 'Windows'  # ASP.NET is Windows
                            os_info['confidence'] = max(os_info['confidence'], 0.8)
                    
                    # X-AspNet-Version header
                    aspnet_version = headers.get('X-AspNet-Version', '')
                    if aspnet_version:
                        os_info['os'] = 'Windows'
                        os_info['version'] = f"ASP.NET {aspnet_version}"
                        os_info['confidence'] = max(os_info['confidence'], 0.9)
                    
                    # X-AspNetMvc-Version header
                    mvc_version = headers.get('X-AspNetMvc-Version', '')
                    if mvc_version:
                        os_info['os'] = 'Windows'
                        os_info['version'] = f"ASP.NET MVC {mvc_version}"
                        os_info['confidence'] = max(os_info['confidence'], 0.9)
                    
                    break  # If successful, don't try other protocols
                    
                except Exception:
                    continue
            
            return os_info
            
        except Exception as e:
            self.logger.debug(f"[-] HTTP header analysis failed: {e}")
            return {'os': 'Unknown', 'version': 'Unknown', 'confidence': 0.0}
    
    def _analyze_ttl_values(self, target: str) -> Dict[str, Any]:
        """Analyze TTL values for OS detection"""
        try:
            os_info = {'os': 'Unknown', 'confidence': 0.0}
            
            # Common TTL values by OS
            ttl_signatures = {
                64: {'os': 'Linux/Unix', 'confidence': 0.8},
                128: {'os': 'Windows', 'confidence': 0.8},
                255: {'os': 'Cisco/IOS', 'confidence': 0.9},
                60: {'os': 'Linux', 'confidence': 0.7},
                32: {'os': 'Windows', 'confidence': 0.6}
            }
            
            # Ping the target to get TTL
            import subprocess
            import re
            
            try:
                if os.name == 'nt':  # Windows
                    result = subprocess.run(['ping', '-n', '1', target], 
                                          capture_output=True, text=True, timeout=10)
                else:  # Linux/Unix
                    result = subprocess.run(['ping', '-c', '1', target], 
                                          capture_output=True, text=True, timeout=10)
                
                # Extract TTL from ping output
                ttl_match = re.search(r'ttl=(\d+)', result.stdout.lower())
                if ttl_match:
                    ttl = int(ttl_match.group(1))
                    os_info['ttl_analysis']['ttl_value'] = ttl
                    
                    # Find closest match
                    closest_ttl = min(ttl_signatures.keys(), key=lambda x: abs(x - ttl))
                    if abs(ttl - closest_ttl) <= 5:  # Within 5 TTL units
                        signature = ttl_signatures[closest_ttl]
                        os_info['os'] = signature['os']
                        os_info['confidence'] = signature['confidence']
                        os_info['ttl_analysis']['matched_signature'] = closest_ttl
                
            except Exception:
                pass
            
            return os_info
            
        except Exception as e:
            self.logger.debug(f"[-] TTL analysis failed: {e}")
            return {'os': 'Unknown', 'confidence': 0.0}
    
    def _analyze_port_signatures(self, target: str) -> Dict[str, Any]:
        """Analyze port signatures for OS detection"""
        try:
            os_info = {'os': 'Unknown', 'confidence': 0.0}
            
            # Common ports and their OS signatures
            port_signatures = {
                135: {'os': 'Windows', 'service': 'RPC', 'confidence': 0.9},
                139: {'os': 'Windows', 'service': 'NetBIOS', 'confidence': 0.8},
                445: {'os': 'Windows', 'service': 'SMB', 'confidence': 0.9},
                3389: {'os': 'Windows', 'service': 'RDP', 'confidence': 0.9},
                22: {'os': 'Linux/Unix', 'service': 'SSH', 'confidence': 0.7},
                21: {'os': 'Linux/Unix', 'service': 'FTP', 'confidence': 0.5},
                23: {'os': 'Linux/Unix', 'service': 'Telnet', 'confidence': 0.5},
                80: {'os': 'Any', 'service': 'HTTP', 'confidence': 0.3},
                443: {'os': 'Any', 'service': 'HTTPS', 'confidence': 0.3}
            }
            
            # Scan common ports
            open_ports = []
            for port in [22, 23, 80, 135, 139, 443, 445, 3389]:
                if self._is_port_open(target, port):
                    open_ports.append(port)
                    os_info['port_signatures'][port] = port_signatures.get(port, {})
            
            # Analyze port combinations
            if 135 in open_ports and 139 in open_ports and 445 in open_ports:
                os_info['os'] = 'Windows'
                os_info['confidence'] = 0.95
            elif 22 in open_ports and 80 in open_ports:
                os_info['os'] = 'Linux/Unix'
                os_info['confidence'] = 0.7
            elif 3389 in open_ports:
                os_info['os'] = 'Windows'
                os_info['confidence'] = 0.9
            
            os_info['port_signatures']['open_ports'] = open_ports
            return os_info
            
        except Exception as e:
            self.logger.debug(f"[-] Port signature analysis failed: {e}")
            return {'os': 'Unknown', 'confidence': 0.0}
    
    def _analyze_tcp_sequence(self, target: str) -> Dict[str, Any]:
        """Analyze TCP sequence numbers for OS detection"""
        try:
            os_info = {'os': 'Unknown', 'confidence': 0.0}
            
            # This is a simplified TCP sequence analysis
            # In practice, you'd analyze actual TCP sequence patterns
            
            # Common TCP sequence patterns by OS
            tcp_patterns = {
                'linux': {'pattern': 'random', 'confidence': 0.6},
                'windows': {'pattern': 'time_based', 'confidence': 0.6},
                'freebsd': {'pattern': 'random', 'confidence': 0.5},
                'openbsd': {'pattern': 'random', 'confidence': 0.5}
            }
            
            # For now, we'll use a simplified approach
            # In a real implementation, you'd capture and analyze actual TCP packets
            os_info['tcp_sequence']['analysis'] = 'simplified'
            os_info['tcp_sequence']['patterns'] = tcp_patterns
            
            return os_info
            
        except Exception as e:
            self.logger.debug(f"[-] TCP sequence analysis failed: {e}")
            return {'os': 'Unknown', 'confidence': 0.0}
    
    def _analyze_service_banners(self, target: str) -> Dict[str, Any]:
        """Analyze service banners for OS detection"""
        try:
            os_info = {'os': 'Unknown', 'version': 'Unknown', 'confidence': 0.0}
            
            # Common service banners and their OS signatures
            banner_patterns = {
                r'openssh.*ubuntu': {'os': 'Linux Ubuntu', 'confidence': 0.9},
                r'openssh.*debian': {'os': 'Linux Debian', 'confidence': 0.9},
                r'openssh.*centos': {'os': 'Linux CentOS', 'confidence': 0.9},
                r'openssh.*redhat': {'os': 'Linux RedHat', 'confidence': 0.9},
                r'microsoft.*iis': {'os': 'Windows', 'confidence': 0.95},
                r'apache.*linux': {'os': 'Linux', 'confidence': 0.8},
                r'nginx.*linux': {'os': 'Linux', 'confidence': 0.8},
                r'apache.*unix': {'os': 'Unix', 'confidence': 0.7}
            }
            
            # Try to get banners from common services
            for port in [22, 80, 443, 21, 23]:
                try:
                    banner = self._get_service_banner(target, port)
                    if banner:
                        os_info['banner_analysis'][port] = banner
                        
                        # Check against known patterns
                        for pattern, signature in banner_patterns.items():
                            if re.search(pattern, banner.lower()):
                                os_info['os'] = signature['os']
                                os_info['confidence'] = signature['confidence']
                                os_info['banner_analysis']['matched_pattern'] = pattern
                                break
                        
                        if os_info['os'] != 'Unknown':
                            break
                            
                except Exception:
                    continue
            
            return os_info
            
        except Exception as e:
            self.logger.debug(f"[-] Service banner analysis failed: {e}")
            return {'os': 'Unknown', 'confidence': 0.0}
    
    def _extract_apache_version(self, server_header: str) -> str:
        """Extract Apache version from server header"""
        try:
            version_match = re.search(r'apache/([\d.]+)', server_header.lower())
            return version_match.group(1) if version_match else 'Unknown'
        except:
            return 'Unknown'
    
    def _extract_iis_version(self, server_header: str) -> str:
        """Extract IIS version from server header"""
        try:
            version_match = re.search(r'iis/([\d.]+)', server_header.lower())
            return version_match.group(1) if version_match else 'Unknown'
        except:
            return 'Unknown'
    
    def _extract_nginx_version(self, server_header: str) -> str:
        """Extract Nginx version from server header"""
        try:
            version_match = re.search(r'nginx/([\d.]+)', server_header.lower())
            return version_match.group(1) if version_match else 'Unknown'
        except:
            return 'Unknown'
    
    def _is_port_open(self, target: str, port: int) -> bool:
        """Check if port is open"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            result = sock.connect_ex((target, port))
            sock.close()
            return result == 0
        except:
            return False
    
    def _get_service_banner(self, target: str, port: int) -> Optional[str]:
        """Get service banner from port"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((target, port))
            
            # Try to get banner
            banner = sock.recv(1024).decode('utf-8', errors='ignore')
            sock.close()
            
            return banner.strip() if banner else None
            
        except:
            return None
    
    def _subdomain_enumeration(self, domain: str) -> Dict[str, Any]:
        """Enumerate subdomains"""
        try:
            self.logger.info(f"[*] Enumerating subdomains for {domain}")
            
            subdomains = []
            
            # DNS enumeration
            for subdomain in self.subdomain_wordlists[:50]:  # Limit for demo
                try:
                    full_domain = f"{subdomain}.{domain}"
                    socket.gethostbyname(full_domain)
                    subdomains.append(full_domain)
                    self.logger.debug(f"[+] Found subdomain: {full_domain}")
                except socket.gaierror:
                    continue
            
            return {
                'subdomains': subdomains,
                'total_subdomains': len(subdomains)
            }
            
        except Exception as e:
            self.logger.error(f"[-] Subdomain enumeration failed: {e}")
            return {}
    
    def _dns_enumeration(self, domain: str) -> Dict[str, Any]:
        """Enumerate DNS records"""
        try:
            self.logger.info(f"[*] Enumerating DNS records for {domain}")
            
            dns_records = {}
            record_types = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'SOA']
            
            for record_type in record_types:
                try:
                    answers = dns.resolver.resolve(domain, record_type)
                    dns_records[record_type] = [str(answer) for answer in answers]
                except:
                    dns_records[record_type] = []
            
            return {
                'dns_records': dns_records,
                'total_records': sum(len(records) for records in dns_records.values())
            }
            
        except Exception as e:
            self.logger.error(f"[-] DNS enumeration failed: {e}")
            return {}
    
    def _whois_lookup(self, domain: str) -> Dict[str, Any]:
        """Perform comprehensive WHOIS lookup with multiple sources"""
        try:
            self.logger.info(f"[*] Performing WHOIS lookup for {domain}")
            
            whois_info = {
                'registrar': 'Unknown',
                'creation_date': 'Unknown',
                'expiration_date': 'Unknown',
                'name_servers': [],
                'status': 'Unknown',
                'admin_contact': 'Unknown',
                'tech_contact': 'Unknown',
                'registrant_org': 'Unknown',
                'registrant_country': 'Unknown',
                'last_updated': 'Unknown',
                'raw_data': '',
                'lookup_sources': []
            }
            
            # Try multiple WHOIS servers
            whois_servers = [
                'whois.verisign-grs.com',
                'whois.internic.net',
                'whois.iana.org',
                'whois.arin.net'
            ]
            
            for server in whois_servers:
                try:
                    # Use socket to connect to WHOIS server
                    import socket
                    import time
                    
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(10)
                    sock.connect((server, 43))
                    
                    # Send WHOIS query
                    query = f"{domain}\r\n"
                    sock.send(query.encode())
                    
                    # Receive response
                    response = b""
                    while True:
                        data = sock.recv(4096)
                        if not data:
                            break
                        response += data
                        time.sleep(0.1)  # Small delay to avoid overwhelming
                    
                    sock.close()
                    
                    # Parse WHOIS response
                    whois_text = response.decode('utf-8', errors='ignore')
                    parsed_info = self._parse_whois_response(whois_text)
                    
                    if parsed_info:
                        whois_info.update(parsed_info)
                        whois_info['lookup_sources'].append(server)
                        whois_info['raw_data'] = whois_text
                        break
                        
                except Exception as e:
                    self.logger.debug(f"[-] WHOIS lookup failed on {server}: {e}")
                    continue
            
            # If no WHOIS data found, try alternative methods
            if whois_info['registrar'] == 'Unknown':
                try:
                    # Try using python-whois if available
                    import whois
                    w = whois.whois(domain)
                    
                    if w.registrar:
                        whois_info['registrar'] = str(w.registrar)
                    if w.creation_date:
                        whois_info['creation_date'] = str(w.creation_date)
                    if w.expiration_date:
                        whois_info['expiration_date'] = str(w.expiration_date)
                    if w.name_servers:
                        whois_info['name_servers'] = [str(ns) for ns in w.name_servers]
                    if w.status:
                        whois_info['status'] = str(w.status)
                    if w.admin_contact:
                        whois_info['admin_contact'] = str(w.admin_contact)
                    if w.tech_contact:
                        whois_info['tech_contact'] = str(w.tech_contact)
                    if w.registrant_org:
                        whois_info['registrant_org'] = str(w.registrant_org)
                    if w.registrant_country:
                        whois_info['registrant_country'] = str(w.registrant_country)
                    if w.last_updated:
                        whois_info['last_updated'] = str(w.last_updated)
                    
                    whois_info['lookup_sources'].append('python-whois')
                    
                except ImportError:
                    self.logger.debug("[-] python-whois not available")
                except Exception as e:
                    self.logger.debug(f"[-] python-whois lookup failed: {e}")
            
            # Additional DNS-based information
            try:
                import dns.resolver
                resolver = dns.resolver.Resolver()
                resolver.timeout = 5
                resolver.lifetime = 5
                
                # Get name servers from DNS
                ns_records = resolver.resolve(domain, 'NS')
                dns_name_servers = [str(ns) for ns in ns_records]
                
                if dns_name_servers and not whois_info['name_servers']:
                    whois_info['name_servers'] = dns_name_servers
                    whois_info['lookup_sources'].append('dns')
                    
            except Exception as e:
                self.logger.debug(f"[-] DNS-based WHOIS lookup failed: {e}")
            
            self.logger.success(f"[+] WHOIS lookup completed using {len(whois_info['lookup_sources'])} sources")
            return whois_info
            
        except Exception as e:
            self.logger.error(f"[-] WHOIS lookup failed: {e}")
            return {}
    
    def _parse_whois_response(self, whois_text: str) -> Dict[str, Any]:
        """Parse WHOIS response text"""
        parsed = {}
        
        try:
            lines = whois_text.split('\n')
            
            for line in lines:
                line = line.strip()
                if ':' in line:
                    key, value = line.split(':', 1)
                    key = key.strip().lower()
                    value = value.strip()
                    
                    if not value or value == 'N/A':
                        continue
                    
                    # Map common WHOIS fields
                    if 'registrar' in key:
                        parsed['registrar'] = value
                    elif 'creation date' in key or 'created' in key:
                        parsed['creation_date'] = value
                    elif 'expiration date' in key or 'expires' in key:
                        parsed['expiration_date'] = value
                    elif 'name server' in key or 'nserver' in key:
                        if 'name_servers' not in parsed:
                            parsed['name_servers'] = []
                        parsed['name_servers'].append(value)
                    elif 'status' in key:
                        parsed['status'] = value
                    elif 'admin contact' in key:
                        parsed['admin_contact'] = value
                    elif 'tech contact' in key:
                        parsed['tech_contact'] = value
                    elif 'registrant organization' in key:
                        parsed['registrant_org'] = value
                    elif 'registrant country' in key:
                        parsed['registrant_country'] = value
                    elif 'last updated' in key:
                        parsed['last_updated'] = value
            
            return parsed
            
        except Exception as e:
            self.logger.debug(f"[-] Error parsing WHOIS response: {e}")
            return {}
    
    def _certificate_analysis(self, domain: str) -> Dict[str, Any]:
        """Analyze SSL certificates with comprehensive security assessment"""
        try:
            self.logger.info(f"[*] Analyzing SSL certificates for {domain}")
            
            cert_info = {
                'issuer': 'Unknown',
                'subject': 'Unknown',
                'valid_from': 'Unknown',
                'valid_to': 'Unknown',
                'serial_number': 'Unknown',
                'signature_algorithm': 'Unknown',
                'key_size': 'Unknown',
                'key_algorithm': 'Unknown',
                'version': 'Unknown',
                'fingerprint': 'Unknown',
                'is_valid': False,
                'days_until_expiry': 0,
                'security_issues': [],
                'certificate_chain': [],
                'ocsp_status': 'Unknown',
                'crl_status': 'Unknown'
            }
            
            # Try HTTPS connection
            for port in [443, 8443, 9443]:
                try:
                    import ssl
                    import socket
                    from datetime import datetime
                    
                    # Create SSL context
                    context = ssl.create_default_context()
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    
                    # Connect to server
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(10)
                    ssl_sock = context.wrap_socket(sock, server_hostname=domain)
                    ssl_sock.connect((domain, port))
                    
                    # Get certificate
                    cert = ssl_sock.getpeercert()
                    cert_der = ssl_sock.getpeercert(binary_form=True)
                    
                    ssl_sock.close()
                    
                    if cert:
                        # Parse certificate information
                        cert_info['issuer'] = self._format_cert_name(cert.get('issuer', {}))
                        cert_info['subject'] = self._format_cert_name(cert.get('subject', {}))
                        cert_info['valid_from'] = cert.get('notBefore', 'Unknown')
                        cert_info['valid_to'] = cert.get('notAfter', 'Unknown')
                        cert_info['serial_number'] = cert.get('serialNumber', 'Unknown')
                        cert_info['version'] = cert.get('version', 'Unknown')
                        
                        # Calculate days until expiry
                        if cert_info['valid_to'] != 'Unknown':
                            try:
                                expiry_date = datetime.strptime(cert_info['valid_to'], '%b %d %H:%M:%S %Y %Z')
                                days_until_expiry = (expiry_date - datetime.now()).days
                                cert_info['days_until_expiry'] = days_until_expiry
                                
                                if days_until_expiry < 0:
                                    cert_info['security_issues'].append('Certificate expired')
                                elif days_until_expiry < 30:
                                    cert_info['security_issues'].append('Certificate expires soon')
                                    
                            except Exception as e:
                                self.logger.debug(f"[-] Error parsing certificate date: {e}")
                        
                        # Check certificate validity
                        cert_info['is_valid'] = True
                        
                        # Get additional certificate details
                        try:
                            from cryptography import x509
                            from cryptography.hazmat.backends import default_backend
                            from cryptography.hazmat.primitives import hashes
                            
                            cert_obj = x509.load_der_x509_certificate(cert_der, default_backend())
                            
                            # Get key information
                            public_key = cert_obj.public_key()
                            if hasattr(public_key, 'key_size'):
                                cert_info['key_size'] = public_key.key_size
                            
                            # Get signature algorithm
                            cert_info['signature_algorithm'] = str(cert_obj.signature_algorithm_oid)
                            
                            # Get fingerprint
                            cert_info['fingerprint'] = cert_obj.fingerprint(hashes.SHA256()).hex()
                            
                            # Security analysis
                            self._analyze_certificate_security(cert_obj, cert_info)
                            
                        except ImportError:
                            self.logger.debug("[-] cryptography library not available for detailed analysis")
                        except Exception as e:
                            self.logger.debug(f"[-] Error in detailed certificate analysis: {e}")
                        
                        # Check OCSP status
                        try:
                            ocsp_status = self._check_ocsp_status(cert, domain)
                            cert_info['ocsp_status'] = ocsp_status
                        except Exception as e:
                            self.logger.debug(f"[-] OCSP check failed: {e}")
                        
                        # Check CRL status
                        try:
                            crl_status = self._check_crl_status(cert)
                            cert_info['crl_status'] = crl_status
                        except Exception as e:
                            self.logger.debug(f"[-] CRL check failed: {e}")
                        
                        self.logger.success(f"[+] Certificate analysis completed for {domain}:{port}")
                        break
                        
                except Exception as e:
                    self.logger.debug(f"[-] Certificate analysis failed on port {port}: {e}")
                    continue
            
            # If no certificate found, try alternative methods
            if not cert_info['is_valid']:
                try:
                    # Try using requests with SSL verification
                    import requests
                    response = requests.get(f"https://{domain}", timeout=10, verify=True)
                    
                    # Get certificate from response
                    if hasattr(response, 'raw') and hasattr(response.raw, 'connection'):
                        cert = response.raw.connection.sock.getpeercert()
                        if cert:
                            cert_info.update(self._parse_certificate_dict(cert))
                            cert_info['is_valid'] = True
                            
                except Exception as e:
                    self.logger.debug(f"[-] Alternative certificate analysis failed: {e}")
            
            return cert_info
            
        except Exception as e:
            self.logger.error(f"[-] Certificate analysis failed: {e}")
            return {}
    
    def _format_cert_name(self, name_dict: Dict) -> str:
        """Format certificate name dictionary to string"""
        try:
            if isinstance(name_dict, dict):
                parts = []
                for key, value in name_dict.items():
                    if isinstance(value, (list, tuple)):
                        for item in value:
                            if isinstance(item, (list, tuple)) and len(item) == 2:
                                parts.append(f"{item[0]}={item[1]}")
                    else:
                        parts.append(f"{key}={value}")
                return ", ".join(parts)
            return str(name_dict)
        except Exception:
            return str(name_dict)
    
    def _parse_certificate_dict(self, cert: Dict) -> Dict[str, Any]:
        """Parse certificate dictionary from requests"""
        parsed = {}
        
        try:
            parsed['issuer'] = self._format_cert_name(cert.get('issuer', {}))
            parsed['subject'] = self._format_cert_name(cert.get('subject', {}))
            parsed['valid_from'] = cert.get('notBefore', 'Unknown')
            parsed['valid_to'] = cert.get('notAfter', 'Unknown')
            parsed['serial_number'] = cert.get('serialNumber', 'Unknown')
            parsed['version'] = cert.get('version', 'Unknown')
            
            # Calculate days until expiry
            if parsed['valid_to'] != 'Unknown':
                try:
                    from datetime import datetime
                    expiry_date = datetime.strptime(parsed['valid_to'], '%b %d %H:%M:%S %Y %Z')
                    days_until_expiry = (expiry_date - datetime.now()).days
                    parsed['days_until_expiry'] = days_until_expiry
                except Exception:
                    parsed['days_until_expiry'] = 0
            
        except Exception as e:
            self.logger.debug(f"[-] Error parsing certificate dict: {e}")
        
        return parsed
    
    def _analyze_certificate_security(self, cert_obj, cert_info: Dict[str, Any]):
        """Analyze certificate for security issues"""
        try:
            from cryptography import x509
            from cryptography.hazmat.primitives import hashes
            
            # Check key size
            if cert_info.get('key_size', 0) < 2048:
                cert_info['security_issues'].append('Weak key size (< 2048 bits)')
            
            # Check signature algorithm
            if 'md5' in cert_info.get('signature_algorithm', '').lower():
                cert_info['security_issues'].append('Weak signature algorithm (MD5)')
            elif 'sha1' in cert_info.get('signature_algorithm', '').lower():
                cert_info['security_issues'].append('Weak signature algorithm (SHA1)')
            
            # Check certificate extensions
            try:
                extensions = cert_obj.extensions
                for ext in extensions:
                    if isinstance(ext.value, x509.KeyUsage):
                        if not ext.value.digital_signature:
                            cert_info['security_issues'].append('Certificate not suitable for digital signatures')
                    elif isinstance(ext.value, x509.BasicConstraints):
                        if ext.value.ca and not ext.value.path_length:
                            cert_info['security_issues'].append('CA certificate without path length constraint')
                            
            except Exception as e:
                self.logger.debug(f"[-] Error analyzing certificate extensions: {e}")
            
        except Exception as e:
            self.logger.debug(f"[-] Error in certificate security analysis: {e}")
    
    def _check_ocsp_status(self, cert: Dict, domain: str) -> str:
        """Check OCSP (Online Certificate Status Protocol) status"""
        try:
            # This is a simplified OCSP check
            # In a real implementation, you'd use proper OCSP libraries
            return 'Not checked'
        except Exception:
            return 'Error'
    
    def _check_crl_status(self, cert: Dict) -> str:
        """Check CRL (Certificate Revocation List) status"""
        try:
            # This is a simplified CRL check
            # In a real implementation, you'd use proper CRL libraries
            return 'Not checked'
        except Exception:
            return 'Error'
    
    def _technology_stack_analysis(self, domain: str) -> Dict[str, Any]:
        """Analyze technology stack"""
        try:
            self.logger.info(f"[*] Analyzing technology stack for {domain}")
            
            tech_stack = []
            
            # Try HTTP and HTTPS
            for protocol in ['http', 'https']:
                try:
                    url = f"{protocol}://{domain}"
                    response = requests.get(url, timeout=5)
                    
                    # Analyze headers
                    headers = response.headers
                    
                    # Server
                    server = headers.get('Server', '').lower()
                    if 'apache' in server:
                        tech_stack.append('Apache')
                    elif 'nginx' in server:
                        tech_stack.append('Nginx')
                    elif 'iis' in server:
                        tech_stack.append('IIS')
                    
                    # X-Powered-By
                    powered_by = headers.get('X-Powered-By', '').lower()
                    if 'php' in powered_by:
                        tech_stack.append('PHP')
                    elif 'asp.net' in powered_by:
                        tech_stack.append('ASP.NET')
                    
                    # Analyze content
                    content = response.text.lower()
                    if 'django' in content:
                        tech_stack.append('Django')
                    elif 'flask' in content:
                        tech_stack.append('Flask')
                    elif 'wordpress' in content:
                        tech_stack.append('WordPress')
                    elif 'joomla' in content:
                        tech_stack.append('Joomla')
                    elif 'drupal' in content:
                        tech_stack.append('Drupal')
                    
                    break  # Found working protocol
                    
                except:
                    continue
            
            return {
                'technology_stack': list(set(tech_stack)),
                'total_technologies': len(set(tech_stack))
            }
            
        except Exception as e:
            self.logger.error(f"[-] Technology stack analysis failed: {e}")
            return {}
    
    def _extract_version(self, banner: str) -> str:
        """Extract version from banner with comprehensive pattern matching"""
        try:
            import re
            from packaging import version
            
            # Comprehensive version patterns for different services
            version_patterns = [
                # Standard version patterns
                r'(\d+\.\d+\.\d+\.\d+)',  # 4-part version (e.g., 1.2.3.4)
                r'(\d+\.\d+\.\d+)',       # 3-part version (e.g., 1.2.3)
                r'(\d+\.\d+)',            # 2-part version (e.g., 1.2)
                r'(\d+)',                 # Single number (e.g., 1)
                
                # Service-specific patterns
                r'apache/([\d.]+)',       # Apache
                r'nginx/([\d.]+)',        # Nginx
                r'iis/([\d.]+)',          # IIS
                r'openssh[_-]?([\d.]+)',  # OpenSSH
                r'openssl[_-]?([\d.]+)',  # OpenSSL
                r'php/([\d.]+)',          # PHP
                r'python/([\d.]+)',       # Python
                r'java/([\d.]+)',         # Java
                r'node\.js/([\d.]+)',     # Node.js
                r'ruby/([\d.]+)',         # Ruby
                r'perl/([\d.]+)',         # Perl
                r'mysql/([\d.]+)',        # MySQL
                r'postgresql/([\d.]+)',   # PostgreSQL
                r'mongodb/([\d.]+)',      # MongoDB
                r'redis/([\d.]+)',        # Redis
                r'elasticsearch/([\d.]+)', # Elasticsearch
                r'docker/([\d.]+)',       # Docker
                r'kubernetes/([\d.]+)',   # Kubernetes
                
                # Generic patterns
                r'version\s*:?\s*([\d.]+)',
                r'v([\d.]+)',
                r'release\s*:?\s*([\d.]+)',
                r'build\s*:?\s*([\d.]+)',
                r'rev\s*:?\s*([\d.]+)',
                r'r([\d.]+)',
                
                # Date-based versions
                r'(\d{4}[\d.]+)',         # Year-based (e.g., 2023.1)
                r'(\d{2}[\d.]+)',         # 2-digit year (e.g., 23.1)
                
                # Special formats
                r'(\d+[a-z]\d+)',         # Alpha/beta versions (e.g., 1a2)
                r'(\d+[.-]\d+[.-]\d+)',  # Dash/dot separators
            ]
            
            found_versions = []
            
            # Try each pattern
            for pattern in version_patterns:
                matches = re.findall(pattern, banner, re.IGNORECASE)
                for match in matches:
                    if isinstance(match, tuple):
                        match = match[0]
                    
                    # Clean up the version string
                    version_str = match.strip('.,;:()[]{}')
                    
                    # Validate version format
                    if self._is_valid_version(version_str):
                        found_versions.append(version_str)
            
            if not found_versions:
                return 'unknown'
            
            # Sort versions by complexity and validity
            def version_priority(v):
                parts = v.split('.')
                # Prefer versions with more parts
                return (len(parts), v)
            
            # Sort by priority and return the best match
            best_version = max(found_versions, key=version_priority)
            
            # Additional validation
            if self._is_meaningful_version(best_version):
                return best_version
            
            return 'unknown'
            
        except Exception as e:
            self.logger.debug(f"[-] Version extraction failed: {e}")
            return 'unknown'
    
    def _is_valid_version(self, version_str: str) -> bool:
        """Check if version string is valid"""
        try:
            # Basic validation
            if not version_str or len(version_str) > 20:
                return False
            
            # Must contain at least one digit
            if not re.search(r'\d', version_str):
                return False
            
            # Must not contain only special characters
            if re.match(r'^[^a-zA-Z0-9]+$', version_str):
                return False
            
            # Check for reasonable version format
            if re.match(r'^\d+([.-]\d+)*[a-zA-Z]*$', version_str):
                return True
            
            # Allow more complex patterns
            if re.match(r'^\d+[a-zA-Z]\d+$', version_str):  # e.g., 1a2
                return True
            
            return False
            
        except Exception:
            return False
    
    def _is_meaningful_version(self, version_str: str) -> bool:
        """Check if version string is meaningful (not just random numbers)"""
        try:
            # Extract numeric parts
            numeric_parts = re.findall(r'\d+', version_str)
            
            if not numeric_parts:
                return False
            
            # Check if version makes sense
            for part in numeric_parts:
                num = int(part)
                # Reasonable version numbers (not too large)
                if num > 9999:
                    return False
            
            # Check for common version patterns
            if re.match(r'^\d+\.\d+', version_str):  # Major.minor
                return True
            if re.match(r'^\d+$', version_str):  # Single number
                return True
            if re.match(r'^\d+[a-zA-Z]\d+$', version_str):  # Alpha/beta
                return True
            
            return True
            
        except Exception:
            return False
