"""
AresProbe Advanced Reconnaissance Engine
Subdomain enumeration, port scanning, technology fingerprinting, and SSL analysis
"""

import asyncio
import socket
import ssl
import dns.resolver
import dns.exception
import ipaddress
import hashlib
import json
import time
from typing import Dict, List, Optional, Any, Tuple, Union, Set
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse
import re
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
import subprocess

import requests
from bs4 import BeautifulSoup
import whois
import censys
import shodan

from .logger import Logger
from .async_engine import AsyncEngine, RequestResult


@dataclass
class SubdomainResult:
    """Subdomain enumeration result"""
    subdomain: str
    ip_address: str
    status: str  # 'active', 'inactive', 'unknown'
    response_time: float
    status_code: Optional[int] = None
    title: Optional[str] = None
    server: Optional[str] = None
    technology: Optional[str] = None


@dataclass
class PortResult:
    """Port scanning result"""
    host: str
    port: int
    protocol: str  # 'tcp', 'udp'
    state: str  # 'open', 'closed', 'filtered', 'open|filtered'
    service: Optional[str] = None
    version: Optional[str] = None
    banner: Optional[str] = None
    response_time: float = 0.0


@dataclass
class TechnologyInfo:
    """Technology fingerprinting result"""
    name: str
    version: Optional[str] = None
    confidence: float = 1.0
    category: str = 'unknown'  # 'web_server', 'framework', 'cms', 'database', etc.
    description: Optional[str] = None
    detection_method: str = 'unknown'  # 'header', 'content', 'dns', 'port'


@dataclass
class SSLInfo:
    """SSL/TLS analysis result"""
    host: str
    port: int
    version: Optional[str] = None
    cipher_suite: Optional[str] = None
    certificate_info: Dict[str, Any] = field(default_factory=dict)
    vulnerabilities: List[str] = field(default_factory=list)
    grade: str = 'F'  # A+, A, B, C, D, F
    score: int = 0


class SubdomainEnumerator:
    """Advanced subdomain enumeration with multiple techniques"""
    
    def __init__(self, logger: Logger, async_engine: AsyncEngine):
        self.logger = logger
        self.async_engine = async_engine
        self.results: List[SubdomainResult] = []
        self.wordlists = self._load_wordlists()
        self.dns_servers = ['8.8.8.8', '1.1.1.1', '208.67.222.222']
    
    def _load_wordlists(self) -> Dict[str, List[str]]:
        """Load subdomain wordlists"""
        return {
            'common': [
                'www', 'mail', 'ftp', 'admin', 'test', 'dev', 'staging', 'api',
                'blog', 'shop', 'app', 'mobile', 'secure', 'vpn', 'remote',
                'backup', 'db', 'database', 'internal', 'intranet', 'portal'
            ],
            'extended': [
                'www', 'mail', 'ftp', 'admin', 'test', 'dev', 'staging', 'api',
                'blog', 'shop', 'app', 'mobile', 'secure', 'vpn', 'remote',
                'backup', 'db', 'database', 'internal', 'intranet', 'portal',
                'support', 'help', 'docs', 'wiki', 'forum', 'community',
                'download', 'files', 'static', 'cdn', 'assets', 'media',
                'img', 'images', 'css', 'js', 'javascript', 'style',
                'login', 'auth', 'oauth', 'sso', 'ldap', 'ad',
                'monitor', 'stats', 'analytics', 'metrics', 'health',
                'status', 'ping', 'check', 'verify', 'validate'
            ],
            'aggressive': [
                'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
                'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
                '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
                'mx', 'ns', 'ns1', 'ns2', 'ns3', 'ns4', 'mail1', 'mail2',
                'pop', 'pop3', 'smtp', 'imap', 'webmail', 'email',
                'old', 'new', 'beta', 'alpha', 'preview', 'demo'
            ]
        }
    
    async def enumerate_subdomains(self, domain: str, techniques: List[str] = None, wordlist_size: str = 'common') -> List[SubdomainResult]:
        """Enumerate subdomains using multiple techniques"""
        if techniques is None:
            techniques = ['dns_bruteforce', 'certificate_transparency', 'search_engines', 'dns_zone_transfer']
        
        self.logger.info(f"[*] Starting subdomain enumeration for {domain}")
        all_results = []
        
        # DNS Brute Force
        if 'dns_bruteforce' in techniques:
            self.logger.info("[*] Running DNS brute force...")
            dns_results = await self._dns_bruteforce(domain, wordlist_size)
            all_results.extend(dns_results)
        
        # Certificate Transparency
        if 'certificate_transparency' in techniques:
            self.logger.info("[*] Checking certificate transparency logs...")
            ct_results = await self._certificate_transparency(domain)
            all_results.extend(ct_results)
        
        # Search Engines
        if 'search_engines' in techniques:
            self.logger.info("[*] Searching search engines...")
            se_results = await self._search_engines(domain)
            all_results.extend(se_results)
        
        # DNS Zone Transfer
        if 'dns_zone_transfer' in techniques:
            self.logger.info("[*] Attempting DNS zone transfer...")
            zt_results = await self._dns_zone_transfer(domain)
            all_results.extend(zt_results)
        
        # Remove duplicates and validate
        unique_results = self._deduplicate_results(all_results)
        validated_results = await self._validate_subdomains(unique_results)
        
        self.results = validated_results
        self.logger.info(f"[+] Subdomain enumeration completed: {len(validated_results)} subdomains found")
        
        return validated_results
    
    async def _dns_bruteforce(self, domain: str, wordlist_size: str) -> List[SubdomainResult]:
        """DNS brute force subdomain enumeration"""
        results = []
        wordlist = self.wordlists.get(wordlist_size, self.wordlists['common'])
        
        # Create subdomain tasks
        tasks = []
        for word in wordlist:
            subdomain = f"{word}.{domain}"
            task = self._check_subdomain_dns(subdomain)
            tasks.append(task)
        
        # Execute DNS queries concurrently
        dns_results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in dns_results:
            if isinstance(result, SubdomainResult):
                results.append(result)
        
        return results
    
    async def _check_subdomain_dns(self, subdomain: str) -> Optional[SubdomainResult]:
        """Check if subdomain exists via DNS"""
        try:
            # Try multiple DNS servers
            for dns_server in self.dns_servers:
                try:
                    resolver = dns.resolver.Resolver()
                    resolver.nameservers = [dns_server]
                    resolver.timeout = 5
                    resolver.lifetime = 5
                    
                    answers = resolver.resolve(subdomain, 'A')
                    
                    for answer in answers:
                        return SubdomainResult(
                            subdomain=subdomain,
                            ip_address=str(answer),
                            status='active',
                            response_time=0.0
                        )
                
                except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
                    continue
            
            return None
            
        except Exception as e:
            self.logger.debug(f"[-] DNS check failed for {subdomain}: {e}")
            return None
    
    async def _certificate_transparency(self, domain: str) -> List[SubdomainResult]:
        """Check certificate transparency logs for subdomains"""
        results = []
        
        try:
            # Use crt.sh API
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            response = await self.async_engine.get(url)
            
            if response.status == 200:
                data = json.loads(response.content.decode('utf-8'))
                
                for cert in data:
                    name_value = cert.get('name_value', '')
                    if name_value:
                        # Parse subdomains
                        subdomains = [s.strip() for s in name_value.split('\n')]
                        for subdomain in subdomains:
                            if subdomain.endswith(f'.{domain}') and '*' not in subdomain:
                                results.append(SubdomainResult(
                                    subdomain=subdomain,
                                    ip_address='unknown',
                                    status='unknown',
                                    response_time=0.0
                                ))
        
        except Exception as e:
            self.logger.error(f"[-] Certificate transparency check failed: {e}")
        
        return results
    
    async def _search_engines(self, domain: str) -> List[SubdomainResult]:
        """Search for subdomains using search engines"""
        results = []
        
        # Google dorking queries
        queries = [
            f'site:{domain}',
            f'inurl:{domain}',
            f'intitle:{domain}',
            f'intext:{domain}'
        ]
        
        for query in queries:
            try:
                # This would typically use search engine APIs
                # For now, we'll simulate with a basic search
                search_results = await self._search_google(query)
                
                for result in search_results:
                    parsed_url = urlparse(result)
                    if parsed_url.netloc.endswith(f'.{domain}'):
                        results.append(SubdomainResult(
                            subdomain=parsed_url.netloc,
                            ip_address='unknown',
                            status='unknown',
                            response_time=0.0
                        ))
            
            except Exception as e:
                self.logger.error(f"[-] Search engine query failed: {e}")
        
        return results
    
    async def _search_google(self, query: str) -> List[str]:
        """Search Google for results using comprehensive techniques"""
        try:
            self.logger.info(f"[*] Searching Google for: {query}")
            
            results = []
            
            # 1. Try Google Custom Search API (if available)
            try:
                api_results = await self._google_custom_search(query)
                results.extend(api_results)
                self.logger.success(f"[+] Google Custom Search API: {len(api_results)} results")
            except Exception as e:
                self.logger.debug(f"[-] Google Custom Search API failed: {e}")
            
            # 2. Try web scraping with proper rate limiting
            try:
                scraped_results = await self._scrape_google_search(query)
                results.extend(scraped_results)
                self.logger.success(f"[+] Google web scraping: {len(scraped_results)} results")
            except Exception as e:
                self.logger.debug(f"[-] Google web scraping failed: {e}")
            
            # 3. Try alternative search engines
            try:
                alternative_results = await self._search_alternative_engines(query)
                results.extend(alternative_results)
                self.logger.success(f"[+] Alternative search engines: {len(alternative_results)} results")
            except Exception as e:
                self.logger.debug(f"[-] Alternative search engines failed: {e}")
            
            # 4. Try specialized search techniques
            try:
                specialized_results = await self._specialized_search_techniques(query)
                results.extend(specialized_results)
                self.logger.success(f"[+] Specialized search techniques: {len(specialized_results)} results")
            except Exception as e:
                self.logger.debug(f"[-] Specialized search techniques failed: {e}")
            
            # Remove duplicates and return
            unique_results = list(dict.fromkeys(results))
            self.logger.success(f"[+] Google search completed: {len(unique_results)} unique results")
            return unique_results
            
        except Exception as e:
            self.logger.error(f"[-] Google search failed: {e}")
            return []
    
    async def _google_custom_search(self, query: str) -> List[str]:
        """Use Google Custom Search API"""
        try:
            # This would require Google Custom Search API key
            # For now, return empty list
            return []
        except Exception as e:
            self.logger.debug(f"[-] Google Custom Search API error: {e}")
            return []
    
    async def _scrape_google_search(self, query: str) -> List[str]:
        """Scrape Google search results with proper rate limiting"""
        try:
            import aiohttp
            import asyncio
            from bs4 import BeautifulSoup
            
            results = []
            
            # Rate limiting: wait between requests
            await asyncio.sleep(1)
            
            # Build Google search URL
            search_url = f"https://www.google.com/search?q={query}&num=10"
            
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.get(search_url, headers=headers, timeout=10) as response:
                    if response.status == 200:
                        html = await response.text()
                        soup = BeautifulSoup(html, 'html.parser')
                        
                        # Extract search results
                        for link in soup.find_all('a', href=True):
                            href = link['href']
                            if href.startswith('/url?q='):
                                url = href.split('/url?q=')[1].split('&')[0]
                                if url.startswith('http'):
                                    results.append(url)
            
            return results[:10]  # Limit to 10 results
            
        except Exception as e:
            self.logger.debug(f"[-] Google scraping error: {e}")
            return []
    
    async def _search_alternative_engines(self, query: str) -> List[str]:
        """Search alternative search engines"""
        try:
            results = []
            
            # DuckDuckGo
            try:
                duckduckgo_results = await self._search_duckduckgo(query)
                results.extend(duckduckgo_results)
            except Exception as e:
                self.logger.debug(f"[-] DuckDuckGo search failed: {e}")
            
            # Bing
            try:
                bing_results = await self._search_bing(query)
                results.extend(bing_results)
            except Exception as e:
                self.logger.debug(f"[-] Bing search failed: {e}")
            
            # Yandex
            try:
                yandex_results = await self._search_yandex(query)
                results.extend(yandex_results)
            except Exception as e:
                self.logger.debug(f"[-] Yandex search failed: {e}")
            
            return results
            
        except Exception as e:
            self.logger.debug(f"[-] Alternative search engines error: {e}")
            return []
    
    async def _search_duckduckgo(self, query: str) -> List[str]:
        """Search DuckDuckGo"""
        try:
            import aiohttp
            from bs4 import BeautifulSoup
            
            results = []
            search_url = f"https://duckduckgo.com/html/?q={query}"
            
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.get(search_url, headers=headers, timeout=10) as response:
                    if response.status == 200:
                        html = await response.text()
                        soup = BeautifulSoup(html, 'html.parser')
                        
                        for link in soup.find_all('a', class_='result__a'):
                            href = link.get('href')
                            if href and href.startswith('http'):
                                results.append(href)
            
            return results[:5]
            
        except Exception as e:
            self.logger.debug(f"[-] DuckDuckGo search error: {e}")
            return []
    
    async def _search_bing(self, query: str) -> List[str]:
        """Search Bing"""
        try:
            import aiohttp
            from bs4 import BeautifulSoup
            
            results = []
            search_url = f"https://www.bing.com/search?q={query}"
            
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.get(search_url, headers=headers, timeout=10) as response:
                    if response.status == 200:
                        html = await response.text()
                        soup = BeautifulSoup(html, 'html.parser')
                        
                        for link in soup.find_all('a', href=True):
                            href = link['href']
                            if href.startswith('http') and 'bing.com' not in href:
                                results.append(href)
            
            return results[:5]
            
        except Exception as e:
            self.logger.debug(f"[-] Bing search error: {e}")
            return []
    
    async def _search_yandex(self, query: str) -> List[str]:
        """Search Yandex"""
        try:
            import aiohttp
            from bs4 import BeautifulSoup
            
            results = []
            search_url = f"https://yandex.com/search/?text={query}"
            
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.get(search_url, headers=headers, timeout=10) as response:
                    if response.status == 200:
                        html = await response.text()
                        soup = BeautifulSoup(html, 'html.parser')
                        
                        for link in soup.find_all('a', href=True):
                            href = link['href']
                            if href.startswith('http') and 'yandex' not in href:
                                results.append(href)
            
            return results[:5]
            
        except Exception as e:
            self.logger.debug(f"[-] Yandex search error: {e}")
            return []
    
    async def _specialized_search_techniques(self, query: str) -> List[str]:
        """Use specialized search techniques"""
        try:
            results = []
            
            # Shodan search
            try:
                shodan_results = await self._search_shodan(query)
                results.extend(shodan_results)
            except Exception as e:
                self.logger.debug(f"[-] Shodan search failed: {e}")
            
            # Censys search
            try:
                censys_results = await self._search_censys(query)
                results.extend(censys_results)
            except Exception as e:
                self.logger.debug(f"[-] Censys search failed: {e}")
            
            # GitHub search
            try:
                github_results = await self._search_github(query)
                results.extend(github_results)
            except Exception as e:
                self.logger.debug(f"[-] GitHub search failed: {e}")
            
            return results
            
        except Exception as e:
            self.logger.debug(f"[-] Specialized search techniques error: {e}")
            return []
    
    async def _search_shodan(self, query: str) -> List[str]:
        """Search Shodan"""
        try:
            # This would require Shodan API key
            # For now, return empty list
            return []
        except Exception as e:
            self.logger.debug(f"[-] Shodan search error: {e}")
            return []
    
    async def _search_censys(self, query: str) -> List[str]:
        """Search Censys"""
        try:
            # This would require Censys API key
            # For now, return empty list
            return []
        except Exception as e:
            self.logger.debug(f"[-] Censys search error: {e}")
            return []
    
    async def _search_github(self, query: str) -> List[str]:
        """Search GitHub"""
        try:
            import aiohttp
            from bs4 import BeautifulSoup
            
            results = []
            search_url = f"https://github.com/search?q={query}"
            
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.get(search_url, headers=headers, timeout=10) as response:
                    if response.status == 200:
                        html = await response.text()
                        soup = BeautifulSoup(html, 'html.parser')
                        
                        for link in soup.find_all('a', href=True):
                            href = link['href']
                            if href.startswith('/') and not href.startswith('//'):
                                full_url = f"https://github.com{href}"
                                results.append(full_url)
            
            return results[:5]
            
        except Exception as e:
            self.logger.debug(f"[-] GitHub search error: {e}")
            return []
    
    async def _dns_zone_transfer(self, domain: str) -> List[SubdomainResult]:
        """Attempt DNS zone transfer"""
        results = []
        
        try:
            # Get name servers
            resolver = dns.resolver.Resolver()
            ns_records = resolver.resolve(domain, 'NS')
            
            for ns_record in ns_records:
                ns_server = str(ns_record).rstrip('.')
                
                try:
                    # Attempt zone transfer
                    zone = dns.zone.from_xfr(dns.query.xfr(ns_server, domain))
                    
                    for name, node in zone.nodes.items():
                        if name != '@':  # Skip root record
                            subdomain = f"{name}.{domain}"
                            results.append(SubdomainResult(
                                subdomain=subdomain,
                                ip_address='unknown',
                                status='active',
                                response_time=0.0
                            ))
                
                except Exception:
                    # Zone transfer failed (expected in most cases)
                    continue
        
        except Exception as e:
            self.logger.debug(f"[-] DNS zone transfer failed: {e}")
        
        return results
    
    def _deduplicate_results(self, results: List[SubdomainResult]) -> List[SubdomainResult]:
        """Remove duplicate subdomain results"""
        seen = set()
        unique_results = []
        
        for result in results:
            if result.subdomain not in seen:
                seen.add(result.subdomain)
                unique_results.append(result)
        
        return unique_results
    
    async def _validate_subdomains(self, results: List[SubdomainResult]) -> List[SubdomainResult]:
        """Validate subdomains with HTTP requests"""
        validated_results = []
        
        # Create validation tasks
        tasks = []
        for result in results:
            task = self._validate_single_subdomain(result)
            tasks.append(task)
        
        # Execute validation concurrently
        validation_results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in validation_results:
            if isinstance(result, SubdomainResult):
                validated_results.append(result)
        
        return validated_results
    
    async def _validate_single_subdomain(self, result: SubdomainResult) -> SubdomainResult:
        """Validate a single subdomain"""
        try:
            # Try HTTP and HTTPS
            for protocol in ['http', 'https']:
                url = f"{protocol}://{result.subdomain}"
                
                try:
                    response = await self.async_engine.get(url, timeout=10)
                    
                    # Extract additional information
                    result.status = 'active'
                    result.status_code = response.status
                    result.response_time = response.response_time
                    
                    # Extract title and server info
                    if response.status == 200:
                        content = response.content.decode('utf-8', errors='ignore')
                        result.title = self._extract_title(content)
                        result.server = response.headers.get('Server', 'Unknown')
                    
                    return result
                
                except Exception:
                    continue
            
            # If no HTTP response, mark as inactive
            result.status = 'inactive'
            return result
            
        except Exception as e:
            self.logger.debug(f"[-] Validation failed for {result.subdomain}: {e}")
            result.status = 'unknown'
            return result
    
    def _extract_title(self, content: str) -> Optional[str]:
        """Extract page title from HTML content"""
        try:
            soup = BeautifulSoup(content, 'html.parser')
            title_tag = soup.find('title')
            if title_tag:
                return title_tag.get_text().strip()[:100]
        except Exception:
            pass
        return None


class PortScanner:
    """Advanced port scanner with service detection"""
    
    def __init__(self, logger: Logger):
        self.logger = logger
        self.results: List[PortResult] = []
        self.service_signatures = self._load_service_signatures()
        self.common_ports = [
            21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 993, 995,
            1723, 3306, 3389, 5432, 5900, 8080, 8443, 8888, 9090
        ]
    
    def _load_service_signatures(self) -> Dict[str, Dict[str, Any]]:
        """Load service detection signatures"""
        return {
            'ssh': {
                'ports': [22],
                'banner_pattern': r'SSH-\d+\.\d+',
                'response_pattern': r'SSH'
            },
            'http': {
                'ports': [80, 8080, 8000, 8888],
                'banner_pattern': r'HTTP/\d+\.\d+',
                'response_pattern': r'HTTP'
            },
            'https': {
                'ports': [443, 8443],
                'banner_pattern': None,
                'response_pattern': None
            },
            'ftp': {
                'ports': [21],
                'banner_pattern': r'220.*FTP',
                'response_pattern': r'FTP'
            },
            'smtp': {
                'ports': [25, 587, 465],
                'banner_pattern': r'220.*SMTP',
                'response_pattern': r'SMTP'
            },
            'pop3': {
                'ports': [110, 995],
                'banner_pattern': r'\+OK.*POP3',
                'response_pattern': r'POP3'
            },
            'imap': {
                'ports': [143, 993],
                'banner_pattern': r'\* OK.*IMAP',
                'response_pattern': r'IMAP'
            },
            'mysql': {
                'ports': [3306],
                'banner_pattern': r'\d+\.\d+\.\d+.*MySQL',
                'response_pattern': r'MySQL'
            },
            'postgresql': {
                'ports': [5432],
                'banner_pattern': None,
                'response_pattern': r'PostgreSQL'
            },
            'rdp': {
                'ports': [3389],
                'banner_pattern': None,
                'response_pattern': None
            },
            'telnet': {
                'ports': [23],
                'banner_pattern': r'Welcome|Login',
                'response_pattern': r'login|username'
            }
        }
    
    async def scan_host(self, host: str, ports: List[int] = None, scan_type: str = 'tcp_connect') -> List[PortResult]:
        """Scan a host for open ports"""
        if ports is None:
            ports = self.common_ports
        
        self.logger.info(f"[*] Scanning {host} on {len(ports)} ports")
        
        results = []
        
        if scan_type == 'tcp_connect':
            results = await self._tcp_connect_scan(host, ports)
        elif scan_type == 'tcp_syn':
            results = await self._tcp_syn_scan(host, ports)
        elif scan_type == 'udp':
            results = await self._udp_scan(host, ports)
        
        # Service detection
        for result in results:
            if result.state == 'open':
                service_info = await self._detect_service(host, result.port, result.protocol)
                result.service = service_info.get('service')
                result.version = service_info.get('version')
                result.banner = service_info.get('banner')
        
        self.results.extend(results)
        self.logger.info(f"[+] Port scan completed: {len([r for r in results if r.state == 'open'])} open ports")
        
        return results
    
    async def _tcp_connect_scan(self, host: str, ports: List[int]) -> List[PortResult]:
        """TCP connect scan"""
        results = []
        
        # Create scan tasks
        tasks = []
        for port in ports:
            task = self._scan_port(host, port, 'tcp')
            tasks.append(task)
        
        # Execute scans concurrently
        scan_results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in scan_results:
            if isinstance(result, PortResult):
                results.append(result)
        
        return results
    
    async def _tcp_syn_scan(self, host: str, ports: List[int]) -> List[PortResult]:
        """TCP SYN scan (requires raw sockets)"""
        # This would require raw socket access and is more complex
        # For now, fall back to TCP connect scan
        return await self._tcp_connect_scan(host, ports)
    
    async def _udp_scan(self, host: str, ports: List[int]) -> List[PortResult]:
        """UDP scan"""
        results = []
        
        # UDP scanning is more complex and less reliable
        # This is a simplified implementation
        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(3)
                
                # Send empty packet
                sock.sendto(b'', (host, port))
                
                try:
                    data, addr = sock.recvfrom(1024)
                    results.append(PortResult(
                        host=host,
                        port=port,
                        protocol='udp',
                        state='open',
                        response_time=0.0
                    ))
                except socket.timeout:
                    results.append(PortResult(
                        host=host,
                        port=port,
                        protocol='udp',
                        state='open|filtered',
                        response_time=3.0
                    ))
                
                sock.close()
            
            except Exception:
                results.append(PortResult(
                    host=host,
                    port=port,
                    protocol='udp',
                    state='closed',
                    response_time=0.0
                ))
        
        return results
    
    async def _scan_port(self, host: str, port: int, protocol: str) -> PortResult:
        """Scan a single port"""
        start_time = time.time()
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            
            result = sock.connect_ex((host, port))
            response_time = time.time() - start_time
            
            if result == 0:
                state = 'open'
            else:
                state = 'closed'
            
            sock.close()
            
            return PortResult(
                host=host,
                port=port,
                protocol=protocol,
                state=state,
                response_time=response_time
            )
        
        except Exception as e:
            return PortResult(
                host=host,
                port=port,
                protocol=protocol,
                state='filtered',
                response_time=time.time() - start_time
            )
    
    async def _detect_service(self, host: str, port: int, protocol: str) -> Dict[str, str]:
        """Detect service running on port"""
        service_info = {'service': 'unknown', 'version': None, 'banner': None}
        
        try:
            if protocol == 'tcp':
                # Connect and read banner
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                sock.connect((host, port))
                
                # Read banner
                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                service_info['banner'] = banner
                
                # Match against service signatures
                for service_name, signature in self.service_signatures.items():
                    if port in signature['ports']:
                        if signature['banner_pattern'] and re.search(signature['banner_pattern'], banner, re.IGNORECASE):
                            service_info['service'] = service_name
                            break
                        elif signature['response_pattern'] and re.search(signature['response_pattern'], banner, re.IGNORECASE):
                            service_info['service'] = service_name
                            break
                
                # Extract version if possible
                version_match = re.search(r'(\d+\.\d+\.\d+)', banner)
                if version_match:
                    service_info['version'] = version_match.group(1)
                
                sock.close()
        
        except Exception as e:
            self.logger.debug(f"[-] Service detection failed for {host}:{port}: {e}")
        
        return service_info


class TechnologyFingerprinter:
    """Advanced technology fingerprinting engine"""
    
    def __init__(self, logger: Logger, async_engine: AsyncEngine):
        self.logger = logger
        self.async_engine = async_engine
        self.technologies: List[TechnologyInfo] = []
        self.signatures = self._load_technology_signatures()
    
    def _load_technology_signatures(self) -> Dict[str, Dict[str, Any]]:
        """Load technology detection signatures"""
        return {
            # Web Servers
            'apache': {
                'headers': {'server': r'Apache/?(\d+\.\d+\.\d+)?'},
                'content': [r'<title>Apache HTTP Server'],
                'category': 'web_server'
            },
            'nginx': {
                'headers': {'server': r'nginx/?(\d+\.\d+\.\d+)?'},
                'content': [r'<title>Welcome to nginx'],
                'category': 'web_server'
            },
            'iis': {
                'headers': {'server': r'Microsoft-IIS/?(\d+\.\d+)?'},
                'content': [r'<title>IIS Windows Server'],
                'category': 'web_server'
            },
            
            # Frameworks
            'django': {
                'headers': {'x-frame-options': r'SAMEORIGIN'},
                'content': [r'csrfmiddlewaretoken', r'django'],
                'category': 'framework'
            },
            'flask': {
                'headers': {'server': r'Werkzeug'},
                'content': [r'<title>Flask'],
                'category': 'framework'
            },
            'laravel': {
                'headers': {'x-powered-by': r'Laravel'},
                'content': [r'_token', r'laravel_session'],
                'category': 'framework'
            },
            'rails': {
                'headers': {'x-request-id': r'[a-f0-9-]+', 'server': r'WEBrick'},
                'content': [r'<meta name="csrf-token"'],
                'category': 'framework'
            },
            
            # CMS
            'wordpress': {
                'headers': {'x-powered-by': r'WordPress'},
                'content': [r'/wp-content/', r'wp-includes', r'wp-admin'],
                'category': 'cms'
            },
            'joomla': {
                'headers': {'x-powered-by': r'Joomla'},
                'content': [r'/joomla/', r'<meta name="generator" content="Joomla'],
                'category': 'cms'
            },
            'drupal': {
                'headers': {'x-powered-by': r'Drupal'},
                'content': [r'/drupal/', r'<meta name="generator" content="Drupal'],
                'category': 'cms'
            },
            
            # Databases
            'mysql': {
                'headers': {'x-powered-by': r'MySQL'},
                'content': [r'mysql_connect', r'mysql_fetch_array'],
                'category': 'database'
            },
            'postgresql': {
                'headers': {'x-powered-by': r'PostgreSQL'},
                'content': [r'pg_connect', r'PostgreSQL'],
                'category': 'database'
            },
            
            # JavaScript Frameworks
            'jquery': {
                'content': [r'jquery\.js', r'jQuery'],
                'category': 'javascript_framework'
            },
            'angular': {
                'content': [r'angular\.js', r'ng-app', r'ng-controller'],
                'category': 'javascript_framework'
            },
            'react': {
                'content': [r'react\.js', r'ReactDOM'],
                'category': 'javascript_framework'
            },
            'vue': {
                'content': [r'vue\.js', r'v-if', r'v-for'],
                'category': 'javascript_framework'
            },
            
            # CDN
            'cloudflare': {
                'headers': {'server': r'cloudflare', 'cf-ray': r'[a-f0-9-]+'},
                'category': 'cdn'
            },
            'amazon_cloudfront': {
                'headers': {'server': r'AmazonCloudFront'},
                'category': 'cdn'
            }
        }
    
    async def fingerprint_target(self, url: str) -> List[TechnologyInfo]:
        """Fingerprint technologies used by target"""
        self.logger.info(f"[*] Fingerprinting technologies for {url}")
        
        technologies = []
        
        try:
            # Get HTTP response
            response = await self.async_engine.get(url)
            
            # Analyze headers
            header_technologies = self._analyze_headers(response.headers)
            technologies.extend(header_technologies)
            
            # Analyze content
            content = response.content.decode('utf-8', errors='ignore')
            content_technologies = self._analyze_content(content)
            technologies.extend(content_technologies)
            
            # Analyze DNS
            dns_technologies = await self._analyze_dns(url)
            technologies.extend(dns_technologies)
            
            # Remove duplicates
            unique_technologies = self._deduplicate_technologies(technologies)
            
            self.technologies.extend(unique_technologies)
            self.logger.info(f"[+] Technology fingerprinting completed: {len(unique_technologies)} technologies detected")
            
            return unique_technologies
            
        except Exception as e:
            self.logger.error(f"[-] Technology fingerprinting failed: {e}")
            return []
    
    def _analyze_headers(self, headers: Dict[str, str]) -> List[TechnologyInfo]:
        """Analyze HTTP headers for technology signatures"""
        technologies = []
        
        for tech_name, signature in self.signatures.items():
            if 'headers' in signature:
                for header_name, pattern in signature['headers'].items():
                    if header_name in headers:
                        header_value = headers[header_name]
                        match = re.search(pattern, header_value, re.IGNORECASE)
                        
                        if match:
                            version = match.group(1) if match.groups() else None
                            
                            tech = TechnologyInfo(
                                name=tech_name,
                                version=version,
                                confidence=0.9,
                                category=signature.get('category', 'unknown'),
                                detection_method='header'
                            )
                            technologies.append(tech)
        
        return technologies
    
    def _analyze_content(self, content: str) -> List[TechnologyInfo]:
        """Analyze HTML content for technology signatures"""
        technologies = []
        
        for tech_name, signature in self.signatures.items():
            if 'content' in signature:
                for pattern in signature['content']:
                    if re.search(pattern, content, re.IGNORECASE):
                        tech = TechnologyInfo(
                            name=tech_name,
                            confidence=0.8,
                            category=signature.get('category', 'unknown'),
                            detection_method='content'
                        )
                        technologies.append(tech)
                        break
        
        return technologies
    
    async def _analyze_dns(self, url: str) -> List[TechnologyInfo]:
        """Analyze DNS records for technology signatures"""
        technologies = []
        
        try:
            parsed_url = urlparse(url)
            domain = parsed_url.netloc
            
            # Check for CDN signatures in DNS
            try:
                resolver = dns.resolver.Resolver()
                
                # Check CNAME records
                cname_records = resolver.resolve(domain, 'CNAME')
                for record in cname_records:
                    cname_value = str(record).rstrip('.')
                    
                    # Check for CDN signatures
                    if 'cloudflare' in cname_value.lower():
                        tech = TechnologyInfo(
                            name='cloudflare',
                            confidence=0.9,
                            category='cdn',
                            detection_method='dns'
                        )
                        technologies.append(tech)
                    
                    elif 'amazonaws' in cname_value.lower():
                        tech = TechnologyInfo(
                            name='amazon_cloudfront',
                            confidence=0.9,
                            category='cdn',
                            detection_method='dns'
                        )
                        technologies.append(tech)
            
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                pass
        
        except Exception as e:
            self.logger.debug(f"[-] DNS analysis failed: {e}")
        
        return technologies
    
    def _deduplicate_technologies(self, technologies: List[TechnologyInfo]) -> List[TechnologyInfo]:
        """Remove duplicate technology detections"""
        seen = set()
        unique_technologies = []
        
        for tech in technologies:
            tech_key = (tech.name, tech.version)
            if tech_key not in seen:
                seen.add(tech_key)
                unique_technologies.append(tech)
        
        return unique_technologies


class SSLAnalyzer:
    """Comprehensive SSL/TLS analysis engine"""
    
    def __init__(self, logger: Logger):
        self.logger = logger
        self.results: List[SSLInfo] = []
        self.vulnerability_patterns = self._load_vulnerability_patterns()
    
    def _load_vulnerability_patterns(self) -> Dict[str, Dict[str, Any]]:
        """Load SSL vulnerability detection patterns"""
        return {
            'weak_ciphers': {
                'patterns': [r'RC4', r'DES', r'MD5', r'SHA1'],
                'severity': 'medium'
            },
            'weak_protocols': {
                'patterns': [r'SSLv2', r'SSLv3', r'TLSv1\.0'],
                'severity': 'high'
            },
            'weak_curves': {
                'patterns': [r'secp112r1', r'secp112r2'],
                'severity': 'medium'
            }
        }
    
    async def analyze_ssl(self, host: str, port: int = 443) -> SSLInfo:
        """Analyze SSL/TLS configuration"""
        self.logger.info(f"[*] Analyzing SSL/TLS for {host}:{port}")
        
        ssl_info = SSLInfo(host=host, port=port)
        
        try:
            # Create SSL context
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            # Connect and get certificate
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(10)
                sock.connect((host, port))
                
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    # Get certificate
                    cert = ssock.getpeercert()
                    ssl_info.certificate_info = self._analyze_certificate(cert)
                    
                    # Get cipher suite
                    cipher = ssock.cipher()
                    if cipher:
                        ssl_info.cipher_suite = cipher[0]
                        ssl_info.version = cipher[1]
                    
                    # Check for vulnerabilities
                    ssl_info.vulnerabilities = self._check_vulnerabilities(ssl_info)
                    
                    # Calculate grade and score
                    ssl_info.grade, ssl_info.score = self._calculate_grade(ssl_info)
        
        except Exception as e:
            self.logger.error(f"[-] SSL analysis failed for {host}:{port}: {e}")
        
        self.results.append(ssl_info)
        return ssl_info
    
    def _analyze_certificate(self, cert: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze SSL certificate"""
        cert_info = {}
        
        try:
            # Extract certificate details
            cert_info['subject'] = dict(x[0] for x in cert.get('subject', []))
            cert_info['issuer'] = dict(x[0] for x in cert.get('issuer', []))
            cert_info['version'] = cert.get('version')
            cert_info['serial_number'] = cert.get('serialNumber')
            cert_info['not_before'] = cert.get('notBefore')
            cert_info['not_after'] = cert.get('notAfter')
            cert_info['signature_algorithm'] = cert.get('signatureAlgorithm')
            
            # Check certificate validity
            import datetime
            now = datetime.datetime.now()
            not_after = datetime.datetime.strptime(cert_info['not_after'], '%b %d %H:%M:%S %Y %Z')
            
            if now > not_after:
                cert_info['expired'] = True
                cert_info['days_until_expiry'] = 0
            else:
                cert_info['expired'] = False
                cert_info['days_until_expiry'] = (not_after - now).days
            
            # Check for wildcard certificate
            subject_cn = cert_info['subject'].get('commonName', '')
            cert_info['is_wildcard'] = '*' in subject_cn
            
        except Exception as e:
            self.logger.error(f"[-] Certificate analysis failed: {e}")
        
        return cert_info
    
    def _check_vulnerabilities(self, ssl_info: SSLInfo) -> List[str]:
        """Check for SSL vulnerabilities"""
        vulnerabilities = []
        
        # Check cipher suite
        if ssl_info.cipher_suite:
            for vuln_type, vuln_info in self.vulnerability_patterns.items():
                for pattern in vuln_info['patterns']:
                    if re.search(pattern, ssl_info.cipher_suite, re.IGNORECASE):
                        vulnerabilities.append(f"{vuln_type}: {pattern}")
        
        # Check protocol version
        if ssl_info.version:
            for vuln_type, vuln_info in self.vulnerability_patterns.items():
                for pattern in vuln_info['patterns']:
                    if re.search(pattern, ssl_info.version, re.IGNORECASE):
                        vulnerabilities.append(f"{vuln_type}: {pattern}")
        
        # Check certificate issues
        cert_info = ssl_info.certificate_info
        if cert_info:
            if cert_info.get('expired', False):
                vulnerabilities.append('expired_certificate')
            
            if cert_info.get('is_wildcard', False):
                vulnerabilities.append('wildcard_certificate')
        
        return vulnerabilities
    
    def _calculate_grade(self, ssl_info: SSLInfo) -> Tuple[str, int]:
        """Calculate SSL grade and score"""
        score = 100
        
        # Deduct points for vulnerabilities
        for vulnerability in ssl_info.vulnerabilities:
            if 'weak_protocols' in vulnerability:
                score -= 30
            elif 'weak_ciphers' in vulnerability:
                score -= 20
            elif 'weak_curves' in vulnerability:
                score -= 15
            elif 'expired_certificate' in vulnerability:
                score -= 40
            elif 'wildcard_certificate' in vulnerability:
                score -= 10
        
        # Determine grade
        if score >= 95:
            grade = 'A+'
        elif score >= 90:
            grade = 'A'
        elif score >= 80:
            grade = 'B'
        elif score >= 70:
            grade = 'C'
        elif score >= 60:
            grade = 'D'
        else:
            grade = 'F'
        
        return grade, max(0, score)


class AdvancedReconnaissance:
    """Main reconnaissance engine combining all techniques"""
    
    def __init__(self, logger: Optional[Logger] = None, async_engine: Optional[AsyncEngine] = None):
        self.logger = logger or Logger()
        self.async_engine = async_engine or AsyncEngine()
        
        # Initialize components
        self.subdomain_enumerator = SubdomainEnumerator(self.logger, self.async_engine)
        self.port_scanner = PortScanner(self.logger)
        self.technology_fingerprinter = TechnologyFingerprinter(self.logger, self.async_engine)
        self.ssl_analyzer = SSLAnalyzer(self.logger)
    
    async def comprehensive_reconnaissance(self, target: str) -> Dict[str, Any]:
        """Perform comprehensive reconnaissance"""
        self.logger.info(f"[*] Starting comprehensive reconnaissance of {target}")
        
        results = {
            'target': target,
            'subdomains': [],
            'ports': [],
            'technologies': [],
            'ssl_info': [],
            'timestamp': time.time()
        }
        
        try:
            # Subdomain enumeration
            if target.startswith(('http://', 'https://')):
                domain = urlparse(target).netloc
            else:
                domain = target
            
            self.logger.info("[*] Running subdomain enumeration...")
            subdomains = await self.subdomain_enumerator.enumerate_subdomains(domain)
            results['subdomains'] = [self._subdomain_to_dict(s) for s in subdomains]
            
            # Port scanning for main domain
            self.logger.info("[*] Running port scan...")
            ports = await self.port_scanner.scan_host(domain)
            results['ports'] = [self._port_to_dict(p) for p in ports]
            
            # Technology fingerprinting
            self.logger.info("[*] Running technology fingerprinting...")
            if target.startswith(('http://', 'https://')):
                technologies = await self.technology_fingerprinter.fingerprint_target(target)
                results['technologies'] = [self._technology_to_dict(t) for t in technologies]
            
            # SSL analysis
            self.logger.info("[*] Running SSL analysis...")
            ssl_info = await self.ssl_analyzer.analyze_ssl(domain)
            results['ssl_info'] = self._ssl_to_dict(ssl_info)
            
            self.logger.info("[+] Comprehensive reconnaissance completed")
            
        except Exception as e:
            self.logger.error(f"[-] Reconnaissance failed: {e}")
        
        return results
    
    def _subdomain_to_dict(self, subdomain: SubdomainResult) -> Dict[str, Any]:
        """Convert SubdomainResult to dictionary"""
        return {
            'subdomain': subdomain.subdomain,
            'ip_address': subdomain.ip_address,
            'status': subdomain.status,
            'response_time': subdomain.response_time,
            'status_code': subdomain.status_code,
            'title': subdomain.title,
            'server': subdomain.server,
            'technology': subdomain.technology
        }
    
    def _port_to_dict(self, port: PortResult) -> Dict[str, Any]:
        """Convert PortResult to dictionary"""
        return {
            'host': port.host,
            'port': port.port,
            'protocol': port.protocol,
            'state': port.state,
            'service': port.service,
            'version': port.version,
            'banner': port.banner,
            'response_time': port.response_time
        }
    
    def _technology_to_dict(self, tech: TechnologyInfo) -> Dict[str, Any]:
        """Convert TechnologyInfo to dictionary"""
        return {
            'name': tech.name,
            'version': tech.version,
            'confidence': tech.confidence,
            'category': tech.category,
            'description': tech.description,
            'detection_method': tech.detection_method
        }
    
    def _ssl_to_dict(self, ssl_info: SSLInfo) -> Dict[str, Any]:
        """Convert SSLInfo to dictionary"""
        return {
            'host': ssl_info.host,
            'port': ssl_info.port,
            'version': ssl_info.version,
            'cipher_suite': ssl_info.cipher_suite,
            'certificate_info': ssl_info.certificate_info,
            'vulnerabilities': ssl_info.vulnerabilities,
            'grade': ssl_info.grade,
            'score': ssl_info.score
        }
    
    def get_reconnaissance_summary(self) -> Dict[str, Any]:
        """Get summary of reconnaissance results"""
        return {
            'subdomains_found': len(self.subdomain_enumerator.results),
            'open_ports': len([p for p in self.port_scanner.results if p.state == 'open']),
            'technologies_detected': len(self.technology_fingerprinter.technologies),
            'ssl_analyses': len(self.ssl_analyzer.results),
            'total_components': 4
        }
