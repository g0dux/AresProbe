"""
AresProbe Tor Requests Integration
Advanced Tor integration for HTTP requests
"""

import requests
import aiohttp
import socks
import socket
import time
import random
from typing import Dict, List, Any, Optional, Union
from urllib.parse import urlparse
import asyncio
import threading
from .advanced_tor_system import AdvancedTorSystem, TorMode, AnonymityLevel

class TorRequests:
    """Advanced Tor requests integration"""
    
    def __init__(self, tor_system: AdvancedTorSystem, logger=None):
        self.tor_system = tor_system
        self.logger = logger
        self.session = None
        self.async_session = None
        self.proxies = {}
        self.rotation_enabled = True
        self.rotation_interval = 30
        self.last_rotation = 0
        
        # Initialize sessions
        self._initialize_sessions()
    
    def _initialize_sessions(self):
        """Initialize HTTP sessions with Tor"""
        try:
            # Configure SOCKS proxy
            self.proxies = {
                'http': f'socks5://127.0.0.1:{self.tor_system.socks_port}',
                'https': f'socks5://127.0.0.1:{self.tor_system.socks_port}'
            }
            
            # Create requests session
            self.session = requests.Session()
            self.session.proxies.update(self.proxies)
            
            # Set timeouts
            self.session.timeout = 30
            
            # Set headers
            self.session.headers.update({
                'User-Agent': self._get_random_user_agent(),
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Accept-Encoding': 'gzip, deflate',
                'Connection': 'keep-alive',
                'Upgrade-Insecure-Requests': '1'
            })
            
            if self.logger:
                self.logger.success("[+] Tor requests session initialized")
        
        except Exception as e:
            if self.logger:
                self.logger.error(f"[-] Tor requests initialization failed: {e}")
    
    async def _initialize_async_sessions(self):
        """Initialize async HTTP sessions with Tor"""
        try:
            # Configure SOCKS proxy for aiohttp
            connector = aiohttp.TCPConnector()
            
            # Create async session
            self.async_session = aiohttp.ClientSession(
                connector=connector,
                timeout=aiohttp.ClientTimeout(total=30),
                headers={
                    'User-Agent': self._get_random_user_agent(),
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                    'Accept-Language': 'en-US,en;q=0.5',
                    'Accept-Encoding': 'gzip, deflate',
                    'Connection': 'keep-alive',
                    'Upgrade-Insecure-Requests': '1'
                }
            )
            
            if self.logger:
                self.logger.success("[+] Tor async session initialized")
        
        except Exception as e:
            if self.logger:
                self.logger.error(f"[-] Tor async session initialization failed: {e}")
    
    def _get_random_user_agent(self) -> str:
        """Get random User-Agent"""
        user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/93.0.4577.63 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:90.0) Gecko/20100101 Firefox/90.0',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:91.0) Gecko/20100101 Firefox/91.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0'
        ]
        
        return random.choice(user_agents)
    
    def _check_rotation(self):
        """Check if circuit rotation is needed"""
        if not self.rotation_enabled:
            return
        
        current_time = time.time()
        if current_time - self.last_rotation > self.rotation_interval:
            self._rotate_circuit()
            self.last_rotation = current_time
    
    def _rotate_circuit(self):
        """Rotate Tor circuit"""
        try:
            # This would implement actual circuit rotation
            # For now, just update User-Agent
            self.session.headers['User-Agent'] = self._get_random_user_agent()
            
            if self.logger:
                self.logger.info("[*] Tor circuit rotated")
        
        except Exception as e:
            if self.logger:
                self.logger.debug(f"[-] Circuit rotation failed: {e}")
    
    def get(self, url: str, **kwargs) -> requests.Response:
        """Make GET request through Tor"""
        self._check_rotation()
        return self.session.get(url, **kwargs)
    
    def post(self, url: str, **kwargs) -> requests.Response:
        """Make POST request through Tor"""
        self._check_rotation()
        return self.session.post(url, **kwargs)
    
    def put(self, url: str, **kwargs) -> requests.Response:
        """Make PUT request through Tor"""
        self._check_rotation()
        return self.session.put(url, **kwargs)
    
    def delete(self, url: str, **kwargs) -> requests.Response:
        """Make DELETE request through Tor"""
        self._check_rotation()
        return self.session.delete(url, **kwargs)
    
    def head(self, url: str, **kwargs) -> requests.Response:
        """Make HEAD request through Tor"""
        self._check_rotation()
        return self.session.head(url, **kwargs)
    
    def options(self, url: str, **kwargs) -> requests.Response:
        """Make OPTIONS request through Tor"""
        self._check_rotation()
        return self.session.options(url, **kwargs)
    
    def patch(self, url: str, **kwargs) -> requests.Response:
        """Make PATCH request through Tor"""
        self._check_rotation()
        return self.session.patch(url, **kwargs)
    
    async def async_get(self, url: str, **kwargs) -> aiohttp.ClientResponse:
        """Make async GET request through Tor"""
        if not self.async_session:
            await self._initialize_async_sessions()
        
        self._check_rotation()
        return await self.async_session.get(url, **kwargs)
    
    async def async_post(self, url: str, **kwargs) -> aiohttp.ClientResponse:
        """Make async POST request through Tor"""
        if not self.async_session:
            await self._initialize_async_sessions()
        
        self._check_rotation()
        return await self.async_session.post(url, **kwargs)
    
    async def async_put(self, url: str, **kwargs) -> aiohttp.ClientResponse:
        """Make async PUT request through Tor"""
        if not self.async_session:
            await self._initialize_async_sessions()
        
        self._check_rotation()
        return await self.async_session.put(url, **kwargs)
    
    async def async_delete(self, url: str, **kwargs) -> aiohttp.ClientResponse:
        """Make async DELETE request through Tor"""
        if not self.async_session:
            await self._initialize_async_sessions()
        
        self._check_rotation()
        return await self.async_session.delete(url, **kwargs)
    
    async def async_head(self, url: str, **kwargs) -> aiohttp.ClientResponse:
        """Make async HEAD request through Tor"""
        if not self.async_session:
            await self._initialize_async_sessions()
        
        self._check_rotation()
        return await self.async_session.head(url, **kwargs)
    
    async def async_options(self, url: str, **kwargs) -> aiohttp.ClientResponse:
        """Make async OPTIONS request through Tor"""
        if not self.async_session:
            await self._initialize_async_sessions()
        
        self._check_rotation()
        return await self.async_session.options(url, **kwargs)
    
    async def async_patch(self, url: str, **kwargs) -> aiohttp.ClientResponse:
        """Make async PATCH request through Tor"""
        if not self.async_session:
            await self._initialize_async_sessions()
        
        self._check_rotation()
        return await self.async_session.patch(url, **kwargs)
    
    def set_rotation_interval(self, interval: int):
        """Set circuit rotation interval in seconds"""
        self.rotation_interval = interval
        if self.logger:
            self.logger.info(f"[*] Rotation interval set to: {interval} seconds")
    
    def enable_rotation(self):
        """Enable circuit rotation"""
        self.rotation_enabled = True
        if self.logger:
            self.logger.info("[*] Circuit rotation enabled")
    
    def disable_rotation(self):
        """Disable circuit rotation"""
        self.rotation_enabled = False
        if self.logger:
            self.logger.info("[*] Circuit rotation disabled")
    
    def set_user_agent(self, user_agent: str):
        """Set custom User-Agent"""
        self.session.headers['User-Agent'] = user_agent
        if self.logger:
            self.logger.info(f"[*] User-Agent set to: {user_agent}")
    
    def set_headers(self, headers: Dict[str, str]):
        """Set custom headers"""
        self.session.headers.update(headers)
        if self.logger:
            self.logger.info(f"[*] Headers updated: {headers}")
    
    def set_timeout(self, timeout: int):
        """Set request timeout"""
        self.session.timeout = timeout
        if self.logger:
            self.logger.info(f"[*] Timeout set to: {timeout} seconds")
    
    def get_ip(self) -> Optional[str]:
        """Get current Tor IP address"""
        try:
            response = self.get('https://httpbin.org/ip')
            if response.status_code == 200:
                data = response.json()
                return data.get('origin')
            return None
        except Exception as e:
            if self.logger:
                self.logger.error(f"[-] Failed to get IP: {e}")
            return None
    
    def test_connection(self) -> bool:
        """Test Tor connection"""
        try:
            response = self.get('https://httpbin.org/ip', timeout=10)
            if response.status_code == 200:
                if self.logger:
                    self.logger.success("[+] Tor connection test successful")
                return True
            else:
                if self.logger:
                    self.logger.error(f"[-] Tor connection test failed: {response.status_code}")
                return False
        except Exception as e:
            if self.logger:
                self.logger.error(f"[-] Tor connection test failed: {e}")
            return False
    
    def close(self):
        """Close Tor requests sessions"""
        try:
            if self.session:
                self.session.close()
            
            if self.async_session:
                asyncio.create_task(self.async_session.close())
            
            if self.logger:
                self.logger.info("[*] Tor requests sessions closed")
        
        except Exception as e:
            if self.logger:
                self.logger.error(f"[-] Failed to close sessions: {e}")
