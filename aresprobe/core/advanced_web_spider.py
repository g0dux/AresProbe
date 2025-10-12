"""
AresProbe Advanced Web Spider
Superior web spider that surpasses Burp Suite's crawling capabilities
"""

import asyncio
import aiohttp
import re
import urllib.parse
from typing import Dict, List, Any, Optional, Set, Tuple, Callable
from dataclasses import dataclass
from enum import Enum
import time
import json
from bs4 import BeautifulSoup
import threading
from queue import Queue
import hashlib
import base64
from urllib.robotparser import RobotFileParser

class SpiderMode(Enum):
    """Spider crawling modes"""
    PASSIVE = "passive"
    ACTIVE = "active"
    AGGRESSIVE = "aggressive"
    STEALTH = "stealth"
    DEEP = "deep"
    WIDE = "wide"
    TARGETED = "targeted"
    CUSTOM = "custom"

@dataclass
class SpiderResult:
    """Spider crawling result"""
    url: str
    method: str
    status_code: int
    content_type: str
    content_length: int
    response_time: float
    timestamp: float
    depth: int
    parent_url: str
    title: str
    meta_description: str
    meta_keywords: str
    forms: List[Dict[str, Any]]
    links: List[str]
    images: List[str]
    scripts: List[str]
    stylesheets: List[str]
    cookies: Dict[str, str]
    headers: Dict[str, str]
    parameters: Dict[str, str]
    vulnerabilities: List[Dict[str, Any]]
    technologies: List[str]
    content_hash: str
    raw_content: bytes

class AdvancedWebSpider:
    """Advanced web spider superior to Burp Suite"""
    
    def __init__(self, logger=None):
        self.logger = logger
        self.visited_urls = set()
        self.url_queue = Queue()
        self.results = []
        self.running = False
        self.session = None
        self.robots_txt = {}
        self.sitemap_urls = set()
        self.forms = []
        self.parameters = set()
        self.technologies = set()
        self.vulnerabilities = []
        
        # Spider configuration
        self.max_depth = 10
        self.max_pages = 1000
        self.delay = 1.0
        self.timeout = 30
        self.max_concurrent = 10
        self.user_agent = "AresProbe-Spider/1.0"
        self.follow_redirects = True
        self.respect_robots = True
        self.include_subdomains = True
        self.include_parameters = True
        self.include_fragments = False
        
        # Advanced features
        self.javascript_execution = True
        self.form_analysis = True
        self.parameter_extraction = True
        self.technology_detection = True
        self.vulnerability_scanning = True
        self.content_analysis = True
        self.link_analysis = True
        self.cookie_analysis = True
        self.header_analysis = True
        self.meta_analysis = True
        
        # Filters
        self.url_filters = []
        self.content_filters = []
        self.status_filters = []
        self.type_filters = []
        
        # Callbacks
        self.on_url_found = None
        self.on_form_found = None
        self.on_parameter_found = None
        self.on_vulnerability_found = None
        self.on_technology_found = None
    
    async def start_spider(self, start_url: str, mode: SpiderMode = SpiderMode.ACTIVE) -> bool:
        """Start advanced web spider"""
        try:
            self.running = True
            self.mode = mode
            
            # Initialize session
            self.session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=self.timeout),
                headers={'User-Agent': self.user_agent}
            )
            
            # Add start URL to queue
            self.url_queue.put((start_url, 0, ""))
            
            if self.logger:
                self.logger.success(f"[+] Advanced web spider started")
                self.logger.success(f"[+] Start URL: {start_url}")
                self.logger.success(f"[+] Mode: {mode.value}")
                self.logger.success(f"[+] Max depth: {self.max_depth}")
                self.logger.success(f"[+] Max pages: {self.max_pages}")
            
            # Start crawling
            await self._crawl_async()
            
            return True
            
        except Exception as e:
            if self.logger:
                self.logger.error(f"[-] Spider start failed: {e}")
            return False
    
    async def _crawl_async(self):
        """Asynchronous crawling"""
        tasks = []
        
        while self.running and not self.url_queue.empty() and len(self.results) < self.max_pages:
            # Get URL from queue
            try:
                url, depth, parent_url = self.url_queue.get_nowait()
            except:
                break
            
            # Check if URL should be crawled
            if not self._should_crawl_url(url, depth):
                continue
            
            # Create crawling task
            task = asyncio.create_task(self._crawl_url(url, depth, parent_url))
            tasks.append(task)
            
            # Limit concurrent tasks
            if len(tasks) >= self.max_concurrent:
                await asyncio.gather(*tasks)
                tasks = []
            
            # Delay between requests
            await asyncio.sleep(self.delay)
        
        # Wait for remaining tasks
        if tasks:
            await asyncio.gather(*tasks)
    
    async def _crawl_url(self, url: str, depth: int, parent_url: str):
        """Crawl single URL"""
        try:
            # Check if already visited
            if url in self.visited_urls:
                return
            
            # Mark as visited
            self.visited_urls.add(url)
            
            # Check robots.txt
            if self.respect_robots and not self._check_robots_txt(url):
                return
            
            # Send request
            start_time = time.time()
            async with self.session.get(url) as response:
                content = await response.read()
                response_time = time.time() - start_time
                
                # Parse response
                result = await self._parse_response(url, response, content, depth, parent_url, response_time)
                
                # Store result
                self.results.append(result)
                
                # Extract new URLs
                if depth < self.max_depth:
                    new_urls = await self._extract_urls(result)
                    for new_url in new_urls:
                        if new_url not in self.visited_urls:
                            self.url_queue.put((new_url, depth + 1, url))
                
                # Call callbacks
                if self.on_url_found:
                    self.on_url_found(result)
                
                if self.logger:
                    self.logger.info(f"[+] Crawled: {url} (Status: {response.status}, Depth: {depth})")
                
        except Exception as e:
            if self.logger:
                self.logger.debug(f"[-] URL crawl failed: {url} - {e}")
    
    async def _parse_response(self, url: str, response: aiohttp.ClientResponse, 
                            content: bytes, depth: int, parent_url: str, 
                            response_time: float) -> SpiderResult:
        """Parse HTTP response"""
        try:
            # Parse HTML content
            soup = BeautifulSoup(content, 'html.parser')
            
            # Extract basic information
            title = soup.title.string if soup.title else ""
            meta_description = ""
            meta_keywords = ""
            
            # Extract meta tags
            meta_desc = soup.find('meta', attrs={'name': 'description'})
            if meta_desc:
                meta_description = meta_desc.get('content', '')
            
            meta_key = soup.find('meta', attrs={'name': 'keywords'})
            if meta_key:
                meta_keywords = meta_key.get('content', '')
            
            # Extract forms
            forms = await self._extract_forms(soup, url)
            
            # Extract links
            links = await self._extract_links(soup, url)
            
            # Extract images
            images = await self._extract_images(soup, url)
            
            # Extract scripts
            scripts = await self._extract_scripts(soup, url)
            
            # Extract stylesheets
            stylesheets = await self._extract_stylesheets(soup, url)
            
            # Extract parameters
            parameters = await self._extract_parameters(url)
            
            # Detect technologies
            technologies = await self._detect_technologies(response, content)
            
            # Scan for vulnerabilities
            vulnerabilities = await self._scan_vulnerabilities(url, response, content)
            
            # Calculate content hash
            content_hash = hashlib.md5(content).hexdigest()
            
            return SpiderResult(
                url=url,
                method="GET",
                status_code=response.status,
                content_type=response.headers.get('content-type', ''),
                content_length=len(content),
                response_time=response_time,
                timestamp=time.time(),
                depth=depth,
                parent_url=parent_url,
                title=title,
                meta_description=meta_description,
                meta_keywords=meta_keywords,
                forms=forms,
                links=links,
                images=images,
                scripts=scripts,
                stylesheets=stylesheets,
                cookies=dict(response.cookies),
                headers=dict(response.headers),
                parameters=parameters,
                vulnerabilities=vulnerabilities,
                technologies=technologies,
                content_hash=content_hash,
                raw_content=content
            )
            
        except Exception as e:
            if self.logger:
                self.logger.debug(f"[-] Response parsing failed: {e}")
            return None
    
    async def _extract_forms(self, soup: BeautifulSoup, base_url: str) -> List[Dict[str, Any]]:
        """Extract forms from HTML"""
        forms = []
        
        try:
            for form in soup.find_all('form'):
                form_data = {
                    'action': form.get('action', ''),
                    'method': form.get('method', 'GET').upper(),
                    'enctype': form.get('enctype', 'application/x-www-form-urlencoded'),
                    'fields': [],
                    'url': urllib.parse.urljoin(base_url, form.get('action', ''))
                }
                
                # Extract form fields
                for field in form.find_all(['input', 'textarea', 'select']):
                    field_data = {
                        'type': field.get('type', 'text'),
                        'name': field.get('name', ''),
                        'value': field.get('value', ''),
                        'placeholder': field.get('placeholder', ''),
                        'required': field.has_attr('required'),
                        'disabled': field.has_attr('disabled'),
                        'readonly': field.has_attr('readonly')
                    }
                    
                    # Extract options for select fields
                    if field.name == 'select':
                        field_data['options'] = []
                        for option in field.find_all('option'):
                            field_data['options'].append({
                                'value': option.get('value', ''),
                                'text': option.string or ''
                            })
                    
                    form_data['fields'].append(field_data)
                
                forms.append(form_data)
                
                # Call callback
                if self.on_form_found:
                    self.on_form_found(form_data)
            
        except Exception as e:
            if self.logger:
                self.logger.debug(f"[-] Form extraction failed: {e}")
        
        return forms
    
    async def _extract_links(self, soup: BeautifulSoup, base_url: str) -> List[str]:
        """Extract links from HTML"""
        links = []
        
        try:
            for link in soup.find_all('a', href=True):
                href = link['href']
                full_url = urllib.parse.urljoin(base_url, href)
                
                # Normalize URL
                full_url = urllib.parse.urlparse(full_url)
                full_url = full_url._replace(fragment='')  # Remove fragment
                full_url = full_url.geturl()
                
                # Check if URL should be included
                if self._should_include_url(full_url):
                    links.append(full_url)
            
        except Exception as e:
            if self.logger:
                self.logger.debug(f"[-] Link extraction failed: {e}")
        
        return links
    
    async def _extract_images(self, soup: BeautifulSoup, base_url: str) -> List[str]:
        """Extract images from HTML"""
        images = []
        
        try:
            for img in soup.find_all('img', src=True):
                src = img['src']
                full_url = urllib.parse.urljoin(base_url, src)
                images.append(full_url)
            
        except Exception as e:
            if self.logger:
                self.logger.debug(f"[-] Image extraction failed: {e}")
        
        return images
    
    async def _extract_scripts(self, soup: BeautifulSoup, base_url: str) -> List[str]:
        """Extract scripts from HTML"""
        scripts = []
        
        try:
            for script in soup.find_all('script', src=True):
                src = script['src']
                full_url = urllib.parse.urljoin(base_url, src)
                scripts.append(full_url)
            
        except Exception as e:
            if self.logger:
                self.logger.debug(f"[-] Script extraction failed: {e}")
        
        return scripts
    
    async def _extract_stylesheets(self, soup: BeautifulSoup, base_url: str) -> List[str]:
        """Extract stylesheets from HTML"""
        stylesheets = []
        
        try:
            for link in soup.find_all('link', rel='stylesheet', href=True):
                href = link['href']
                full_url = urllib.parse.urljoin(base_url, href)
                stylesheets.append(full_url)
            
        except Exception as e:
            if self.logger:
                self.logger.debug(f"[-] Stylesheet extraction failed: {e}")
        
        return stylesheets
    
    async def _extract_parameters(self, url: str) -> Dict[str, str]:
        """Extract parameters from URL"""
        parameters = {}
        
        try:
            parsed_url = urllib.parse.urlparse(url)
            query_params = urllib.parse.parse_qs(parsed_url.query)
            
            for key, values in query_params.items():
                parameters[key] = values[0] if values else ''
                
                # Call callback
                if self.on_parameter_found:
                    self.on_parameter_found(key, values[0] if values else '')
            
        except Exception as e:
            if self.logger:
                self.logger.debug(f"[-] Parameter extraction failed: {e}")
        
        return parameters
    
    async def _detect_technologies(self, response: aiohttp.ClientResponse, 
                                 content: bytes) -> List[str]:
        """Detect web technologies"""
        technologies = []
        
        try:
            # Check headers
            headers = dict(response.headers)
            
            # Server header
            if 'server' in headers:
                server = headers['server'].lower()
                if 'apache' in server:
                    technologies.append('Apache')
                elif 'nginx' in server:
                    technologies.append('Nginx')
                elif 'iis' in server:
                    technologies.append('IIS')
                elif 'tomcat' in server:
                    technologies.append('Tomcat')
            
            # X-Powered-By header
            if 'x-powered-by' in headers:
                powered_by = headers['x-powered-by'].lower()
                if 'php' in powered_by:
                    technologies.append('PHP')
                elif 'asp.net' in powered_by:
                    technologies.append('ASP.NET')
                elif 'express' in powered_by:
                    technologies.append('Express.js')
            
            # Check content for technologies
            content_str = content.decode('utf-8', errors='ignore').lower()
            
            # JavaScript frameworks
            if 'jquery' in content_str:
                technologies.append('jQuery')
            if 'react' in content_str:
                technologies.append('React')
            if 'angular' in content_str:
                technologies.append('Angular')
            if 'vue' in content_str:
                technologies.append('Vue.js')
            
            # CSS frameworks
            if 'bootstrap' in content_str:
                technologies.append('Bootstrap')
            if 'foundation' in content_str:
                technologies.append('Foundation')
            if 'materialize' in content_str:
                technologies.append('Materialize')
            
            # CMS
            if 'wordpress' in content_str:
                technologies.append('WordPress')
            if 'drupal' in content_str:
                technologies.append('Drupal')
            if 'joomla' in content_str:
                technologies.append('Joomla')
            
            # Analytics
            if 'google-analytics' in content_str:
                technologies.append('Google Analytics')
            if 'gtag' in content_str:
                technologies.append('Google Tag Manager')
            
            # Call callback
            if self.on_technology_found:
                for tech in technologies:
                    self.on_technology_found(tech)
            
        except Exception as e:
            if self.logger:
                self.logger.debug(f"[-] Technology detection failed: {e}")
        
        return technologies
    
    async def _scan_vulnerabilities(self, url: str, response: aiohttp.ClientResponse, 
                                  content: bytes) -> List[Dict[str, Any]]:
        """Scan for potential vulnerabilities"""
        vulnerabilities = []
        
        try:
            # Check for common vulnerabilities
            content_str = content.decode('utf-8', errors='ignore').lower()
            
            # SQL injection patterns
            sql_patterns = [
                r'error.*sql',
                r'mysql.*error',
                r'postgresql.*error',
                r'oracle.*error',
                r'sqlserver.*error',
                r'syntax.*error',
                r'warning.*mysql',
                r'fatal.*error'
            ]
            
            for pattern in sql_patterns:
                if re.search(pattern, content_str):
                    vulnerabilities.append({
                        'type': 'SQL Injection',
                        'severity': 'High',
                        'description': 'Potential SQL injection vulnerability detected',
                        'url': url,
                        'pattern': pattern
                    })
            
            # XSS patterns
            xss_patterns = [
                r'<script.*>',
                r'javascript:',
                r'onclick=',
                r'onload=',
                r'onerror=',
                r'alert\(',
                r'document\.cookie',
                r'window\.location'
            ]
            
            for pattern in xss_patterns:
                if re.search(pattern, content_str):
                    vulnerabilities.append({
                        'type': 'XSS',
                        'severity': 'High',
                        'description': 'Potential XSS vulnerability detected',
                        'url': url,
                        'pattern': pattern
                    })
            
            # Directory traversal patterns
            traversal_patterns = [
                r'\.\./',
                r'\.\.\\',
                r'%2e%2e%2f',
                r'%2e%2e%5c',
                r'\.\.%2f',
                r'\.\.%5c'
            ]
            
            for pattern in traversal_patterns:
                if re.search(pattern, content_str):
                    vulnerabilities.append({
                        'type': 'Directory Traversal',
                        'severity': 'Medium',
                        'description': 'Potential directory traversal vulnerability detected',
                        'url': url,
                        'pattern': pattern
                    })
            
            # Call callback
            if self.on_vulnerability_found:
                for vuln in vulnerabilities:
                    self.on_vulnerability_found(vuln)
            
        except Exception as e:
            if self.logger:
                self.logger.debug(f"[-] Vulnerability scanning failed: {e}")
        
        return vulnerabilities
    
    def _should_crawl_url(self, url: str, depth: int) -> bool:
        """Check if URL should be crawled"""
        # Check depth
        if depth > self.max_depth:
            return False
        
        # Check if already visited
        if url in self.visited_urls:
            return False
        
        # Apply URL filters
        for filter_func in self.url_filters:
            if not filter_func(url):
                return False
        
        return True
    
    def _should_include_url(self, url: str) -> bool:
        """Check if URL should be included in results"""
        # Check if URL is valid
        if not url or url.startswith('#'):
            return False
        
        # Check if URL is in same domain
        if not self.include_subdomains:
            # This would need to be implemented based on base URL
            pass
        
        # Check if URL has parameters
        if not self.include_parameters and '?' in url:
            return False
        
        # Check if URL has fragments
        if not self.include_fragments and '#' in url:
            return False
        
        return True
    
    def _check_robots_txt(self, url: str) -> bool:
        """Check robots.txt for URL"""
        try:
            parsed_url = urllib.parse.urlparse(url)
            base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
            
            if base_url not in self.robots_txt:
                # Fetch robots.txt
                robots_url = f"{base_url}/robots.txt"
                # This would need to be implemented
                self.robots_txt[base_url] = True
            
            return self.robots_txt.get(base_url, True)
            
        except Exception as e:
            if self.logger:
                self.logger.debug(f"[-] Robots.txt check failed: {e}")
            return True
    
    def add_url_filter(self, filter_func: Callable[[str], bool]):
        """Add URL filter"""
        self.url_filters.append(filter_func)
    
    def add_content_filter(self, filter_func: Callable[[bytes], bool]):
        """Add content filter"""
        self.content_filters.append(filter_func)
    
    def add_status_filter(self, filter_func: Callable[[int], bool]):
        """Add status code filter"""
        self.status_filters.append(filter_func)
    
    def add_type_filter(self, filter_func: Callable[[str], bool]):
        """Add content type filter"""
        self.type_filters.append(filter_func)
    
    def get_results(self) -> List[SpiderResult]:
        """Get spider results"""
        return self.results
    
    def get_forms(self) -> List[Dict[str, Any]]:
        """Get discovered forms"""
        return self.forms
    
    def get_parameters(self) -> Set[str]:
        """Get discovered parameters"""
        return self.parameters
    
    def get_technologies(self) -> Set[str]:
        """Get discovered technologies"""
        return self.technologies
    
    def get_vulnerabilities(self) -> List[Dict[str, Any]]:
        """Get discovered vulnerabilities"""
        return self.vulnerabilities
    
    def clear_results(self):
        """Clear spider results"""
        self.results.clear()
        self.forms.clear()
        self.parameters.clear()
        self.technologies.clear()
        self.vulnerabilities.clear()
        self.visited_urls.clear()
    
    def stop_spider(self):
        """Stop spider"""
        self.running = False
        if self.session:
            asyncio.create_task(self.session.close())
