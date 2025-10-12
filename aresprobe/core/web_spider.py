"""
AresProbe Advanced Web Spider
Advanced web crawling and application mapping like Burp Suite
"""

import asyncio
import aiohttp
import re
import time
import random
from typing import Dict, List, Optional, Set, Any, Tuple
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from bs4 import BeautifulSoup
from dataclasses import dataclass
from enum import Enum
import threading
from concurrent.futures import ThreadPoolExecutor
import json
from collections import defaultdict

from .logger import Logger


class SpiderState(Enum):
    """Spider crawling states"""
    IDLE = "idle"
    CRAWLING = "crawling"
    PAUSED = "paused"
    STOPPED = "stopped"
    COMPLETED = "completed"


@dataclass
class CrawledURL:
    """Represents a crawled URL"""
    url: str
    method: str
    status_code: int
    content_type: str
    content_length: int
    response_time: float
    depth: int
    parent_url: Optional[str]
    forms: List[Dict[str, Any]]
    parameters: List[Dict[str, Any]]
    links: List[str]
    scripts: List[str]
    cookies: Dict[str, str]
    headers: Dict[str, str]
    timestamp: float


@dataclass
class FormData:
    """Represents a discovered form"""
    action: str
    method: str
    parameters: List[Dict[str, Any]]
    inputs: List[Dict[str, Any]]
    select_options: List[Dict[str, Any]]
    textareas: List[Dict[str, Any]]
    file_inputs: List[Dict[str, Any]]
    hidden_inputs: List[Dict[str, Any]]


@dataclass
class Parameter:
    """Represents a discovered parameter"""
    name: str
    value: str
    parameter_type: str  # GET, POST, COOKIE, HEADER
    source: str  # URL, FORM, AJAX, etc.
    required: bool
    input_type: str  # text, password, email, etc.


class AdvancedWebSpider:
    """
    Advanced web spider with comprehensive crawling capabilities
    Similar to Burp Suite Spider but with enhanced features
    """
    
    def __init__(self, logger: Logger = None):
        self.logger = logger or Logger()
        self.state = SpiderState.IDLE
        self.visited_urls: Set[str] = set()
        self.crawled_urls: List[CrawledURL] = []
        self.discovered_forms: List[FormData] = []
        self.discovered_parameters: List[Parameter] = []
        self.discovered_endpoints: List[str] = []
        self.discovered_links: Set[str] = set()
        self.discovered_scripts: Set[str] = set()
        self.discovered_apis: List[Dict[str, Any]] = []
        
        # Configuration
        self.max_depth = 10
        self.max_pages = 1000
        self.delay_between_requests = 0.1
        self.timeout = 30
        self.max_concurrent_requests = 10
        self.respect_robots_txt = True
        self.follow_redirects = True
        self.crawl_js_files = True
        self.crawl_css_files = False
        self.extract_parameters = True
        self.extract_forms = True
        self.extract_apis = True
        
        # User agents for rotation
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:89.0) Gecko/20100101 Firefox/89.0'
        ]
        
        # Common file extensions to ignore
        self.ignored_extensions = {
            '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.ico', '.svg', '.webp',
            '.mp3', '.mp4', '.avi', '.mov', '.wmv', '.flv', '.webm',
            '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
            '.zip', '.rar', '.7z', '.tar', '.gz', '.bz2',
            '.css', '.js', '.woff', '.woff2', '.ttf', '.eot'
        }
        
        # Session for making requests
        self.session = None
        self.semaphore = asyncio.Semaphore(self.max_concurrent_requests)
        
    async def crawl_application(self, base_url: str, config: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Crawl web application comprehensively
        """
        try:
            self.logger.info(f"[*] Starting comprehensive web crawl of {base_url}")
            self.state = SpiderState.CRAWLING
            
            # Apply configuration
            if config:
                self._apply_config(config)
            
            # Initialize session
            self.session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=self.timeout),
                headers={'User-Agent': random.choice(self.user_agents)}
            )
            
            # Start crawling from base URL
            await self._crawl_url(base_url, depth=0, parent_url=None)
            
            # Process discovered content
            await self._process_discovered_content()
            
            # Generate comprehensive report
            report = self._generate_crawl_report()
            
            self.state = SpiderState.COMPLETED
            self.logger.success(f"[+] Web crawl completed: {len(self.crawled_urls)} pages crawled")
            
            return report
            
        except Exception as e:
            self.logger.error(f"[-] Web crawl failed: {e}")
            self.state = SpiderState.STOPPED
            return {'error': str(e), 'success': False}
        finally:
            if self.session:
                await self.session.close()
    
    async def _crawl_url(self, url: str, depth: int, parent_url: Optional[str]):
        """Crawl a single URL"""
        if depth > self.max_depth or len(self.visited_urls) >= self.max_pages:
            return
        
        if url in self.visited_urls:
            return
        
        # Check if URL should be ignored
        if self._should_ignore_url(url):
            return
        
        async with self.semaphore:
            try:
                self.visited_urls.add(url)
                self.logger.info(f"[*] Crawling: {url} (depth: {depth})")
                
                # Make request
                start_time = time.time()
                response = await self._make_request(url)
                response_time = time.time() - start_time
                
                if response:
                    # Parse response
                    content = await response.text()
                    content_type = response.headers.get('content-type', '')
                    
                    # Extract information from response
                    forms = self._extract_forms(content, url)
                    parameters = self._extract_parameters(url, content)
                    links = self._extract_links(content, url)
                    scripts = self._extract_scripts(content, url)
                    apis = self._extract_api_endpoints(content, url)
                    
                    # Create crawled URL object
                    crawled_url = CrawledURL(
                        url=url,
                        method='GET',
                        status_code=response.status,
                        content_type=content_type,
                        content_length=len(content),
                        response_time=response_time,
                        depth=depth,
                        parent_url=parent_url,
                        forms=forms,
                        parameters=parameters,
                        links=links,
                        scripts=scripts,
                        cookies=dict(response.cookies),
                        headers=dict(response.headers),
                        timestamp=time.time()
                    )
                    
                    self.crawled_urls.append(crawled_url)
                    self.discovered_forms.extend([FormData(**form) for form in forms])
                    self.discovered_parameters.extend([Parameter(**param) for param in parameters])
                    self.discovered_links.update(links)
                    self.discovered_scripts.update(scripts)
                    self.discovered_apis.extend(apis)
                    
                    # Continue crawling discovered links
                    if depth < self.max_depth:
                        for link in links:
                            if link not in self.visited_urls:
                                await asyncio.sleep(self.delay_between_requests)
                                await self._crawl_url(link, depth + 1, url)
                
            except Exception as e:
                self.logger.debug(f"[-] Error crawling {url}: {e}")
    
    async def _make_request(self, url: str) -> Optional[aiohttp.ClientResponse]:
        """Make HTTP request with proper error handling"""
        try:
            # Rotate user agent
            headers = {'User-Agent': random.choice(self.user_agents)}
            
            async with self.session.get(url, headers=headers, allow_redirects=self.follow_redirects) as response:
                return response
                
        except Exception as e:
            self.logger.debug(f"[-] Request failed for {url}: {e}")
            return None
    
    def _should_ignore_url(self, url: str) -> bool:
        """Check if URL should be ignored"""
        try:
            parsed = urlparse(url)
            
            # Check file extension
            path = parsed.path.lower()
            for ext in self.ignored_extensions:
                if path.endswith(ext):
                    return True
            
            # Check for common non-content URLs
            ignore_patterns = [
                r'\.(css|js|png|jpg|jpeg|gif|ico|svg|woff|woff2|ttf|eot)$',
                r'/(admin|login|logout|register|signup|signin)/?$',
                r'\.(pdf|doc|docx|xls|xlsx|ppt|pptx)$',
                r'\.(zip|rar|7z|tar|gz)$'
            ]
            
            for pattern in ignore_patterns:
                if re.search(pattern, url, re.IGNORECASE):
                    return True
            
            return False
            
        except Exception:
            return True
    
    def _extract_forms(self, content: str, base_url: str) -> List[Dict[str, Any]]:
        """Extract forms from HTML content"""
        forms = []
        
        try:
            soup = BeautifulSoup(content, 'html.parser')
            
            for form in soup.find_all('form'):
                form_data = {
                    'action': form.get('action', ''),
                    'method': form.get('method', 'GET').upper(),
                    'parameters': [],
                    'inputs': [],
                    'select_options': [],
                    'textareas': [],
                    'file_inputs': [],
                    'hidden_inputs': []
                }
                
                # Extract form action URL
                action = form.get('action', '')
                if action:
                    form_data['action'] = urljoin(base_url, action)
                else:
                    form_data['action'] = base_url
                
                # Extract input fields
                for input_tag in form.find_all('input'):
                    input_data = {
                        'name': input_tag.get('name', ''),
                        'type': input_tag.get('type', 'text'),
                        'value': input_tag.get('value', ''),
                        'placeholder': input_tag.get('placeholder', ''),
                        'required': input_tag.has_attr('required')
                    }
                    
                    form_data['inputs'].append(input_data)
                    
                    # Categorize inputs
                    input_type = input_data['type'].lower()
                    if input_type == 'file':
                        form_data['file_inputs'].append(input_data)
                    elif input_type == 'hidden':
                        form_data['hidden_inputs'].append(input_data)
                    
                    # Add to parameters
                    if input_data['name']:
                        form_data['parameters'].append({
                            'name': input_data['name'],
                            'value': input_data['value'],
                            'type': input_data['type']
                        })
                
                # Extract select options
                for select in form.find_all('select'):
                    select_data = {
                        'name': select.get('name', ''),
                        'options': []
                    }
                    
                    for option in select.find_all('option'):
                        option_data = {
                            'value': option.get('value', ''),
                            'text': option.get_text(strip=True)
                        }
                        select_data['options'].append(option_data)
                    
                    form_data['select_options'].append(select_data)
                    
                    if select_data['name']:
                        form_data['parameters'].append({
                            'name': select_data['name'],
                            'value': '',
                            'type': 'select'
                        })
                
                # Extract textareas
                for textarea in form.find_all('textarea'):
                    textarea_data = {
                        'name': textarea.get('name', ''),
                        'value': textarea.get_text(strip=True),
                        'placeholder': textarea.get('placeholder', '')
                    }
                    
                    form_data['textareas'].append(textarea_data)
                    
                    if textarea_data['name']:
                        form_data['parameters'].append({
                            'name': textarea_data['name'],
                            'value': textarea_data['value'],
                            'type': 'textarea'
                        })
                
                forms.append(form_data)
                
        except Exception as e:
            self.logger.debug(f"[-] Error extracting forms: {e}")
        
        return forms
    
    def _extract_parameters(self, url: str, content: str) -> List[Dict[str, Any]]:
        """Extract parameters from URL and content"""
        parameters = []
        
        try:
            parsed = urlparse(url)
            
            # Extract URL parameters
            query_params = parse_qs(parsed.query)
            for name, values in query_params.items():
                for value in values:
                    parameters.append({
                        'name': name,
                        'value': value,
                        'parameter_type': 'GET',
                        'source': 'URL',
                        'required': False,
                        'input_type': 'text'
                    })
            
            # Extract parameters from JavaScript
            js_params = self._extract_js_parameters(content)
            parameters.extend(js_params)
            
            # Extract parameters from AJAX calls
            ajax_params = self._extract_ajax_parameters(content)
            parameters.extend(ajax_params)
            
        except Exception as e:
            self.logger.debug(f"[-] Error extracting parameters: {e}")
        
        return parameters
    
    def _extract_links(self, content: str, base_url: str) -> List[str]:
        """Extract links from HTML content"""
        links = []
        
        try:
            soup = BeautifulSoup(content, 'html.parser')
            
            # Extract <a> tags
            for link in soup.find_all('a', href=True):
                href = link['href']
                full_url = urljoin(base_url, href)
                if self._is_valid_url(full_url):
                    links.append(full_url)
            
            # Extract <link> tags
            for link in soup.find_all('link', href=True):
                href = link['href']
                full_url = urljoin(base_url, href)
                if self._is_valid_url(full_url):
                    links.append(full_url)
            
            # Extract JavaScript redirects
            js_links = self._extract_js_links(content, base_url)
            links.extend(js_links)
            
        except Exception as e:
            self.logger.debug(f"[-] Error extracting links: {e}")
        
        return links
    
    def _extract_scripts(self, content: str, base_url: str) -> List[str]:
        """Extract JavaScript files and inline scripts"""
        scripts = []
        
        try:
            soup = BeautifulSoup(content, 'html.parser')
            
            # Extract external script files
            for script in soup.find_all('script', src=True):
                src = script['src']
                full_url = urljoin(base_url, src)
                if self._is_valid_url(full_url):
                    scripts.append(full_url)
            
            # Extract inline scripts
            for script in soup.find_all('script', src=False):
                script_content = script.get_text()
                if script_content.strip():
                    scripts.append(f"inline:{script_content[:100]}...")
            
        except Exception as e:
            self.logger.debug(f"[-] Error extracting scripts: {e}")
        
        return scripts
    
    def _extract_api_endpoints(self, content: str, base_url: str) -> List[Dict[str, Any]]:
        """Extract API endpoints from content"""
        apis = []
        
        try:
            # Look for common API patterns
            api_patterns = [
                r'["\'](/api/[^"\']*)["\']',
                r'["\'](/v\d+/[^"\']*)["\']',
                r'["\'](/rest/[^"\']*)["\']',
                r'["\'](/graphql[^"\']*)["\']',
                r'["\'](/webhook/[^"\']*)["\']',
                r'["\'](/endpoint/[^"\']*)["\']'
            ]
            
            for pattern in api_patterns:
                matches = re.findall(pattern, content, re.IGNORECASE)
                for match in matches:
                    full_url = urljoin(base_url, match)
                    if self._is_valid_url(full_url):
                        apis.append({
                            'url': full_url,
                            'pattern': pattern,
                            'method': 'GET',  # Default, would need more analysis
                            'source': 'content_analysis'
                        })
            
            # Extract from JavaScript fetch/XMLHttpRequest calls
            js_apis = self._extract_js_api_calls(content, base_url)
            apis.extend(js_apis)
            
        except Exception as e:
            self.logger.debug(f"[-] Error extracting API endpoints: {e}")
        
        return apis
    
    def _extract_js_parameters(self, content: str) -> List[Dict[str, Any]]:
        """Extract parameters from JavaScript code"""
        parameters = []
        
        try:
            # Look for common parameter patterns in JS
            patterns = [
                r'["\']([a-zA-Z_][a-zA-Z0-9_]*)["\']\s*[:=]',
                r'\.([a-zA-Z_][a-zA-Z0-9_]*)\s*[:=]',
                r'getParameter\(["\']([^"\']+)["\']\)',
                r'getAttribute\(["\']([^"\']+)["\']\)'
            ]
            
            for pattern in patterns:
                matches = re.findall(pattern, content)
                for match in matches:
                    parameters.append({
                        'name': match,
                        'value': '',
                        'parameter_type': 'JS',
                        'source': 'JavaScript',
                        'required': False,
                        'input_type': 'text'
                    })
            
        except Exception as e:
            self.logger.debug(f"[-] Error extracting JS parameters: {e}")
        
        return parameters
    
    def _extract_ajax_parameters(self, content: str) -> List[Dict[str, Any]]:
        """Extract parameters from AJAX calls"""
        parameters = []
        
        try:
            # Look for AJAX parameter patterns
            patterns = [
                r'data\s*:\s*\{([^}]+)\}',
                r'params\s*:\s*\{([^}]+)\}',
                r'payload\s*:\s*\{([^}]+)\}'
            ]
            
            for pattern in patterns:
                matches = re.findall(pattern, content, re.DOTALL)
                for match in matches:
                    # Extract key-value pairs
                    kv_pattern = r'["\']([^"\']+)["\']\s*:\s*["\']?([^"\'},]+)["\']?'
                    kv_matches = re.findall(kv_pattern, match)
                    for key, value in kv_matches:
                        parameters.append({
                            'name': key,
                            'value': value,
                            'parameter_type': 'AJAX',
                            'source': 'AJAX',
                            'required': False,
                            'input_type': 'text'
                        })
            
        except Exception as e:
            self.logger.debug(f"[-] Error extracting AJAX parameters: {e}")
        
        return parameters
    
    def _extract_js_links(self, content: str, base_url: str) -> List[str]:
        """Extract links from JavaScript code"""
        links = []
        
        try:
            # Look for URL patterns in JavaScript
            patterns = [
                r'["\']([^"\']*\.(html|php|asp|aspx|jsp)[^"\']*)["\']',
                r'window\.location\s*=\s*["\']([^"\']+)["\']',
                r'location\.href\s*=\s*["\']([^"\']+)["\']',
                r'href\s*=\s*["\']([^"\']+)["\']'
            ]
            
            for pattern in patterns:
                matches = re.findall(pattern, content, re.IGNORECASE)
                for match in matches:
                    if isinstance(match, tuple):
                        match = match[0]
                    full_url = urljoin(base_url, match)
                    if self._is_valid_url(full_url):
                        links.append(full_url)
            
        except Exception as e:
            self.logger.debug(f"[-] Error extracting JS links: {e}")
        
        return links
    
    def _extract_js_api_calls(self, content: str, base_url: str) -> List[Dict[str, Any]]:
        """Extract API calls from JavaScript"""
        apis = []
        
        try:
            # Look for fetch/XMLHttpRequest calls
            patterns = [
                r'fetch\(["\']([^"\']+)["\']',
                r'\.open\(["\']([^"\']+)["\']\s*,\s*["\']([^"\']+)["\']',
                r'axios\.(get|post|put|delete)\(["\']([^"\']+)["\']',
                r'\.ajax\([^}]*url\s*:\s*["\']([^"\']+)["\']'
            ]
            
            for pattern in patterns:
                matches = re.findall(pattern, content, re.IGNORECASE)
                for match in matches:
                    if isinstance(match, tuple):
                        if len(match) == 2:  # method and URL
                            method, url = match
                        else:  # just URL
                            url = match[0]
                            method = 'GET'
                    else:
                        url = match
                        method = 'GET'
                    
                    full_url = urljoin(base_url, url)
                    if self._is_valid_url(full_url):
                        apis.append({
                            'url': full_url,
                            'method': method.upper(),
                            'pattern': pattern,
                            'source': 'JavaScript'
                        })
            
        except Exception as e:
            self.logger.debug(f"[-] Error extracting JS API calls: {e}")
        
        return apis
    
    def _is_valid_url(self, url: str) -> bool:
        """Check if URL is valid and should be crawled"""
        try:
            parsed = urlparse(url)
            return bool(parsed.netloc) and parsed.scheme in ['http', 'https']
        except Exception:
            return False
    
    async def _process_discovered_content(self):
        """Process all discovered content for additional insights"""
        try:
            self.logger.info("[*] Processing discovered content...")
            
            # Analyze forms for security issues
            self._analyze_forms_security()
            
            # Analyze parameters for injection points
            self._analyze_parameters_security()
            
            # Analyze API endpoints
            self._analyze_api_endpoints()
            
            # Generate endpoint map
            self._generate_endpoint_map()
            
        except Exception as e:
            self.logger.debug(f"[-] Error processing discovered content: {e}")
    
    def _analyze_forms_security(self):
        """Analyze forms for security issues"""
        for form in self.discovered_forms:
            # Check for common security issues
            issues = []
            
            # Check for password fields without HTTPS
            has_password = any(input_data['type'] == 'password' for input_data in form.inputs)
            if has_password and not form.action.startswith('https://'):
                issues.append('Password form without HTTPS')
            
            # Check for file upload forms
            has_file_upload = len(form.file_inputs) > 0
            if has_file_upload:
                issues.append('File upload form detected')
            
            # Check for hidden inputs (potential CSRF tokens)
            has_hidden = len(form.hidden_inputs) > 0
            if has_hidden:
                issues.append('Hidden inputs detected (potential CSRF tokens)')
            
            # Add issues to form data
            form.security_issues = issues
    
    def _analyze_parameters_security(self):
        """Analyze parameters for potential injection points"""
        for param in self.discovered_parameters:
            # Check for potential injection points
            issues = []
            
            # Check parameter name patterns
            if any(pattern in param.name.lower() for pattern in ['id', 'user', 'search', 'query', 'filter']):
                issues.append('Potential injection point')
            
            # Check for SQL-like parameter names
            if any(pattern in param.name.lower() for pattern in ['select', 'insert', 'update', 'delete', 'where', 'order']):
                issues.append('SQL-like parameter name')
            
            # Add issues to parameter data
            param.security_issues = issues
    
    def _analyze_api_endpoints(self):
        """Analyze API endpoints for security issues"""
        for api in self.discovered_apis:
            # Check for common API security issues
            issues = []
            
            # Check for versioning
            if '/v' in api['url']:
                issues.append('Versioned API endpoint')
            
            # Check for authentication
            if any(auth_word in api['url'].lower() for auth_word in ['auth', 'login', 'token', 'key']):
                issues.append('Authentication-related endpoint')
            
            # Add issues to API data
            api['security_issues'] = issues
    
    def _generate_endpoint_map(self):
        """Generate comprehensive endpoint map"""
        self.endpoint_map = {
            'urls': list(self.visited_urls),
            'forms': [form.__dict__ for form in self.discovered_forms],
            'parameters': [param.__dict__ for param in self.discovered_parameters],
            'apis': self.discovered_apis,
            'scripts': list(self.discovered_scripts),
            'links': list(self.discovered_links)
        }
    
    def _generate_crawl_report(self) -> Dict[str, Any]:
        """Generate comprehensive crawl report"""
        return {
            'success': True,
            'crawl_summary': {
                'total_urls_crawled': len(self.crawled_urls),
                'total_forms_discovered': len(self.discovered_forms),
                'total_parameters_discovered': len(self.discovered_parameters),
                'total_apis_discovered': len(self.discovered_apis),
                'total_scripts_discovered': len(self.discovered_scripts),
                'total_links_discovered': len(self.discovered_links),
                'crawl_depth': max([url.depth for url in self.crawled_urls]) if self.crawled_urls else 0
            },
            'crawled_urls': [url.__dict__ for url in self.crawled_urls],
            'discovered_forms': [form.__dict__ for form in self.discovered_forms],
            'discovered_parameters': [param.__dict__ for param in self.discovered_parameters],
            'discovered_apis': self.discovered_apis,
            'endpoint_map': self.endpoint_map,
            'security_analysis': self._generate_security_analysis()
        }
    
    def _generate_security_analysis(self) -> Dict[str, Any]:
        """Generate security analysis of discovered content"""
        analysis = {
            'potential_injection_points': 0,
            'file_upload_forms': 0,
            'authentication_forms': 0,
            'api_endpoints': len(self.discovered_apis),
            'hidden_inputs': 0,
            'security_issues': []
        }
        
        # Count security-relevant findings
        for form in self.discovered_forms:
            if len(form.file_inputs) > 0:
                analysis['file_upload_forms'] += 1
            if any(input_data['type'] == 'password' for input_data in form.inputs):
                analysis['authentication_forms'] += 1
            if len(form.hidden_inputs) > 0:
                analysis['hidden_inputs'] += 1
        
        for param in self.discovered_parameters:
            if hasattr(param, 'security_issues') and param.security_issues:
                analysis['potential_injection_points'] += 1
        
        return analysis
    
    def _apply_config(self, config: Dict[str, Any]):
        """Apply configuration settings"""
        self.max_depth = config.get('max_depth', self.max_depth)
        self.max_pages = config.get('max_pages', self.max_pages)
        self.delay_between_requests = config.get('delay', self.delay_between_requests)
        self.timeout = config.get('timeout', self.timeout)
        self.max_concurrent_requests = config.get('max_concurrent', self.max_concurrent_requests)
        self.respect_robots_txt = config.get('respect_robots', self.respect_robots_txt)
        self.follow_redirects = config.get('follow_redirects', self.follow_redirects)
        self.crawl_js_files = config.get('crawl_js', self.crawl_js_files)
        self.crawl_css_files = config.get('crawl_css', self.crawl_css_files)
        self.extract_parameters = config.get('extract_parameters', self.extract_parameters)
        self.extract_forms = config.get('extract_forms', self.extract_forms)
        self.extract_apis = config.get('extract_apis', self.extract_apis)
    
    def get_crawl_statistics(self) -> Dict[str, Any]:
        """Get current crawl statistics"""
        return {
            'state': self.state.value,
            'urls_visited': len(self.visited_urls),
            'urls_crawled': len(self.crawled_urls),
            'forms_discovered': len(self.discovered_forms),
            'parameters_discovered': len(self.discovered_parameters),
            'apis_discovered': len(self.discovered_apis)
        }
    
    def pause_crawl(self):
        """Pause the crawling process"""
        self.state = SpiderState.PAUSED
        self.logger.info("[*] Web crawl paused")
    
    def resume_crawl(self):
        """Resume the crawling process"""
        if self.state == SpiderState.PAUSED:
            self.state = SpiderState.CRAWLING
            self.logger.info("[*] Web crawl resumed")
    
    def stop_crawl(self):
        """Stop the crawling process"""
        self.state = SpiderState.STOPPED
        self.logger.info("[*] Web crawl stopped")
