"""
AresProbe AsyncIO Engine
Complete asynchronous engine for all network operations
"""

import asyncio
import aiohttp
import ssl
import time
from typing import Dict, List, Optional, Any, Union, Tuple
from dataclasses import dataclass, field
from concurrent.futures import ThreadPoolExecutor
import json
from urllib.parse import urljoin, urlparse
import logging

from .logger import Logger


@dataclass
class AsyncConfig:
    """Configuration for async operations"""
    max_concurrent_requests: int = 100
    timeout: float = 30.0
    max_retries: int = 3
    retry_delay: float = 1.0
    connection_limit: int = 100
    ttl_dns_cache: int = 300
    use_compression: bool = True
    verify_ssl: bool = False
    user_agent: str = "AresProbe/2.0"
    headers: Dict[str, str] = field(default_factory=dict)


@dataclass
class RequestResult:
    """Result of an async request"""
    url: str
    status: int
    headers: Dict[str, str]
    content: bytes
    response_time: float
    error: Optional[str] = None
    redirects: List[str] = field(default_factory=list)


class AsyncConnectionPool:
    """Advanced connection pooling for HTTP requests"""
    
    def __init__(self, config: AsyncConfig, logger: Logger):
        self.config = config
        self.logger = logger
        self.connector = None
        self.session = None
        self._semaphore = asyncio.Semaphore(config.max_concurrent_requests)
        
    async def __aenter__(self):
        """Async context manager entry"""
        await self._create_session()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        await self._close_session()
    
    async def _create_session(self):
        """Create aiohttp session with optimized settings"""
        # SSL context for better performance
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE if not self.config.verify_ssl else ssl.CERT_REQUIRED
        
        # Connector with connection pooling
        self.connector = aiohttp.TCPConnector(
            limit=self.config.connection_limit,
            limit_per_host=20,
            ttl_dns_cache=self.config.ttl_dns_cache,
            use_dns_cache=True,
            ssl=ssl_context,
            enable_cleanup_closed=True,
            force_close=True
        )
        
        # Session with optimized settings
        timeout = aiohttp.ClientTimeout(total=self.config.timeout)
        self.session = aiohttp.ClientSession(
            connector=self.connector,
            timeout=timeout,
            headers={'User-Agent': self.config.user_agent, **self.config.headers},
            auto_decompress=self.config.use_compression,
            read_timeout=self.config.timeout,
            conn_timeout=10
        )
        
        self.logger.info(f"[*] Async session created with {self.config.connection_limit} connections")
    
    async def _close_session(self):
        """Close aiohttp session"""
        if self.session:
            await self.session.close()
        if self.connector:
            await self.connector.close()
        self.logger.info("[*] Async session closed")
    
    async def request(self, method: str, url: str, **kwargs) -> RequestResult:
        """Make an async HTTP request"""
        async with self._semaphore:
            start_time = time.time()
            redirects = []
            
            for attempt in range(self.config.max_retries + 1):
                try:
                    async with self.session.request(method, url, **kwargs) as response:
                        content = await response.read()
                        response_time = time.time() - start_time
                        
                        return RequestResult(
                            url=str(response.url),
                            status=response.status,
                            headers=dict(response.headers),
                            content=content,
                            response_time=response_time,
                            redirects=redirects
                        )
                        
                except asyncio.TimeoutError:
                    if attempt < self.config.max_retries:
                        await asyncio.sleep(self.config.retry_delay * (attempt + 1))
                        continue
                    return RequestResult(
                        url=url,
                        status=0,
                        headers={},
                        content=b'',
                        response_time=time.time() - start_time,
                        error="Timeout"
                    )
                    
                except Exception as e:
                    if attempt < self.config.max_retries:
                        await asyncio.sleep(self.config.retry_delay * (attempt + 1))
                        continue
                    return RequestResult(
                        url=url,
                        status=0,
                        headers={},
                        content=b'',
                        response_time=time.time() - start_time,
                        error=str(e)
                    )
            
            return RequestResult(
                url=url,
                status=0,
                headers={},
                content=b'',
                response_time=time.time() - start_time,
                error="Max retries exceeded"
            )


class AsyncRateLimiter:
    """Intelligent rate limiting per target"""
    
    def __init__(self, logger: Logger):
        self.logger = logger
        self.rate_limits: Dict[str, Dict[str, Any]] = {}
        self.default_limits = {
            'requests_per_second': 10,
            'requests_per_minute': 300,
            'requests_per_hour': 10000
        }
    
    def _get_domain(self, url: str) -> str:
        """Extract domain from URL"""
        return urlparse(url).netloc.lower()
    
    def _update_limits(self, domain: str, response_time: float, status_code: int):
        """Update rate limits based on response"""
        if domain not in self.rate_limits:
            self.rate_limits[domain] = {
                'requests_per_second': self.default_limits['requests_per_second'],
                'requests_per_minute': self.default_limits['requests_per_minute'],
                'requests_per_hour': self.default_limits['requests_per_hour'],
                'last_requests': [],
                'avg_response_time': response_time,
                'error_rate': 0.0
            }
        
        limits = self.rate_limits[domain]
        current_time = time.time()
        
        # Update request history
        limits['last_requests'].append(current_time)
        
        # Clean old requests (keep only last hour)
        limits['last_requests'] = [
            req_time for req_time in limits['last_requests']
            if current_time - req_time < 3600
        ]
        
        # Update average response time
        limits['avg_response_time'] = (limits['avg_response_time'] + response_time) / 2
        
        # Update error rate
        recent_requests = [r for r in limits['last_requests'] if current_time - r < 60]
        error_requests = len([r for r in recent_requests if status_code >= 400])
        limits['error_rate'] = error_requests / len(recent_requests) if recent_requests else 0.0
        
        # Adaptive rate limiting
        if limits['error_rate'] > 0.1:  # High error rate
            limits['requests_per_second'] = max(1, limits['requests_per_second'] * 0.5)
        elif limits['avg_response_time'] > 5.0:  # Slow response
            limits['requests_per_second'] = max(1, limits['requests_per_second'] * 0.8)
        elif limits['error_rate'] < 0.01 and limits['avg_response_time'] < 1.0:  # Good performance
            limits['requests_per_second'] = min(50, limits['requests_per_second'] * 1.1)
    
    async def wait_if_needed(self, url: str):
        """Wait if rate limit would be exceeded"""
        domain = self._get_domain(url)
        
        if domain not in self.rate_limits:
            return
        
        limits = self.rate_limits[domain]
        current_time = time.time()
        
        # Check requests per second
        recent_requests = [
            req_time for req_time in limits['last_requests']
            if current_time - req_time < 1.0
        ]
        
        if len(recent_requests) >= limits['requests_per_second']:
            sleep_time = 1.0 - (current_time - recent_requests[0])
            if sleep_time > 0:
                await asyncio.sleep(sleep_time)
        
        # Check requests per minute
        minute_requests = [
            req_time for req_time in limits['last_requests']
            if current_time - req_time < 60.0
        ]
        
        if len(minute_requests) >= limits['requests_per_minute']:
            sleep_time = 60.0 - (current_time - minute_requests[0])
            if sleep_time > 0:
                await asyncio.sleep(sleep_time)


class AsyncEngine:
    """Complete AsyncIO engine for AresProbe"""
    
    def __init__(self, config: Optional[AsyncConfig] = None, logger: Optional[Logger] = None):
        self.config = config or AsyncConfig()
        self.logger = logger or Logger()
        self.connection_pool = AsyncConnectionPool(self.config, self.logger)
        self.rate_limiter = AsyncRateLimiter(self.logger)
        self.thread_pool = ThreadPoolExecutor(max_workers=10)
        self.active_tasks: Dict[str, asyncio.Task] = {}
        
    async def __aenter__(self):
        """Async context manager entry"""
        await self.connection_pool._create_session()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        await self._cleanup()
    
    async def _cleanup(self):
        """Cleanup resources"""
        # Cancel all active tasks
        for task_id, task in self.active_tasks.items():
            if not task.done():
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass
        
        # Close connection pool
        await self.connection_pool._close_session()
        
        # Shutdown thread pool
        self.thread_pool.shutdown(wait=True)
        
        self.logger.info("[*] AsyncEngine cleanup completed")
    
    async def request(self, method: str, url: str, **kwargs) -> RequestResult:
        """Make a single async request with rate limiting"""
        await self.rate_limiter.wait_if_needed(url)
        
        result = await self.connection_pool.request(method, url, **kwargs)
        
        # Update rate limiter
        self.rate_limiter._update_limits(url, result.response_time, result.status)
        
        return result
    
    async def request_batch(self, requests: List[Tuple[str, str, Dict]]) -> List[RequestResult]:
        """Make multiple async requests concurrently"""
        tasks = []
        
        for method, url, kwargs in requests:
            task = asyncio.create_task(self.request(method, url, **kwargs))
            tasks.append(task)
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Filter out exceptions
        valid_results = []
        for result in results:
            if isinstance(result, RequestResult):
                valid_results.append(result)
            else:
                self.logger.error(f"[-] Request failed: {result}")
        
        return valid_results
    
    async def get(self, url: str, **kwargs) -> RequestResult:
        """GET request"""
        return await self.request('GET', url, **kwargs)
    
    async def post(self, url: str, **kwargs) -> RequestResult:
        """POST request"""
        return await self.request('POST', url, **kwargs)
    
    async def put(self, url: str, **kwargs) -> RequestResult:
        """PUT request"""
        return await self.request('PUT', url, **kwargs)
    
    async def delete(self, url: str, **kwargs) -> RequestResult:
        """DELETE request"""
        return await self.request('DELETE', url, **kwargs)
    
    async def run_cpu_intensive(self, func, *args, **kwargs):
        """Run CPU-intensive operations in thread pool"""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(self.thread_pool, func, *args, **kwargs)
    
    def create_task(self, coro, task_id: str = None) -> str:
        """Create and track an async task"""
        if task_id is None:
            task_id = f"task_{len(self.active_tasks)}"
        
        task = asyncio.create_task(coro)
        self.active_tasks[task_id] = task
        
        return task_id
    
    async def cancel_task(self, task_id: str) -> bool:
        """Cancel a tracked task"""
        if task_id in self.active_tasks:
            task = self.active_tasks[task_id]
            if not task.done():
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass
            del self.active_tasks[task_id]
            return True
        return False
    
    async def wait_for_task(self, task_id: str, timeout: float = None):
        """Wait for a task to complete"""
        if task_id in self.active_tasks:
            task = self.active_tasks[task_id]
            return await asyncio.wait_for(task, timeout=timeout)
        return None
    
    def get_task_status(self, task_id: str) -> Optional[str]:
        """Get status of a tracked task"""
        if task_id in self.active_tasks:
            task = self.active_tasks[task_id]
            if task.done():
                if task.cancelled():
                    return "cancelled"
                elif task.exception():
                    return "failed"
                else:
                    return "completed"
            else:
                return "running"
        return None
    
    def get_active_tasks(self) -> Dict[str, str]:
        """Get status of all active tasks"""
        return {task_id: self.get_task_status(task_id) for task_id in self.active_tasks.keys()}
    
    async def health_check(self) -> Dict[str, Any]:
        """Perform health check on the async engine"""
        health = {
            'connection_pool': 'healthy',
            'rate_limiter': 'healthy',
            'thread_pool': 'healthy',
            'active_tasks': len(self.active_tasks)
        }
        
        try:
            # Test connection pool
            test_result = await self.get('https://httpbin.org/get', timeout=5)
            if test_result.status != 200:
                health['connection_pool'] = 'unhealthy'
        except Exception:
            health['connection_pool'] = 'unhealthy'
        
        return health


# Global async engine instance
_global_async_engine: Optional[AsyncEngine] = None


def get_async_engine() -> AsyncEngine:
    """Get global async engine instance"""
    global _global_async_engine
    if _global_async_engine is None:
        _global_async_engine = AsyncEngine()
    return _global_async_engine


async def init_async_engine(config: Optional[AsyncConfig] = None, logger: Optional[Logger] = None):
    """Initialize global async engine"""
    global _global_async_engine
    _global_async_engine = AsyncEngine(config, logger)
    await _global_async_engine.__aenter__()
    return _global_async_engine


async def cleanup_async_engine():
    """Cleanup global async engine"""
    global _global_async_engine
    if _global_async_engine:
        await _global_async_engine.__aexit__(None, None, None)
        _global_async_engine = None
