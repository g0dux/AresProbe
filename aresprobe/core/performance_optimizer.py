"""
AresProbe Performance Optimizer
Advanced performance optimization and memory management
"""

import os
import time
import psutil
import gc
import threading
import asyncio
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass
from enum import Enum
import concurrent.futures
from functools import wraps
import weakref
import tracemalloc

from .logger import Logger


class OptimizationLevel(Enum):
    """Performance optimization levels"""
    NONE = "none"
    BASIC = "basic"
    AGGRESSIVE = "aggressive"
    MAXIMUM = "maximum"


@dataclass
class PerformanceMetrics:
    """Performance metrics container"""
    cpu_usage: float
    memory_usage: float
    memory_available: float
    thread_count: int
    active_connections: int
    response_time_avg: float
    requests_per_second: float
    cache_hit_ratio: float
    gc_collections: int
    timestamp: float


@dataclass
class OptimizationConfig:
    """Performance optimization configuration"""
    max_memory_usage: float = 0.8  # 80% of available memory
    max_threads: int = 50
    max_connections: int = 100
    gc_threshold: int = 1000  # Trigger GC after N operations
    cache_size_limit: int = 10000
    response_time_threshold: float = 5.0  # seconds
    optimization_level: OptimizationLevel = OptimizationLevel.BASIC
    enable_profiling: bool = False
    enable_memory_tracking: bool = True


class MemoryManager:
    """Advanced memory management system"""
    
    def __init__(self, logger: Logger = None):
        self.logger = logger or Logger()
        self.memory_usage = {}
        self.weak_refs = weakref.WeakValueDictionary()
        self.memory_threshold = 0.8
        self.cleanup_callbacks = []
        
    def track_object(self, obj: Any, name: str = None) -> str:
        """Track object for memory management"""
        obj_id = id(obj)
        self.memory_usage[obj_id] = {
            'object': obj,
            'name': name or f"object_{obj_id}",
            'created_at': time.time(),
            'size': self._get_object_size(obj)
        }
        return str(obj_id)
    
    def _get_object_size(self, obj: Any) -> int:
        """Get approximate object size in bytes"""
        try:
            import sys
            return sys.getsizeof(obj)
        except:
            return 0
    
    def cleanup_old_objects(self, max_age: float = 3600) -> int:
        """Clean up objects older than max_age seconds"""
        current_time = time.time()
        cleaned_count = 0
        
        to_remove = []
        for obj_id, info in self.memory_usage.items():
            if current_time - info['created_at'] > max_age:
                to_remove.append(obj_id)
                cleaned_count += 1
        
        for obj_id in to_remove:
            del self.memory_usage[obj_id]
        
        if cleaned_count > 0:
            self.logger.info(f"[*] Cleaned up {cleaned_count} old objects")
        
        return cleaned_count
    
    def get_memory_usage(self) -> Dict[str, Any]:
        """Get current memory usage statistics"""
        process = psutil.Process()
        memory_info = process.memory_info()
        
        return {
            'rss': memory_info.rss,  # Resident Set Size
            'vms': memory_info.vms,  # Virtual Memory Size
            'percent': process.memory_percent(),
            'available': psutil.virtual_memory().available,
            'total': psutil.virtual_memory().total,
            'tracked_objects': len(self.memory_usage)
        }
    
    def force_garbage_collection(self) -> Dict[str, int]:
        """Force garbage collection and return statistics"""
        before = len(gc.get_objects())
        
        # Run garbage collection
        collected = gc.collect()
        
        after = len(gc.get_objects())
        
        stats = {
            'collected': collected,
            'objects_before': before,
            'objects_after': after,
            'objects_freed': before - after
        }
        
        self.logger.info(f"[*] Garbage collection: {collected} objects collected")
        return stats


class ThreadPoolManager:
    """Advanced thread pool management"""
    
    def __init__(self, logger: Logger = None):
        self.logger = logger or Logger()
        self.thread_pools = {}
        self.max_threads = 50
        self.active_tasks = {}
        self.task_counter = 0
        
    def get_thread_pool(self, name: str = "default", max_workers: int = None) -> concurrent.futures.ThreadPoolExecutor:
        """Get or create thread pool with specified name"""
        if name not in self.thread_pools:
            workers = max_workers or min(self.max_threads, (os.cpu_count() or 1) * 2)
            self.thread_pools[name] = concurrent.futures.ThreadPoolExecutor(
                max_workers=workers,
                thread_name_prefix=f"AresProbe-{name}"
            )
            self.logger.info(f"[+] Created thread pool '{name}' with {workers} workers")
        
        return self.thread_pools[name]
    
    def submit_task(self, func: Callable, *args, name: str = "default", **kwargs) -> concurrent.futures.Future:
        """Submit task to thread pool"""
        pool = self.get_thread_pool(name)
        future = pool.submit(func, *args, **kwargs)
        
        self.task_counter += 1
        task_id = self.task_counter
        self.active_tasks[task_id] = {
            'future': future,
            'function': func.__name__,
            'submitted_at': time.time(),
            'pool_name': name
        }
        
        return future
    
    def get_active_tasks(self) -> Dict[str, Any]:
        """Get information about active tasks"""
        current_time = time.time()
        active_info = {}
        
        for task_id, info in self.active_tasks.items():
            if not info['future'].done():
                active_info[task_id] = {
                    'function': info['function'],
                    'pool_name': info['pool_name'],
                    'running_time': current_time - info['submitted_at']
                }
        
        return active_info
    
    def cleanup_completed_tasks(self) -> int:
        """Remove completed tasks from tracking"""
        completed = []
        for task_id, info in self.active_tasks.items():
            if info['future'].done():
                completed.append(task_id)
        
        for task_id in completed:
            del self.active_tasks[task_id]
        
        return len(completed)
    
    def shutdown_all_pools(self):
        """Shutdown all thread pools"""
        for name, pool in self.thread_pools.items():
            self.logger.info(f"[*] Shutting down thread pool '{name}'")
            pool.shutdown(wait=True)
        
        self.thread_pools.clear()
        self.active_tasks.clear()


class ConnectionManager:
    """HTTP connection management and pooling"""
    
    def __init__(self, logger: Logger = None):
        self.logger = logger or Logger()
        self.connections = {}
        self.max_connections = 100
        self.connection_timeout = 30
        self.keep_alive = True
        
    def get_connection(self, host: str, port: int = 80, ssl: bool = False) -> Any:
        """Get or create connection to host"""
        key = f"{host}:{port}:{ssl}"
        
        if key not in self.connections:
            # In a real implementation, this would create actual connections
            self.connections[key] = {
                'host': host,
                'port': port,
                'ssl': ssl,
                'created_at': time.time(),
                'last_used': time.time(),
                'use_count': 0
            }
            self.logger.debug(f"[*] Created connection to {host}:{port}")
        
        conn = self.connections[key]
        conn['last_used'] = time.time()
        conn['use_count'] += 1
        
        return conn
    
    def cleanup_idle_connections(self, max_idle_time: float = 300) -> int:
        """Clean up idle connections"""
        current_time = time.time()
        to_remove = []
        
        for key, conn in self.connections.items():
            if current_time - conn['last_used'] > max_idle_time:
                to_remove.append(key)
        
        for key in to_remove:
            del self.connections[key]
        
        if to_remove:
            self.logger.info(f"[*] Cleaned up {len(to_remove)} idle connections")
        
        return len(to_remove)
    
    def get_connection_stats(self) -> Dict[str, Any]:
        """Get connection statistics"""
        total_connections = len(self.connections)
        active_connections = sum(1 for conn in self.connections.values() 
                               if time.time() - conn['last_used'] < 60)
        
        return {
            'total_connections': total_connections,
            'active_connections': active_connections,
            'idle_connections': total_connections - active_connections,
            'max_connections': self.max_connections
        }


class PerformanceOptimizer:
    """Main performance optimization engine"""
    
    def __init__(self, config: OptimizationConfig = None, logger: Logger = None):
        self.logger = logger or Logger()
        self.config = config or OptimizationConfig()
        self.memory_manager = MemoryManager(logger)
        self.thread_manager = ThreadPoolManager(logger)
        self.connection_manager = ConnectionManager(logger)
        
        self.metrics_history = []
        self.optimization_callbacks = []
        self.is_monitoring = False
        self.monitor_thread = None
        
        # Performance tracking
        self.operation_count = 0
        self.response_times = []
        self.request_count = 0
        self.start_time = time.time()
        
        # Enable memory tracking if configured
        if self.config.enable_memory_tracking:
            tracemalloc.start()
    
    def start_monitoring(self):
        """Start performance monitoring"""
        if self.is_monitoring:
            return
        
        self.is_monitoring = True
        self.monitor_thread = threading.Thread(target=self._monitor_performance, daemon=True)
        self.monitor_thread.start()
        self.logger.info("[+] Performance monitoring started")
    
    def stop_monitoring(self):
        """Stop performance monitoring"""
        self.is_monitoring = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5)
        self.logger.info("[+] Performance monitoring stopped")
    
    def _monitor_performance(self):
        """Background performance monitoring"""
        while self.is_monitoring:
            try:
                metrics = self.collect_metrics()
                self.metrics_history.append(metrics)
                
                # Keep only last 100 metrics
                if len(self.metrics_history) > 100:
                    self.metrics_history = self.metrics_history[-100:]
                
                # Check if optimization is needed
                if self._should_optimize(metrics):
                    self._perform_optimization(metrics)
                
                time.sleep(5)  # Monitor every 5 seconds
                
            except Exception as e:
                self.logger.error(f"[-] Performance monitoring error: {e}")
                time.sleep(10)
    
    def collect_metrics(self) -> PerformanceMetrics:
        """Collect current performance metrics"""
        process = psutil.Process()
        
        # CPU usage
        cpu_usage = process.cpu_percent()
        
        # Memory usage
        memory_info = process.memory_info()
        memory_usage = memory_info.rss / (1024 * 1024)  # MB
        memory_available = psutil.virtual_memory().available / (1024 * 1024)  # MB
        
        # Thread count
        thread_count = process.num_threads()
        
        # Active connections
        active_connections = self.connection_manager.get_connection_stats()['active_connections']
        
        # Response time average
        response_time_avg = sum(self.response_times) / len(self.response_times) if self.response_times else 0
        
        # Requests per second
        uptime = time.time() - self.start_time
        requests_per_second = self.request_count / uptime if uptime > 0 else 0
        
        # Cache hit ratio (placeholder)
        cache_hit_ratio = 0.8  # Would be calculated from actual cache stats
        
        # GC collections
        gc_collections = len(gc.get_objects())
        
        return PerformanceMetrics(
            cpu_usage=cpu_usage,
            memory_usage=memory_usage,
            memory_available=memory_available,
            thread_count=thread_count,
            active_connections=active_connections,
            response_time_avg=response_time_avg,
            requests_per_second=requests_per_second,
            cache_hit_ratio=cache_hit_ratio,
            gc_collections=gc_collections,
            timestamp=time.time()
        )
    
    def _should_optimize(self, metrics: PerformanceMetrics) -> bool:
        """Determine if optimization is needed"""
        if self.config.optimization_level == OptimizationLevel.NONE:
            return False
        
        # Check memory usage
        if metrics.memory_usage > self.config.max_memory_usage * 1024:  # Convert to MB
            return True
        
        # Check thread count
        if metrics.thread_count > self.config.max_threads:
            return True
        
        # Check response time
        if metrics.response_time_avg > self.config.response_time_threshold:
            return True
        
        # Check operation count for GC
        if self.operation_count > self.config.gc_threshold:
            return True
        
        return False
    
    def _perform_optimization(self, metrics: PerformanceMetrics):
        """Perform optimization based on metrics"""
        self.logger.info("[*] Performing performance optimization...")
        
        optimizations_applied = []
        
        # Memory optimization
        if metrics.memory_usage > self.config.max_memory_usage * 1024:
            self._optimize_memory()
            optimizations_applied.append("memory")
        
        # Thread optimization
        if metrics.thread_count > self.config.max_threads:
            self._optimize_threads()
            optimizations_applied.append("threads")
        
        # Connection optimization
        if metrics.active_connections > self.config.max_connections:
            self._optimize_connections()
            optimizations_applied.append("connections")
        
        # Garbage collection
        if self.operation_count > self.config.gc_threshold:
            self._force_garbage_collection()
            optimizations_applied.append("garbage_collection")
        
        if optimizations_applied:
            self.logger.success(f"[+] Applied optimizations: {', '.join(optimizations_applied)}")
        else:
            self.logger.info("[*] No optimizations needed")
    
    def _optimize_memory(self):
        """Optimize memory usage"""
        # Clean up old objects
        cleaned = self.memory_manager.cleanup_old_objects()
        
        # Force garbage collection
        self.memory_manager.force_garbage_collection()
        
        # Clear response time history if too large
        if len(self.response_times) > 1000:
            self.response_times = self.response_times[-500:]
        
        self.logger.info(f"[*] Memory optimization: cleaned {cleaned} objects")
    
    def _optimize_threads(self):
        """Optimize thread usage"""
        # Clean up completed tasks
        completed = self.thread_manager.cleanup_completed_tasks()
        
        # Shutdown idle thread pools
        # This would be implemented based on actual thread pool usage
        
        self.logger.info(f"[*] Thread optimization: cleaned {completed} completed tasks")
    
    def _optimize_connections(self):
        """Optimize connection usage"""
        # Clean up idle connections
        cleaned = self.connection_manager.cleanup_idle_connections()
        
        self.logger.info(f"[*] Connection optimization: cleaned {cleaned} idle connections")
    
    def _force_garbage_collection(self):
        """Force garbage collection"""
        stats = self.memory_manager.force_garbage_collection()
        self.operation_count = 0  # Reset counter
        
        self.logger.info(f"[*] Forced garbage collection: {stats['collected']} objects collected")
    
    def track_operation(self, operation_name: str):
        """Track operation for performance monitoring"""
        self.operation_count += 1
        
        # Add callback for operation tracking
        for callback in self.optimization_callbacks:
            try:
                callback(operation_name, self.operation_count)
            except Exception as e:
                self.logger.error(f"[-] Optimization callback error: {e}")
    
    def track_response_time(self, response_time: float):
        """Track response time for performance monitoring"""
        self.response_times.append(response_time)
        
        # Keep only last 1000 response times
        if len(self.response_times) > 1000:
            self.response_times = self.response_times[-1000:]
    
    def track_request(self):
        """Track request for performance monitoring"""
        self.request_count += 1
    
    def get_performance_report(self) -> Dict[str, Any]:
        """Get comprehensive performance report"""
        current_metrics = self.collect_metrics()
        
        # Calculate averages from history
        if self.metrics_history:
            avg_cpu = sum(m.cpu_usage for m in self.metrics_history) / len(self.metrics_history)
            avg_memory = sum(m.memory_usage for m in self.metrics_history) / len(self.metrics_history)
            avg_response_time = sum(m.response_time_avg for m in self.metrics_history) / len(self.metrics_history)
        else:
            avg_cpu = current_metrics.cpu_usage
            avg_memory = current_metrics.memory_usage
            avg_response_time = current_metrics.response_time_avg
        
        return {
            'current_metrics': {
                'cpu_usage': current_metrics.cpu_usage,
                'memory_usage_mb': current_metrics.memory_usage,
                'memory_available_mb': current_metrics.memory_available,
                'thread_count': current_metrics.thread_count,
                'active_connections': current_metrics.active_connections,
                'response_time_avg': current_metrics.response_time_avg,
                'requests_per_second': current_metrics.requests_per_second
            },
            'average_metrics': {
                'cpu_usage': avg_cpu,
                'memory_usage_mb': avg_memory,
                'response_time_avg': avg_response_time
            },
            'statistics': {
                'total_requests': self.request_count,
                'total_operations': self.operation_count,
                'uptime_seconds': time.time() - self.start_time,
                'metrics_collected': len(self.metrics_history)
            },
            'memory_stats': self.memory_manager.get_memory_usage(),
            'thread_stats': self.thread_manager.get_active_tasks(),
            'connection_stats': self.connection_manager.get_connection_stats()
        }
    
    def add_optimization_callback(self, callback: Callable):
        """Add optimization callback"""
        self.optimization_callbacks.append(callback)
    
    def remove_optimization_callback(self, callback: Callable):
        """Remove optimization callback"""
        if callback in self.optimization_callbacks:
            self.optimization_callbacks.remove(callback)
    
    def cleanup(self):
        """Cleanup performance optimizer"""
        self.stop_monitoring()
        self.thread_manager.shutdown_all_pools()
        self.memory_manager.cleanup_old_objects(max_age=0)  # Clean all objects
        
        if self.config.enable_memory_tracking:
            tracemalloc.stop()
        
        self.logger.info("[+] Performance optimizer cleaned up")


def performance_monitor(optimizer: PerformanceOptimizer):
    """Decorator for performance monitoring"""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            start_time = time.time()
            
            try:
                # Track operation
                optimizer.track_operation(func.__name__)
                
                # Execute function
                result = func(*args, **kwargs)
                
                # Track response time
                response_time = time.time() - start_time
                optimizer.track_response_time(response_time)
                
                return result
                
            except Exception as e:
                # Still track response time even on error
                response_time = time.time() - start_time
                optimizer.track_response_time(response_time)
                raise e
        
        return wrapper
    return decorator


# Global performance optimizer instance
_global_optimizer = None

def get_global_optimizer() -> PerformanceOptimizer:
    """Get global performance optimizer instance"""
    global _global_optimizer
    if _global_optimizer is None:
        _global_optimizer = PerformanceOptimizer()
    return _global_optimizer

def initialize_performance_optimizer(config: OptimizationConfig = None) -> PerformanceOptimizer:
    """Initialize global performance optimizer"""
    global _global_optimizer
    _global_optimizer = PerformanceOptimizer(config)
    return _global_optimizer