"""
AresProbe Cache Manager
Intelligent caching system for performance optimization
"""

import time
import hashlib
import json
import pickle
import threading
from typing import Dict, List, Optional, Any, Union, Callable
from dataclasses import dataclass
from enum import Enum
import os
from collections import OrderedDict

from .logger import Logger


class CachePolicy(Enum):
    """Cache eviction policies"""
    LRU = "lru"  # Least Recently Used
    LFU = "lfu"  # Least Frequently Used
    TTL = "ttl"  # Time To Live
    SIZE = "size"  # Size-based


@dataclass
class CacheEntry:
    """Cache entry with metadata"""
    key: str
    value: Any
    created_at: float
    last_accessed: float
    access_count: int
    size: int
    ttl: Optional[float] = None
    tags: List[str] = None
    
    def __post_init__(self):
        if self.tags is None:
            self.tags = []
    
    def is_expired(self) -> bool:
        """Check if entry is expired"""
        if self.ttl is None:
            return False
        return time.time() - self.created_at > self.ttl
    
    def get_age(self) -> float:
        """Get age of entry in seconds"""
        return time.time() - self.created_at
    
    def get_idle_time(self) -> float:
        """Get idle time in seconds"""
        return time.time() - self.last_accessed


class CacheManager:
    """
    Intelligent cache manager for AresProbe
    """
    
    def __init__(self, max_size: int = 1000, max_memory_mb: int = 100, 
                 policy: CachePolicy = CachePolicy.LRU, logger: Logger = None):
        self.logger = logger or Logger()
        self.max_size = max_size
        self.max_memory_bytes = max_memory_mb * 1024 * 1024
        self.policy = policy
        self.cache: Dict[str, CacheEntry] = {}
        self.access_order = OrderedDict()  # For LRU
        self.frequency_count: Dict[str, int] = {}  # For LFU
        self.current_memory = 0
        self.lock = threading.RLock()
        self.stats = {
            'hits': 0,
            'misses': 0,
            'evictions': 0,
            'insertions': 0,
            'updates': 0
        }
        
        # Cache tags for organized invalidation
        self.tag_index: Dict[str, set] = {}
        
        # Persistent cache settings
        self.persistent_cache_dir = "cache"
        self.persistent_cache_enabled = True
        self._ensure_cache_dir()
    
    def _ensure_cache_dir(self):
        """Ensure cache directory exists"""
        if self.persistent_cache_enabled:
            os.makedirs(self.persistent_cache_dir, exist_ok=True)
    
    def _calculate_size(self, value: Any) -> int:
        """Calculate approximate size of value in bytes"""
        try:
            if isinstance(value, (str, bytes)):
                return len(value)
            elif isinstance(value, (int, float, bool)):
                return 8
            elif isinstance(value, (list, tuple, dict)):
                return len(str(value).encode('utf-8'))
            else:
                return len(pickle.dumps(value))
        except:
            return 1024  # Default size if calculation fails
    
    def _generate_key(self, key: Union[str, tuple, dict]) -> str:
        """Generate cache key from various input types"""
        if isinstance(key, str):
            return key
        elif isinstance(key, (tuple, list)):
            return hashlib.md5(str(key).encode()).hexdigest()
        elif isinstance(key, dict):
            return hashlib.md5(json.dumps(key, sort_keys=True).encode()).hexdigest()
        else:
            return hashlib.md5(str(key).encode()).hexdigest()
    
    def get(self, key: Union[str, tuple, dict], default: Any = None) -> Any:
        """Get value from cache"""
        cache_key = self._generate_key(key)
        
        with self.lock:
            if cache_key in self.cache:
                entry = self.cache[cache_key]
                
                # Check if expired
                if entry.is_expired():
                    self._remove_entry(cache_key)
                    self.stats['misses'] += 1
                    return default
                
                # Update access information
                entry.last_accessed = time.time()
                entry.access_count += 1
                
                # Update access order for LRU
                if cache_key in self.access_order:
                    self.access_order.move_to_end(cache_key)
                
                # Update frequency for LFU
                self.frequency_count[cache_key] = self.frequency_count.get(cache_key, 0) + 1
                
                self.stats['hits'] += 1
                return entry.value
            else:
                self.stats['misses'] += 1
                return default
    
    def set(self, key: Union[str, tuple, dict], value: Any, ttl: Optional[float] = None, 
            tags: List[str] = None) -> bool:
        """Set value in cache"""
        cache_key = self._generate_key(key)
        
        with self.lock:
            # Calculate size
            size = self._calculate_size(value)
            
            # Check if we need to evict
            if cache_key not in self.cache:
                self._evict_if_needed(size)
            
            # Create cache entry
            entry = CacheEntry(
                key=cache_key,
                value=value,
                created_at=time.time(),
                last_accessed=time.time(),
                access_count=1,
                size=size,
                ttl=ttl,
                tags=tags or []
            )
            
            # Update memory usage
            if cache_key in self.cache:
                old_entry = self.cache[cache_key]
                self.current_memory -= old_entry.size
                self.stats['updates'] += 1
            else:
                self.stats['insertions'] += 1
            
            self.current_memory += size
            
            # Store entry
            self.cache[cache_key] = entry
            
            # Update access order for LRU
            self.access_order[cache_key] = True
            
            # Update frequency for LFU
            self.frequency_count[cache_key] = 1
            
            # Update tag index
            if tags:
                for tag in tags:
                    if tag not in self.tag_index:
                        self.tag_index[tag] = set()
                    self.tag_index[tag].add(cache_key)
            
            return True
    
    def delete(self, key: Union[str, tuple, dict]) -> bool:
        """Delete value from cache"""
        cache_key = self._generate_key(key)
        
        with self.lock:
            if cache_key in self.cache:
                self._remove_entry(cache_key)
                return True
            return False
    
    def _remove_entry(self, cache_key: str):
        """Remove entry from cache and update metadata"""
        if cache_key in self.cache:
            entry = self.cache[cache_key]
            
            # Update memory usage
            self.current_memory -= entry.size
            
            # Remove from access order
            if cache_key in self.access_order:
                del self.access_order[cache_key]
            
            # Remove from frequency count
            if cache_key in self.frequency_count:
                del self.frequency_count[cache_key]
            
            # Remove from tag index
            for tag in entry.tags:
                if tag in self.tag_index and cache_key in self.tag_index[tag]:
                    self.tag_index[tag].remove(cache_key)
                    if not self.tag_index[tag]:
                        del self.tag_index[tag]
            
            # Remove from cache
            del self.cache[cache_key]
    
    def _evict_if_needed(self, required_size: int):
        """Evict entries if cache is full"""
        while (len(self.cache) >= self.max_size or 
               self.current_memory + required_size > self.max_memory_bytes):
            
            if not self.cache:
                break
            
            # Choose entry to evict based on policy
            evict_key = self._choose_eviction_candidate()
            if evict_key:
                self._remove_entry(evict_key)
                self.stats['evictions'] += 1
            else:
                break
    
    def _choose_eviction_candidate(self) -> Optional[str]:
        """Choose which entry to evict based on policy"""
        if not self.cache:
            return None
        
        if self.policy == CachePolicy.LRU:
            # Remove least recently used
            return next(iter(self.access_order.keys()))
        
        elif self.policy == CachePolicy.LFU:
            # Remove least frequently used
            min_freq = min(self.frequency_count.values())
            for key, freq in self.frequency_count.items():
                if freq == min_freq:
                    return key
        
        elif self.policy == CachePolicy.TTL:
            # Remove oldest entry
            oldest_key = None
            oldest_time = float('inf')
            for key, entry in self.cache.items():
                if entry.created_at < oldest_time:
                    oldest_time = entry.created_at
                    oldest_key = key
            return oldest_key
        
        elif self.policy == CachePolicy.SIZE:
            # Remove largest entry
            largest_key = None
            largest_size = 0
            for key, entry in self.cache.items():
                if entry.size > largest_size:
                    largest_size = entry.size
                    largest_key = key
            return largest_key
        
        # Default: remove first entry
        return next(iter(self.cache.keys()))
    
    def invalidate_by_tag(self, tag: str) -> int:
        """Invalidate all entries with specific tag"""
        count = 0
        
        with self.lock:
            if tag in self.tag_index:
                keys_to_remove = list(self.tag_index[tag])
                for key in keys_to_remove:
                    self._remove_entry(key)
                    count += 1
                del self.tag_index[tag]
        
        return count
    
    def invalidate_pattern(self, pattern: str) -> int:
        """Invalidate entries matching pattern"""
        import re
        count = 0
        
        with self.lock:
            keys_to_remove = []
            for key in self.cache.keys():
                if re.search(pattern, key):
                    keys_to_remove.append(key)
            
            for key in keys_to_remove:
                self._remove_entry(key)
                count += 1
        
        return count
    
    def clear(self):
        """Clear all cache entries"""
        with self.lock:
            self.cache.clear()
            self.access_order.clear()
            self.frequency_count.clear()
            self.tag_index.clear()
            self.current_memory = 0
    
    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        with self.lock:
            total_requests = self.stats['hits'] + self.stats['misses']
            hit_rate = (self.stats['hits'] / total_requests * 100) if total_requests > 0 else 0
            
            return {
                'size': len(self.cache),
                'max_size': self.max_size,
                'memory_used_mb': self.current_memory / (1024 * 1024),
                'max_memory_mb': self.max_memory_bytes / (1024 * 1024),
                'hit_rate': hit_rate,
                'hits': self.stats['hits'],
                'misses': self.stats['misses'],
                'evictions': self.stats['evictions'],
                'insertions': self.stats['insertions'],
                'updates': self.stats['updates'],
                'policy': self.policy.value
            }
    
    def save_to_disk(self, filename: str = None) -> bool:
        """Save cache to disk"""
        if not self.persistent_cache_enabled:
            return False
        
        try:
            if filename is None:
                filename = os.path.join(self.persistent_cache_dir, "cache.pkl")
            
            with self.lock:
                cache_data = {
                    'cache': self.cache,
                    'stats': self.stats,
                    'timestamp': time.time()
                }
                
                with open(filename, 'wb') as f:
                    pickle.dump(cache_data, f)
                
                self.logger.info(f"[*] Cache saved to {filename}")
                return True
                
        except Exception as e:
            self.logger.error(f"[-] Error saving cache to disk: {e}")
            return False
    
    def load_from_disk(self, filename: str = None) -> bool:
        """Load cache from disk"""
        if not self.persistent_cache_enabled:
            return False
        
        try:
            if filename is None:
                filename = os.path.join(self.persistent_cache_dir, "cache.pkl")
            
            if not os.path.exists(filename):
                return False
            
            with open(filename, 'rb') as f:
                cache_data = pickle.load(f)
            
            with self.lock:
                # Check if cache is not too old (e.g., 24 hours)
                if time.time() - cache_data.get('timestamp', 0) > 86400:
                    self.logger.info("[*] Cache file is too old, skipping load")
                    return False
                
                self.cache = cache_data.get('cache', {})
                self.stats = cache_data.get('stats', self.stats)
                
                # Rebuild metadata
                self.access_order.clear()
                self.frequency_count.clear()
                self.tag_index.clear()
                self.current_memory = 0
                
                for key, entry in self.cache.items():
                    self.access_order[key] = True
                    self.frequency_count[key] = entry.access_count
                    self.current_memory += entry.size
                    
                    for tag in entry.tags:
                        if tag not in self.tag_index:
                            self.tag_index[tag] = set()
                        self.tag_index[tag].add(key)
                
                self.logger.info(f"[*] Cache loaded from {filename}")
                return True
                
        except Exception as e:
            self.logger.error(f"[-] Error loading cache from disk: {e}")
            return False
    
    def cleanup_expired(self) -> int:
        """Remove expired entries"""
        count = 0
        
        with self.lock:
            keys_to_remove = []
            for key, entry in self.cache.items():
                if entry.is_expired():
                    keys_to_remove.append(key)
            
            for key in keys_to_remove:
                self._remove_entry(key)
                count += 1
        
        return count
    
    def get_memory_usage(self) -> Dict[str, float]:
        """Get detailed memory usage information"""
        with self.lock:
            return {
                'used_mb': self.current_memory / (1024 * 1024),
                'max_mb': self.max_memory_bytes / (1024 * 1024),
                'usage_percent': (self.current_memory / self.max_memory_bytes) * 100,
                'entry_count': len(self.cache),
                'average_entry_size': self.current_memory / len(self.cache) if self.cache else 0
            }


class CacheDecorator:
    """Decorator for caching function results"""
    
    def __init__(self, cache_manager: CacheManager, ttl: float = None, 
                 tags: List[str] = None, key_func: Callable = None):
        self.cache_manager = cache_manager
        self.ttl = ttl
        self.tags = tags or []
        self.key_func = key_func
    
    def __call__(self, func):
        def wrapper(*args, **kwargs):
            # Generate cache key
            if self.key_func:
                cache_key = self.key_func(*args, **kwargs)
            else:
                cache_key = f"{func.__name__}:{hash(str(args) + str(sorted(kwargs.items())))}"
            
            # Try to get from cache
            result = self.cache_manager.get(cache_key)
            if result is not None:
                return result
            
            # Execute function
            result = func(*args, **kwargs)
            
            # Store in cache
            self.cache_manager.set(cache_key, result, ttl=self.ttl, tags=self.tags)
            
            return result
        
        return wrapper
