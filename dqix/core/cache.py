from __future__ import annotations
from typing import TypeVar, Optional, Any, Dict
import time
from datetime import datetime

T = TypeVar('T')

class CacheEntry:
    """Cache entry."""
    
    def __init__(self, data: Any, ttl: int):
        """Initialize cache entry.
        
        Args:
            data: Data to cache
            ttl: Time to live in seconds
        """
        self.data = data
        self.created_at = time.time()
        self.ttl = ttl
        
    @property
    def is_expired(self) -> bool:
        """Check if entry is expired."""
        return time.time() - self.created_at > self.ttl

class ProbeCache:
    """Cache for probe results."""
    
    def __init__(
        self,
        maxsize: int = 1000,
        default_ttl: int = 3600  # 1 hour
    ):
        """Initialize cache.
        
        Args:
            maxsize: Maximum cache size
            default_ttl: Default time to live in seconds
        """
        self.maxsize = maxsize
        self.default_ttl = default_ttl
        self._cache: Dict[str, CacheEntry] = {}
        
    def _get_key(self, probe_id: str, domain: str) -> str:
        """Get cache key."""
        return f"probe:{probe_id}:{domain}"
        
    def _get_ttl(self, probe_id: str) -> int:
        """Get TTL for probe."""
        # Different TTLs for different probes
        ttl_map = {
            "dns": 300,  # 5 minutes
            "tls": 3600,  # 1 hour
            "http": 1800,  # 30 minutes
            "ip": 3600,  # 1 hour
            "whois": 86400,  # 24 hours
            "reputation": 3600,  # 1 hour
            "typosquat": 86400,  # 24 hours
            "mx": 3600,  # 1 hour
            "spf": 3600,  # 1 hour
            "dkim": 3600,  # 1 hour
            "dmarc": 3600,  # 1 hour
        }
        return ttl_map.get(probe_id, self.default_ttl)
        
    def _evict_oldest(self) -> None:
        """Evict oldest entry."""
        if not self._cache:
            return
            
        # Remove oldest
        key = min(self._cache.keys(), key=lambda k: self._cache[k].created_at)
        del self._cache[key]
        
    def get(self, probe_id: str, domain: str) -> Optional[Any]:
        """Get cached result."""
        key = self._get_key(probe_id, domain)
        entry = self._cache.get(key)
        
        if entry:
            if entry.is_expired:
                del self._cache[key]
                return None
            return entry.data
            
        return None
        
    def set(self, probe_id: str, domain: str, data: Any) -> None:
        """Set cached result."""
        key = self._get_key(probe_id, domain)
        
        # Remove oldest entry if cache is full
        if len(self._cache) >= self.maxsize:
            self._evict_oldest()
            
        self._cache[key] = CacheEntry(data, self._get_ttl(probe_id))
        
    def delete(self, probe_id: str, domain: str) -> None:
        """Delete cached result."""
        key = self._get_key(probe_id, domain)
        self._cache.pop(key, None)
        
    def clear(self) -> None:
        """Clear all cached results."""
        self._cache.clear() 