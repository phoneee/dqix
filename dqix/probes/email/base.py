from __future__ import annotations
from dataclasses import dataclass
from typing import Dict, List, Optional, TypeVar, Generic, Tuple
import re

from ...base import Probe, ProbeResult, ProbeCategory
from ...cache import ProbeCache
from .dns_resolver import DNSResolver, DNSRecords

T = TypeVar('T')

@dataclass
class EmailProbeData:
    """Base class for email probe data."""
    domain: str
    error: Optional[str] = None

class EmailProbe(Probe, Generic[T]):
    """Base class for email probes."""
    
    def __init__(self, cache: Optional[ProbeCache] = None, dns_resolver: Optional[DNSResolver] = None):
        """Initialize probe.
        
        Args:
            cache: Optional cache instance
            dns_resolver: Optional DNS resolver instance
        """
        super().__init__()
        self.category = ProbeCategory.EMAIL
        self.cache = cache
        self.dns_resolver = dns_resolver or DNSResolver()
        
    async def _get_dns_records(self, domain: str) -> DNSRecords:
        """Get DNS records for domain."""
        return await self.dns_resolver.get_records(domain)
        
    async def collect_data(self, domain: str) -> T:
        """Collect data.
        
        Args:
            domain: Domain to check
            
        Returns:
            Probe data
        """
        raise NotImplementedError
        
    async def run(self, domain: str) -> ProbeResult:
        """Run probe.
        
        Args:
            domain: Domain to check
            
        Returns:
            Probe result
        """
        data = await self.collect_data(domain)
        score = self.calculate_score(data)
        
        return ProbeResult(
            probe_id=self.id,
            domain=domain,
            score=score,
            data=data,
            category=self.category
        )
        
    def calculate_score(self, data: T) -> float:
        """Calculate score.
        
        Args:
            data: Probe data
            
        Returns:
            Score between 0 and 1
        """
        raise NotImplementedError
        
    def _validate_domain(self, domain: str) -> bool:
        """Validate domain name.
        
        Args:
            domain: Domain to validate
            
        Returns:
            True if valid, False otherwise
        """
        if not domain or len(domain) > 255:
            return False
            
        # Check domain format
        pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$'
        return bool(re.match(pattern, domain))
        
    def _get_cached_data(self, domain: str) -> Optional[T]:
        """Get cached data.
        
        Args:
            domain: Domain to check
            
        Returns:
            Cached data if exists, None otherwise
        """
        if self.cache:
            cached_data = self.cache.get(self.id, domain)
            if cached_data:
                return self._create_data_from_cache(cached_data)
        return None
        
    def _create_data_from_cache(self, cached_data: Dict) -> T:
        """Create data object from cached data.
        
        Args:
            cached_data: Cached data
            
        Returns:
            Data object
        """
        raise NotImplementedError
        
    def _cache_data(self, domain: str, data: T):
        """Cache data.
        
        Args:
            domain: Domain to cache
            data: Data to cache
        """
        if self.cache:
            self.cache.set(self.id, domain, data.__dict__)
        
    def _find_record(self, records: List[str], prefix: str) -> Optional[str]:
        """Find record with prefix."""
        for record in records:
            if record.startswith(prefix):
                return record
        return None
        
    def _parse_record(self, record: str, delimiter: str = ';') -> Dict[str, str]:
        """Parse record into key-value pairs."""
        result = {}
        parts = record.split(delimiter)
        
        for part in parts:
            part = part.strip()
            if '=' in part:
                key, value = part.split('=', 1)
                result[key] = value
                
        return result 