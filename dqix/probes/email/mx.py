from __future__ import annotations
from dataclasses import dataclass
from typing import Dict, List, Optional
import socket
import asyncio

from ..exceptions import MXProbeError
from ..utils import retry
from .base import EmailProbe, EmailProbeData

@dataclass
class MXData(EmailProbeData):
    """MX data."""
    mx_records: List[str]
    mx_priorities: Dict[str, int]
    mx_ttls: Dict[str, int]
    has_valid_mx: bool
    has_valid_ttl: bool = False
    has_valid_priorities: bool = False

class MXProbe(EmailProbe[MXData]):
    """Probe for checking MX records."""
    
    @retry(max_retries=3, initial_delay=1.0)
    async def _get_a_records(self, hostname: str) -> List[str]:
        """Get A records.
        
        Args:
            hostname: Hostname to check
            
        Returns:
            List of IP addresses
        """
        try:
            records = await self.dns_resolver.resolver.query(hostname, 'A')
            return [record.host for record in records]
        except Exception:
            return []
            
    async def collect_data(self, domain: str) -> MXData:
        """Collect MX data."""
        # Check cache first
        cached_data = self._get_cached_data(domain)
        if cached_data:
            return cached_data
            
        try:
            # Get DNS records
            dns_records = await self._get_dns_records(domain)
            
            if dns_records.error:
                raise MXProbeError(dns_records.error)
                
            # Process MX records
            mx_priorities = {}
            mx_ttls = {}
            
            for record in dns_records.mx_records:
                hostname = record.host
                mx_priorities[hostname] = record.priority
                mx_ttls[hostname] = record.ttl
                
            # Check TTL and priorities (optional)
            has_valid_ttl = False
            has_valid_priorities = False
            
            if mx_ttls:
                ttl = next(iter(mx_ttls.values()))
                has_valid_ttl = 300 <= ttl <= 3600
                
            if len(mx_priorities) > 1:
                priorities = sorted(mx_priorities.values())
                has_valid_priorities = priorities[0] < priorities[1]
                
            data = MXData(
                domain=domain,
                mx_records=[record.host for record in dns_records.mx_records],
                mx_priorities=mx_priorities,
                mx_ttls=mx_ttls,
                has_valid_mx=bool(dns_records.mx_records),
                has_valid_ttl=has_valid_ttl,
                has_valid_priorities=has_valid_priorities
            )
            
            # Cache result
            self._cache_data(domain, data)
            
            return data
            
        except Exception as e:
            return MXData(
                domain=domain,
                mx_records=[],
                mx_priorities={},
                mx_ttls={},
                has_valid_mx=False,
                has_valid_ttl=False,
                has_valid_priorities=False,
                error=str(e)
            )
            
    def calculate_score(self, data: MXData) -> float:
        """Calculate score.
        
        Level 1: Has valid MX records (0.4)
        Level 2: Multiple MX records (0.3)
        Level 3: Valid priorities and TTLs (0.3) - Optional
        """
        if data.error:
            return 0.0
            
        score = 0.0
        
        # Level 1: Basic MX check
        if data.has_valid_mx:
            score += 0.4
            
        # Level 2: Multiple MX records
        if len(data.mx_records) > 1:
            score += 0.3
            
        # Level 3: Advanced configuration (Optional)
        if data.has_valid_ttl and data.has_valid_priorities:
            score += 0.3
                
        return score
        
    def _create_data_from_cache(self, cached_data: Dict) -> MXData:
        """Create MXData from cached data."""
        return MXData(**cached_data) 