from __future__ import annotations
from dataclasses import dataclass
from typing import Dict, List, Optional
import aiodns
import asyncio

@dataclass
class DNSRecords:
    """DNS records for a domain."""
    domain: str
    txt_records: List[str]
    mx_records: List[aiodns.MXRecord]
    error: Optional[str] = None

class DNSResolver:
    """DNS resolver for email probes."""
    
    def __init__(self):
        """Initialize resolver."""
        self.resolver = aiodns.DNSResolver()
        self._cache: Dict[str, DNSRecords] = {}
        
    async def get_records(self, domain: str) -> DNSRecords:
        """Get all DNS records for a domain.
        
        Args:
            domain: Domain to check
            
        Returns:
            DNS records
        """
        # Check cache first
        if domain in self._cache:
            return self._cache[domain]
            
        try:
            # Get TXT and MX records concurrently
            txt_task = self.resolver.query(domain, 'TXT')
            mx_task = self.resolver.query(domain, 'MX')
            
            txt_records, mx_records = await asyncio.gather(
                txt_task,
                mx_task,
                return_exceptions=True
            )
            
            # Handle exceptions
            if isinstance(txt_records, Exception):
                txt_records = []
            else:
                txt_records = [record.text for record in txt_records]
                
            if isinstance(mx_records, Exception):
                mx_records = []
                
            records = DNSRecords(
                domain=domain,
                txt_records=txt_records,
                mx_records=mx_records
            )
            
            # Cache result
            self._cache[domain] = records
            
            return records
            
        except Exception as e:
            records = DNSRecords(
                domain=domain,
                txt_records=[],
                mx_records=[],
                error=str(e)
            )
            
            # Cache error result
            self._cache[domain] = records
            
            return records
            
    def clear_cache(self):
        """Clear DNS records cache."""
        self._cache.clear() 