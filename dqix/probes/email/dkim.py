from __future__ import annotations
from typing import Tuple, Dict, Any, List, Optional
from dataclasses import dataclass
import re
import aiodns
import base64
import hashlib

import dns.resolver

from .base import Probe, ProbeData, ScoreCalculator, EmailProbe, EmailProbeData
from . import register
from ..utils.dns import get_txt_records
from ..base import ProbeResult, ProbeCategory
from ..cache import ProbeCache
from ..exceptions import DKIMProbeError
from ..utils import retry
from .dns_resolver import DNSResolver

@dataclass
class DKIMData(EmailProbeData):
    """DKIM data."""
    selector: str
    dkim_record: Optional[str]
    public_key: Optional[str]
    key_size: Optional[int]
    has_valid_dkim: bool

class DKIMScoreCalculator(ScoreCalculator):
    """Calculate score for DKIM probe."""
    
    def calculate_score(self, data: DKIMData) -> Tuple[float, Dict[str, Any]]:
        """Calculate score from DKIM data.
        
        Scoring logic (0–1):
            • Has valid DKIM record (0.4)
            • Has valid public key (0.3)
            • Has strong key (0.3)
        """
        if data.error:
            return 0.0, {"error": data.error}
            
        score = 0.0
        details = {}
        
        # Check for valid DKIM record
        if data.has_valid_dkim:
            score += 0.4
            details["dkim"] = "valid"
        else:
            details["dkim"] = "missing"
            
        # Check for valid public key
        if data.public_key:
            score += 0.3
            details["public_key"] = "valid"
        else:
            details["public_key"] = "missing"
            
        # Check for strong key
        if data.key_size and data.key_size >= 2048:
            score += 0.2
            details["key_size"] = "sufficient"
        else:
            details["key_size"] = "insufficient"
            
        # Check for valid selector
        if data.selector and re.match(r'^[a-zA-Z0-9._-]+$', data.selector):
            score += 0.2
            details["selector"] = "valid"
        else:
            details["selector"] = "invalid"
            
        details["dkim_record"] = data.dkim_record
        details["public_key"] = data.public_key
        details["key_type"] = data.key_type
        details["key_size"] = data.key_size
        
        return round(score, 2), details

@register
class DKIMProbe(Probe):
    """Check DKIM signatures configuration."""
    
    id, weight = "dkim", 0.15
    ScoreCalculator = DKIMScoreCalculator
    
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
        
    @retry(max_retries=3, initial_delay=1.0)
    async def _get_txt_records(self, domain: str) -> List[str]:
        """Get TXT records.
        
        Args:
            domain: Domain to check
            
        Returns:
            List of TXT records
            
        Raises:
            DKIMProbeError: If TXT lookup fails
        """
        try:
            records = await self.dns_resolver.get_records(domain, 'TXT')
            return [record.text for record in records.txt_records]
        except Exception as e:
            raise DKIMProbeError(f"TXT lookup failed: {str(e)}")
        
    def _parse_dkim_record(self, record: str) -> tuple[Optional[str], Optional[str], Optional[int]]:
        """Parse DKIM record.
        
        Args:
            record: DKIM record
            
        Returns:
            Tuple of (public_key, key_type, key_size)
        """
        public_key = None
        key_type = None
        key_size = None
        
        # Split record into parts
        parts = record.split(';')
        
        for part in parts:
            part = part.strip()
            if part.startswith('p='):
                public_key = part[2:]
            elif part.startswith('k='):
                key_type = part[2:]
            elif part.startswith('s='):
                key_size = int(part[2:])
                
        return public_key, key_type, key_size
        
    async def collect_data(self, domain: str, selector: str = 'default') -> DKIMData:
        """Collect DKIM data.
        
        Args:
            domain: Domain to check
            selector: DKIM selector
            
        Returns:
            DKIM data
        """
        # Check cache first
        cache_key = f"{domain}:{selector}"
        cached_data = self._get_cached_data(cache_key)
        if cached_data:
            return cached_data
            
        try:
            # Get DNS records
            dkim_domain = f"{selector}._domainkey.{domain}"
            dns_records = await self.dns_resolver.get_records(dkim_domain)
            
            if dns_records.error:
                raise DKIMProbeError(dns_records.error)
                
            # Find DKIM record
            dkim_record = None
            for record in dns_records.txt_records:
                if record.startswith('v=DKIM1'):
                    dkim_record = record
                    break
                    
            if not dkim_record:
                return DKIMData(
                    domain=domain,
                    selector=selector,
                    dkim_record=None,
                    public_key=None,
                    key_type=None,
                    key_size=None,
                    has_valid_dkim=False
                )
                
            # Parse DKIM record
            public_key, key_type, key_size = self._parse_dkim_record(dkim_record)
            
            data = DKIMData(
                domain=domain,
                selector=selector,
                dkim_record=dkim_record,
                public_key=public_key,
                key_type=key_type,
                key_size=key_size,
                has_valid_dkim=True
            )
            
            # Cache result
            self._cache_data(cache_key, data)
            
            return data
            
        except Exception as e:
            return DKIMData(
                domain=domain,
                selector=selector,
                dkim_record=None,
                public_key=None,
                key_type=None,
                key_size=None,
                has_valid_dkim=False,
                error=str(e)
            )
            
    async def run(self, domain: str) -> ProbeResult:
        """Run probe.
        
        Args:
            domain: Domain to check
            
        Returns:
            Probe result
        """
        data = await self.collect_data(domain)
        score, details = DKIMScoreCalculator.calculate_score(data)
        
        return ProbeResult(
            probe_id=self.id,
            domain=domain,
            score=score,
            data=data,
            category=self.category,
            details=details
        ) 