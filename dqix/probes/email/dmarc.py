from __future__ import annotations
from dataclasses import dataclass
from typing import Dict, List, Optional

from ..exceptions import DMARCProbeError
from .base import EmailProbe, EmailProbeData

@dataclass
class DMARCData(EmailProbeData):
    """DMARC data."""
    dmarc_record: Optional[str]
    policy: Optional[str]
    subdomain_policy: Optional[str]
    aspf: Optional[str]
    adkim: Optional[str]
    has_valid_dmarc: bool
    has_strict_alignment: bool = False

class DMARCProbe(EmailProbe[DMARCData]):
    """Probe for checking DMARC records."""
    
    def _parse_dmarc_record(self, record: str) -> tuple[Optional[str], Optional[str], Optional[str], Optional[str]]:
        """Parse DMARC record."""
        parsed = self._parse_record(record)
        return (
            parsed.get('p'),
            parsed.get('sp'),
            parsed.get('aspf'),
            parsed.get('adkim')
        )
        
    async def collect_data(self, domain: str) -> DMARCData:
        """Collect DMARC data."""
        # Check cache first
        cached_data = self._get_cached_data(domain)
        if cached_data:
            return cached_data
            
        try:
            # Get DNS records
            dmarc_domain = f"_dmarc.{domain}"
            dns_records = await self._get_dns_records(dmarc_domain)
            
            if dns_records.error:
                raise DMARCProbeError(dns_records.error)
                
            # Find DMARC record
            dmarc_record = self._find_record(dns_records.txt_records, 'v=DMARC1')
            
            if not dmarc_record:
                return DMARCData(
                    domain=domain,
                    dmarc_record=None,
                    policy=None,
                    subdomain_policy=None,
                    aspf=None,
                    adkim=None,
                    has_valid_dmarc=False,
                    has_strict_alignment=False
                )
                
            # Parse DMARC record
            policy, subdomain_policy, aspf, adkim = self._parse_dmarc_record(dmarc_record)
            
            # Check alignment settings (optional)
            has_strict_alignment = aspf == 's' or adkim == 's'
            
            data = DMARCData(
                domain=domain,
                dmarc_record=dmarc_record,
                policy=policy,
                subdomain_policy=subdomain_policy,
                aspf=aspf,
                adkim=adkim,
                has_valid_dmarc=True,
                has_strict_alignment=has_strict_alignment
            )
            
            # Cache result
            self._cache_data(domain, data)
            
            return data
            
        except Exception as e:
            return DMARCData(
                domain=domain,
                dmarc_record=None,
                policy=None,
                subdomain_policy=None,
                aspf=None,
                adkim=None,
                has_valid_dmarc=False,
                has_strict_alignment=False,
                error=str(e)
            )
            
    def calculate_score(self, data: DMARCData) -> float:
        """Calculate score.
        
        Level 1: Has valid DMARC record (0.4)
        Level 2: Has strict policy (0.3)
        Level 3: Has strict alignment (0.3) - Optional
        """
        if data.error:
            return 0.0
            
        score = 0.0
        
        # Level 1: Basic DMARC check
        if data.has_valid_dmarc:
            score += 0.4
            
        # Level 2: Policy
        if data.policy in ['reject', 'quarantine']:
            score += 0.3
            
        # Level 3: Alignment (Optional)
        if data.has_strict_alignment:
            score += 0.3
            
        return score
        
    def _create_data_from_cache(self, cached_data: Dict) -> DMARCData:
        """Create DMARCData from cached data."""
        return DMARCData(**cached_data) 