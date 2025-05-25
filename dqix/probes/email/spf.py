from __future__ import annotations
from dataclasses import dataclass
from typing import Dict, List, Optional

from ..exceptions import SPFProbeError
from .base import EmailProbe, EmailProbeData

@dataclass
class SPFData(EmailProbeData):
    """SPF data."""
    spf_record: Optional[str]
    mechanisms: List[str]
    all_mechanism: Optional[str]
    has_valid_spf: bool
    has_multiple_mechanisms: bool = False

class SPFProbe(EmailProbe[SPFData]):
    """Probe for checking SPF records."""
    
    def _parse_spf_record(self, record: str) -> tuple[List[str], Optional[str]]:
        """Parse SPF record."""
        mechanisms = []
        all_mechanism = None
        
        # Split record into parts
        parts = record.split()
        
        for part in parts:
            if part.startswith('v=spf1'):
                continue
                
            if part.startswith('all'):
                all_mechanism = part
                mechanisms.append(part)
            else:
                mechanisms.append(part)
                
        return mechanisms, all_mechanism
        
    async def collect_data(self, domain: str) -> SPFData:
        """Collect SPF data."""
        # Check cache first
        cached_data = self._get_cached_data(domain)
        if cached_data:
            return cached_data
            
        try:
            # Get DNS records
            dns_records = await self._get_dns_records(domain)
            
            if dns_records.error:
                raise SPFProbeError(dns_records.error)
                
            # Find SPF record
            spf_record = self._find_record(dns_records.txt_records, 'v=spf1')
            
            if not spf_record:
                return SPFData(
                    domain=domain,
                    spf_record=None,
                    mechanisms=[],
                    all_mechanism=None,
                    has_valid_spf=False,
                    has_multiple_mechanisms=False
                )
                
            # Parse SPF record
            mechanisms, all_mechanism = self._parse_spf_record(spf_record)
            
            data = SPFData(
                domain=domain,
                spf_record=spf_record,
                mechanisms=mechanisms,
                all_mechanism=all_mechanism,
                has_valid_spf=True,
                has_multiple_mechanisms=len(mechanisms) > 2
            )
            
            # Cache result
            self._cache_data(domain, data)
            
            return data
            
        except Exception as e:
            return SPFData(
                domain=domain,
                spf_record=None,
                mechanisms=[],
                all_mechanism=None,
                has_valid_spf=False,
                has_multiple_mechanisms=False,
                error=str(e)
            )
            
    def calculate_score(self, data: SPFData) -> float:
        """Calculate score.
        
        Level 1: Has valid SPF record (0.4)
        Level 2: Has ALL mechanism (0.3)
        Level 3: Has multiple mechanisms (0.3) - Optional
        """
        if data.error:
            return 0.0
            
        score = 0.0
        
        # Level 1: Basic SPF check
        if data.has_valid_spf:
            score += 0.4
            
        # Level 2: ALL mechanism
        if data.all_mechanism and data.all_mechanism in ['-all', '~all']:
            score += 0.3
            
        # Level 3: Multiple mechanisms (Optional)
        if data.has_multiple_mechanisms:
            score += 0.3
            
        return score
        
    def _create_data_from_cache(self, cached_data: Dict) -> SPFData:
        """Create SPFData from cached data."""
        return SPFData(**cached_data) 