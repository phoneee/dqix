"""Refactored SPF probe demonstrating improved architecture."""

from __future__ import annotations
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from dqix.core.probes import Probe, register
from dqix.core.mixins import CacheMixin, DNSRecordMixin, ErrorHandlingMixin
from ..exceptions import SPFProbeError


@dataclass
class SPFData:
    """SPF probe data."""
    domain: str
    spf_record: Optional[str] = None
    mechanisms: List[str] = None
    all_mechanism: Optional[str] = None
    has_valid_spf: bool = False
    has_multiple_mechanisms: bool = False
    error: Optional[str] = None
    
    def __post_init__(self):
        """Initialize default values."""
        if self.mechanisms is None:
            self.mechanisms = []


class SPFScoreCalculator:
    """Calculate SPF score based on data."""
    
    @staticmethod
    def calculate_score(data: SPFData) -> float:
        """Calculate SPF score.
        
        Scoring breakdown:
        - Has valid SPF record: 0.4 points
        - Has proper ALL mechanism: 0.3 points  
        - Has multiple mechanisms: 0.3 points (optional)
        
        Args:
            data: SPF data to score
            
        Returns:
            Score between 0.0 and 1.0
        """
        if data.error:
            return 0.0
            
        score = 0.0
        
        # Level 1: Basic SPF presence
        if data.has_valid_spf:
            score += 0.4
            
        # Level 2: Proper ALL mechanism
        if data.all_mechanism and data.all_mechanism in ['-all', '~all']:
            score += 0.3
            
        # Level 3: Multiple mechanisms (shows comprehensive setup)
        if data.has_multiple_mechanisms:
            score += 0.3
            
        return min(score, 1.0)  # Cap at 1.0


@register
class SPFProbe(Probe, CacheMixin, DNSRecordMixin, ErrorHandlingMixin):
    """Probe for checking SPF (Sender Policy Framework) records."""
    
    id = "spf"
    weight = 0.1
    category = "email"
    
    def __init__(self, cache=None, dns_resolver=None):
        """Initialize SPF probe.
        
        Args:
            cache: Optional cache instance
            dns_resolver: Optional DNS resolver
        """
        super().__init__(cache=cache)
        self.dns_resolver = dns_resolver
    
    def run(self, domain: str) -> Tuple[float, Dict[str, any]]:
        """Run SPF probe against domain.
        
        Args:
            domain: Domain to check
            
        Returns:
            Tuple of (score, details)
        """
        try:
            self._report_progress(f"SPF: Checking {domain}...")
            
            # Check cache first
            cached_data = self._get_cached_data(domain)
            if cached_data:
                data = SPFData(**cached_data)
            else:
                data = self._collect_spf_data(domain)
                self._cache_data(domain, data)
            
            score = SPFScoreCalculator.calculate_score(data)
            details = self._build_details(data)
            
            return score, details
            
        except Exception as e:
            self.logger.error(f"SPF probe error for {domain}: {str(e)}")
            return 0.0, {"error": str(e), "spf_record": None}
    
    def _collect_spf_data(self, domain: str) -> SPFData:
        """Collect SPF data for domain.
        
        Args:
            domain: Domain to check
            
        Returns:
            SPF data
        """
        try:
            # Get TXT records (SPF is stored in TXT records)
            txt_records = self._get_txt_records(domain)
            
            # Find SPF record
            spf_record = self._find_record(txt_records, 'v=spf1')
            
            if not spf_record:
                return SPFData(
                    domain=domain,
                    has_valid_spf=False
                )
            
            # Parse SPF record
            mechanisms, all_mechanism = self._parse_spf_record(spf_record)
            
            return SPFData(
                domain=domain,
                spf_record=spf_record,
                mechanisms=mechanisms,
                all_mechanism=all_mechanism,
                has_valid_spf=True,
                has_multiple_mechanisms=len(mechanisms) > 2
            )
            
        except Exception as e:
            return self._handle_probe_error(
                domain, 
                e, 
                SPFData(domain=domain, has_valid_spf=False)
            )
    
    def _get_txt_records(self, domain: str) -> List[str]:
        """Get TXT records for domain.
        
        Args:
            domain: Domain to query
            
        Returns:
            List of TXT records
        """
        # This would integrate with your DNS resolver
        # For now, return empty list as placeholder
        if self.dns_resolver:
            return self.dns_resolver.get_txt_records(domain)
        return []
    
    def _parse_spf_record(self, record: str) -> Tuple[List[str], Optional[str]]:
        """Parse SPF record into mechanisms.
        
        Args:
            record: SPF record string
            
        Returns:
            Tuple of (mechanisms list, all_mechanism)
        """
        mechanisms = []
        all_mechanism = None
        
        # Split record into parts and process each
        parts = record.split()
        
        for part in parts:
            if part.startswith('v=spf1'):
                continue  # Skip version declaration
                
            if part.endswith('all'):
                all_mechanism = part
                
            mechanisms.append(part)
                
        return mechanisms, all_mechanism
    
    def _build_details(self, data: SPFData) -> Dict[str, any]:
        """Build details dictionary from SPF data.
        
        Args:
            data: SPF data
            
        Returns:
            Details dictionary
        """
        details = {
            "spf_record": data.spf_record,
            "has_valid_spf": data.has_valid_spf,
            "mechanisms_count": len(data.mechanisms),
            "all_mechanism": data.all_mechanism,
        }
        
        if data.error:
            details["error"] = data.error
            
        return details 