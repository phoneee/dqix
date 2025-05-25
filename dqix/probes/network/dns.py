from __future__ import annotations
from typing import Dict, Any, Optional, List
from dataclasses import dataclass
import dns.resolver
import dns.dnssec
import dns.rdatatype

from ..base import Probe, ProbeData, ScoreCalculator, ProbeResult, ProbeCategory
from . import register

@dataclass
class DNSData(ProbeData):
    """Data collected by DNSProbe."""
    domain: str
    has_a_record: bool
    has_aaaa_record: bool
    has_mx_record: bool
    has_txt_record: bool
    has_dnssec: bool
    nameservers: List[str]
    error: Optional[str] = None

class DNSScoreCalculator(ScoreCalculator):
    """Calculate score for DNS probe."""
    
    def calculate_score(self, data: DNSData) -> ProbeResult:
        """Calculate score from DNS data.
        
        Scoring logic (0–1):
            • A Record (0.2)
            • AAAA Record (0.2)
            • MX Record (0.2)
            • TXT Record (0.2)
            • DNSSEC (0.2)
        """
        if data.error:
            return ProbeResult(
                score=0.0,
                details={"error": data.error},
                error=data.error,
                category=ProbeCategory.TRUSTWORTHINESS
            )
            
        score = 0.0
        details = {}
        
        # Check A Record
        if data.has_a_record:
            score += 0.2
            details["a_record"] = "present"
        else:
            details["a_record"] = "missing"
            
        # Check AAAA Record
        if data.has_aaaa_record:
            score += 0.2
            details["aaaa_record"] = "present"
        else:
            details["aaaa_record"] = "missing"
            
        # Check MX Record
        if data.has_mx_record:
            score += 0.2
            details["mx_record"] = "present"
        else:
            details["mx_record"] = "missing"
            
        # Check TXT Record
        if data.has_txt_record:
            score += 0.2
            details["txt_record"] = "present"
        else:
            details["txt_record"] = "missing"
            
        # Check DNSSEC
        if data.has_dnssec:
            score += 0.2
            details["dnssec"] = "enabled"
        else:
            details["dnssec"] = "disabled"
            
        return ProbeResult(
            score=round(score, 2),
            details=details,
            data=data,
            category=ProbeCategory.TRUSTWORTHINESS
        )

@register
class DNSProbe(Probe):
    """Check DNS configuration and security."""
    
    id, weight = "dns", 0.15
    category = ProbeCategory.TRUSTWORTHINESS
    ScoreCalculator = DNSScoreCalculator
    
    def _check_dnssec(self, domain: str) -> bool:
        """Check if domain has DNSSEC enabled."""
        try:
            # Check for DNSKEY record
            dns.resolver.resolve(domain, 'DNSKEY')
            return True
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            return False
            
    def collect_data(self, domain: str) -> DNSData:
        """Collect DNS data for the domain.
        
        Args:
            domain: The domain to check
            
        Returns:
            DNSData containing DNS information
        """
        try:
            # Check A Record
            try:
                dns.resolver.resolve(domain, 'A')
                has_a_record = True
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                has_a_record = False
                
            # Check AAAA Record
            try:
                dns.resolver.resolve(domain, 'AAAA')
                has_aaaa_record = True
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                has_aaaa_record = False
                
            # Check MX Record
            try:
                dns.resolver.resolve(domain, 'MX')
                has_mx_record = True
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                has_mx_record = False
                
            # Check TXT Record
            try:
                dns.resolver.resolve(domain, 'TXT')
                has_txt_record = True
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                has_txt_record = False
                
            # Get Nameservers
            try:
                ns_records = dns.resolver.resolve(domain, 'NS')
                nameservers = [str(ns) for ns in ns_records]
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                nameservers = []
                
            # Check DNSSEC
            has_dnssec = self._check_dnssec(domain)
            
            return DNSData(
                domain=domain,
                has_a_record=has_a_record,
                has_aaaa_record=has_aaaa_record,
                has_mx_record=has_mx_record,
                has_txt_record=has_txt_record,
                has_dnssec=has_dnssec,
                nameservers=nameservers
            )
            
        except Exception as e:
            self.logger.error(f"Error collecting DNS data: {str(e)}", exc_info=True)
            return DNSData(
                domain=domain,
                has_a_record=False,
                has_aaaa_record=False,
                has_mx_record=False,
                has_txt_record=False,
                has_dnssec=False,
                nameservers=[],
                error=str(e)
            ) 