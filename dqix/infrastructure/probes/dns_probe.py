"""DNS configuration probe."""

import dns.resolver
from typing import Dict, Any

from ...domain.entities import Domain, ProbeCategory, ProbeConfig, ProbeResult
from .base import BaseProbe


class DNSProbe(BaseProbe):
    """Checks DNS configuration."""
    
    def __init__(self):
        super().__init__("dns", ProbeCategory.SECURITY)
    
    async def check(self, domain: Domain, config: ProbeConfig) -> ProbeResult:
        """Check DNS configuration for domain."""
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = config.timeout
            
            details = {}
            score = 0.0
            
            # Check A record
            try:
                a_records = resolver.resolve(domain.name, "A")
                details["a_records"] = [str(r) for r in a_records]
                score += 0.2
            except:
                details["a_records"] = []
            
            # Check AAAA record (IPv6)
            try:
                aaaa_records = resolver.resolve(domain.name, "AAAA")
                details["aaaa_records"] = [str(r) for r in aaaa_records]
                score += 0.1  # Bonus for IPv6 support
            except:
                details["aaaa_records"] = []
            
            # Check MX record
            try:
                mx_records = resolver.resolve(domain.name, "MX")
                details["mx_records"] = [f"{r.preference} {r.exchange}" for r in mx_records]
                score += 0.2
            except:
                details["mx_records"] = []
            
            # Check SPF record
            try:
                txt_records = resolver.resolve(domain.name, "TXT")
                spf_records = [str(r) for r in txt_records if str(r).startswith('"v=spf1')]
                details["spf_records"] = spf_records
                if spf_records:
                    score += 0.2
            except:
                details["spf_records"] = []
            
            # Check DMARC record
            try:
                dmarc_records = resolver.resolve(f"_dmarc.{domain.name}", "TXT")
                details["dmarc_records"] = [str(r) for r in dmarc_records]
                if dmarc_records:
                    score += 0.3
            except:
                details["dmarc_records"] = []
            
            return self._create_result(domain, score, details)
            
        except Exception as e:
            return self._create_result(
                domain, 
                0.0, 
                {"error": str(e)}, 
                error=str(e)
            ) 