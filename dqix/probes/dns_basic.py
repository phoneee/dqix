from __future__ import annotations
from typing import Tuple, Dict, Any, List
import dns.resolver

from .base import Probe
from . import register
from ..utils.dns import domain_variants

@register
class DNSBasicProbe(Probe):
    """Validate presence of essential DNS records.
    
    Scoring logic (0–1):
        • A/AAAA present (0.25)
        • ≥2 NS records (0.25)
        • SOA present (0.25)
        • MX present (0.25) – if none, partial credit 0.10 (domain may be web-only)
    """
    
    id, weight = "dns_basic", 0.05
    
    def _query_any(self, domain: str, rdtype: str) -> List[Any]:
        """Query DNS records of specified type.
        
        Args:
            domain: Domain to query
            rdtype: Record type (A, AAAA, NS, SOA, MX)
            
        Returns:
            List of DNS records, empty list on error
        """
        try:
            answers = dns.resolver.resolve(domain, rdtype, raise_on_no_answer=False)
            return list(answers) if answers else []
        except dns.resolver.NoAnswer:
            return []
        except Exception:
            return []
            
    def run(self, original_domain: str) -> Tuple[float, Dict[str, Any]]:
        """Run basic DNS checks against the domain.
        
        Args:
            original_domain: The domain to check
            
        Returns:
            Tuple of (score, details) where score is between 0 and 1
        """
        variants = domain_variants(original_domain)
        last_err = None

        for dom in variants:
            try:
                self._report_progress(f"DNSBasic: querying records for {dom}…")

                a_ok = bool(self._query_any(dom, "A") or self._query_any(dom, "AAAA"))
                ns_records = self._query_any(dom, "NS")
                ns_ok = len(ns_records) >= 2
                soa_ok = bool(self._query_any(dom, "SOA"))
                mx_records = self._query_any(dom, "MX")
                mx_ok = bool(mx_records)

                score = 0.0
                score += 0.25 if a_ok else 0.0
                score += 0.25 if ns_ok else 0.0
                score += 0.25 if soa_ok else 0.0
                score += 0.25 if mx_ok else 0.10  # partial credit

                details = {
                    "a_present": a_ok,
                    "ns_count": len(ns_records),
                    "soa_present": soa_ok,
                    "mx_present": mx_ok,
                }

                return round(score, 2), details
            except Exception as e:
                last_err = str(e)
                continue

        return 0.0, {"error": last_err or "DNS query failed"} 