from __future__ import annotations
from typing import Tuple, Dict, Any, List, Optional
from dataclasses import dataclass

from ..base import Probe, ProbeData, ScoreCalculator
from .. import register
from dqix.utils.dns import domain_variants, query_records

@dataclass
class DNSBasicData(ProbeData):
    """Data collected by DNSBasicProbe."""
    a_records: List[Any]
    aaaa_records: List[Any]
    ns_records: List[Any]
    soa_records: List[Any]
    mx_records: List[Any]
    error: Optional[str] = None

class DNSBasicScoreCalculator(ScoreCalculator):
    """Calculate score for DNS basic probe."""
    
    def calculate_score(self, data: DNSBasicData) -> Tuple[float, Dict[str, Any]]:
        """Calculate score from DNS basic data.
        
        Scoring logic (0–1):
            • A/AAAA present (0.25)
            • ≥2 NS records (0.25)
            • SOA present (0.25)
            • MX present (0.25) – if none, partial credit 0.10 (domain may be web-only)
        """
        if data.error:
            return 0.0, {"error": data.error}
            
        a_ok = bool(data.a_records or data.aaaa_records)
        ns_ok = len(data.ns_records) >= 2
        soa_ok = bool(data.soa_records)
        mx_ok = bool(data.mx_records)

        score = 0.0
        score += 0.25 if a_ok else 0.0
        score += 0.25 if ns_ok else 0.0
        score += 0.25 if soa_ok else 0.0
        score += 0.25 if mx_ok else 0.10  # partial credit

        details = {
            "a_present": a_ok,
            "ns_count": len(data.ns_records),
            "soa_present": soa_ok,
            "mx_present": mx_ok,
        }

        return round(score, 2), details

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
    ScoreCalculator = DNSBasicScoreCalculator
            
    def collect_data(self, original_domain: str) -> DNSBasicData:
        """Collect DNS records for the domain.
        
        Args:
            original_domain: The domain to check
            
        Returns:
            DNSBasicData containing all collected records
        """
        variants = domain_variants(original_domain)
        last_err = None

        for dom in variants:
            try:
                self._report_progress(f"DNSBasic: querying records for {dom}…")

                return DNSBasicData(
                    a_records=query_records(dom, "A"),
                    aaaa_records=query_records(dom, "AAAA"),
                    ns_records=query_records(dom, "NS"),
                    soa_records=query_records(dom, "SOA"),
                    mx_records=query_records(dom, "MX")
                )
            except Exception as e:
                last_err = str(e)
                continue

        return DNSBasicData(
            a_records=[],
            aaaa_records=[],
            ns_records=[],
            soa_records=[],
            mx_records=[],
            error=last_err or "DNS query failed"
        ) 