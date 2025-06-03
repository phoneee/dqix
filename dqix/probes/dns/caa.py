from __future__ import annotations
from typing import Tuple, Dict, Any, List, Optional
from dataclasses import dataclass
from ..base import Probe, ProbeData, ScoreCalculator
from .. import register
from dqix.utils.dns import domain_variants, query_records, get_caa_records

@dataclass
class CAAData(ProbeData):
    """Data collected by CAAProbe."""
    domain: str
    records: List[str]
    error: Optional[str] = None

class CAAScoreCalculator(ScoreCalculator):
    """Calculate score for CAA probe.

    Scoring logic (0–1):
        • No CAA records                → 0.00
        • CAA present, but only "issue *" or empty → 0.50
        • At least one CA restricted (e.g. "issue letsencrypt.org") → 1.00
    """

    def calculate_score(self, data: CAAData) -> Tuple[float, Dict[str, Any]]:
        """Calculate score from CAA data."""
        if data.error:
            return 0.0, {"caa": f"error: {data.error}"}
            
        if not data.records:
            return 0.0, {
                "caa_found": False,
                "restricts": False,
                "records": data.records,
                "caa_raw": data.records
            }

        # Aggregate unique CA entries
        cas: List[str] = []
        for r in data.records:
            parts = r.split()
            if len(parts) >= 3:
                tag = parts[1].lower()
                value = parts[2].strip("\"")
                if tag == "issue":
                    cas.append(value.lower())
                    
        if not cas:
            return 0.5, {
                "caa_found": True,
                "restricts": False,
                "records": data.records,
                "caa_raw": data.records
            }
            
        if "*" in cas:
            # issue * permits any CA – weak policy
            return 0.5, {
                "caa_found": True,
                "restricts": False,
                "records": data.records,
                "caa_raw": data.records
            }
            
        # Otherwise at least one CA explicitly allowed
        return 1.0, {
            "caa_found": True,
            "restricts": True,
            "records": data.records,
            "caa_raw": data.records
        }

@register
class CAAProbe(Probe):
    """Check Certification Authority Authorization (CAA) DNS records.

    A CAA record restricts which Certificate Authorities (CAs) may issue
    certificates for a domain, reducing the risk of mis-issuance. This probe
    evaluates the presence and basic correctness of CAA records.
    """

    id, weight = "caa", 0.02
    ScoreCalculator = CAAScoreCalculator

    def collect_data(self, domain: str) -> CAAData:
        """Collect CAA records for the domain.
        
        Args:
            domain: The domain to check
            
        Returns:
            CAAData containing all collected CAA records
        """
        try:
            self._report_progress(f"CAA: Resolving CAA for {domain}…")
            records = get_caa_records(domain)
            return CAAData(
                domain=domain,
                records=records
            )
        except Exception as e:
            return CAAData(
                domain=domain,
                records=[],
                error=str(e)
            ) 