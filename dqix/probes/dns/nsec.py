from __future__ import annotations
from typing import Tuple, Dict, Any, List, Optional
from dataclasses import dataclass

import dns.resolver

from .base import Probe, ProbeData, ScoreCalculator
from . import register
from ..utils.dns import query_records

@dataclass
class NSECData(ProbeData):
    """Data collected by NSECProbe."""
    domain: str
    nsec_records: List[str]
    nsec3_records: List[str]
    nsec3_params: Optional[Dict[str, Any]]
    error: Optional[str] = None

class NSECScoreCalculator(ScoreCalculator):
    """Calculate score for NSEC probe."""
    
    def calculate_score(self, data: NSECData) -> Tuple[float, Dict[str, Any]]:
        """Calculate score from NSEC data.
        
        Scoring logic (0–1):
            • NSEC/NSEC3 present (0.4)
            • NSEC3 with opt-out disabled (0.3)
            • NSEC3 with modern algorithm (0.3)
        """
        if data.error:
            return 0.0, {"error": data.error}
            
        if not data.nsec_records and not data.nsec3_records:
            return 0.0, {"nsec": "missing"}
            
        score = 0.0
        details = {}
        
        # Check presence
        if data.nsec_records or data.nsec3_records:
            score += 0.4
            details["nsec"] = "present"
        else:
            details["nsec"] = "missing"
            
        # Check NSEC3 opt-out
        if data.nsec3_params:
            if not data.nsec3_params.get("opt_out", False):
                score += 0.3
                details["opt_out"] = "disabled"
            else:
                details["opt_out"] = "enabled"
                
        # Check NSEC3 algorithm
        if data.nsec3_params:
            algo = data.nsec3_params.get("algorithm", 0)
            if algo in [1, 2]:  # SHA-1 or SHA-256
                score += 0.3
                details["algorithm"] = "modern"
            else:
                details["algorithm"] = "legacy"
                
        details["nsec_records"] = data.nsec_records
        details["nsec3_records"] = data.nsec3_records
        details["nsec3_params"] = data.nsec3_params
        
        return round(score, 2), details

@register
class NSECProbe(Probe):
    """Check NSEC/NSEC3 records."""
    
    id, weight = "nsec", 0.15
    ScoreCalculator = NSECScoreCalculator
    
    def _parse_nsec3_params(self, record: str) -> Dict[str, Any]:
        """Parse NSEC3 parameters from record."""
        params = {}
        
        # Extract algorithm
        algo_match = re.search(r"(\d+)\s+(\d+)\s+(\d+)\s+([A-Z0-9]+)", record)
        if algo_match:
            params["algorithm"] = int(algo_match.group(1))
            params["flags"] = int(algo_match.group(2))
            params["iterations"] = int(algo_match.group(3))
            params["salt"] = algo_match.group(4)
            
            # Check opt-out flag
            params["opt_out"] = bool(params["flags"] & 0x01)
            
        return params
        
    def collect_data(self, domain: str) -> NSECData:
        """Collect NSEC data for the domain.
        
        Args:
            domain: The domain to check
            
        Returns:
            NSECData containing NSEC information
        """
        try:
            self._report_progress(f"NSEC: Checking records for {domain}...")
            
            # Query NSEC records
            nsec_records = query_records(domain, "NSEC")
            
            # Query NSEC3 records
            nsec3_records = query_records(domain, "NSEC3")
            
            # Parse NSEC3 parameters
            nsec3_params = None
            if nsec3_records:
                nsec3_params = self._parse_nsec3_params(nsec3_records[0])
                
            return NSECData(
                domain=domain,
                nsec_records=nsec_records,
                nsec3_records=nsec3_records,
                nsec3_params=nsec3_params
            )
            
        except Exception as e:
            return NSECData(
                domain=domain,
                nsec_records=[],
                nsec3_records=[],
                nsec3_params=None,
                error=str(e)
            ) 