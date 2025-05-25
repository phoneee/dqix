from __future__ import annotations
from typing import Tuple, Dict, Any, List, Optional
from dataclasses import dataclass
import re

import requests

from .base import Probe, ProbeData, ScoreCalculator
from . import register
from ..utils.dns import get_txt_records

@dataclass
class BIMIData(ProbeData):
    """Data collected by BIMIProbe."""
    domain: str
    bimi_record: Optional[str]
    logo_url: Optional[str]
    logo_type: Optional[str]
    logo_size: Optional[int]
    vmc_url: Optional[str]
    error: Optional[str] = None

class BIMIScoreCalculator(ScoreCalculator):
    """Calculate score for BIMI probe."""
    
    def calculate_score(self, data: BIMIData) -> Tuple[float, Dict[str, Any]]:
        """Calculate score from BIMI data.
        
        Scoring logic (0–1):
            • BIMI record present (0.3)
            • Valid logo URL (0.3)
            • SVG logo type (0.2)
            • VMC URL present (0.2)
        """
        if data.error:
            return 0.0, {"error": data.error}
            
        if not data.bimi_record:
            return 0.0, {"bimi": "missing"}
            
        score = 0.0
        details = {}
        
        # Check presence
        score += 0.3
        details["bimi"] = "present"
        
        # Check logo URL
        if data.logo_url:
            try:
                resp = requests.head(data.logo_url, timeout=5)
                if resp.status_code == 200:
                    score += 0.3
                    details["logo_url"] = "valid"
                else:
                    details["logo_url"] = "invalid"
            except:
                details["logo_url"] = "error"
        else:
            details["logo_url"] = "missing"
            
        # Check logo type
        if data.logo_type == "image/svg+xml":
            score += 0.2
            details["logo_type"] = "svg"
        else:
            details["logo_type"] = "other"
            
        # Check VMC URL
        if data.vmc_url:
            score += 0.2
            details["vmc"] = "present"
        else:
            details["vmc"] = "missing"
            
        details["logo_size"] = data.logo_size
        details["vmc_url"] = data.vmc_url
        
        return round(score, 2), details

@register
class BIMIProbe(Probe):
    """Check BIMI records."""
    
    id, weight = "bimi", 0.15
    ScoreCalculator = BIMIScoreCalculator
    
    def _parse_bimi_record(self, record: str) -> Tuple[Optional[str], Optional[str], Optional[int], Optional[str]]:
        """Parse BIMI record to extract logo and VMC info."""
        logo_url = None
        logo_type = None
        logo_size = None
        vmc_url = None
        
        # Extract logo URL
        logo_match = re.search(r"l=([^;]+)", record)
        if logo_match:
            logo_url = logo_match.group(1)
            
            # Check logo type and size
            try:
                resp = requests.head(logo_url, timeout=5)
                if resp.status_code == 200:
                    logo_type = resp.headers.get("content-type")
                    logo_size = int(resp.headers.get("content-length", 0))
            except:
                pass
                
        # Extract VMC URL
        vmc_match = re.search(r"a=([^;]+)", record)
        if vmc_match:
            vmc_url = vmc_match.group(1)
            
        return logo_url, logo_type, logo_size, vmc_url
        
    def collect_data(self, domain: str) -> BIMIData:
        """Collect BIMI data for the domain.
        
        Args:
            domain: The domain to check
            
        Returns:
            BIMIData containing BIMI information
        """
        try:
            self._report_progress(f"BIMI: Checking records for {domain}...")
            
            # Get BIMI record
            bimi_domain = f"default._bimi.{domain}"
            txt_records = get_txt_records(bimi_domain)
            
            bimi_record = None
            for record in txt_records:
                if record.startswith("v=BIMI1"):
                    bimi_record = record
                    break
                    
            if not bimi_record:
                return BIMIData(
                    domain=domain,
                    bimi_record=None,
                    logo_url=None,
                    logo_type=None,
                    logo_size=None,
                    vmc_url=None
                )
                
            # Parse record
            logo_url, logo_type, logo_size, vmc_url = self._parse_bimi_record(bimi_record)
            
            return BIMIData(
                domain=domain,
                bimi_record=bimi_record,
                logo_url=logo_url,
                logo_type=logo_type,
                logo_size=logo_size,
                vmc_url=vmc_url
            )
            
        except Exception as e:
            return BIMIData(
                domain=domain,
                bimi_record=None,
                logo_url=None,
                logo_type=None,
                logo_size=None,
                vmc_url=None,
                error=str(e)
            ) 