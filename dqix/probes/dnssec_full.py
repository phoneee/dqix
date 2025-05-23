from __future__ import annotations
from typing import Tuple, Dict, Any
import requests

from .base import Probe
from . import register

# Google's DNS-over-HTTPS endpoint
GOOGLE_DOH = "https://dns.google/resolve"

@register
class DNSSECProbe(Probe):
    """Check DNSSEC validation status using Google's DNS-over-HTTPS."""
    
    id, weight = "dnssec", 0.20
    
    def run(self, dom: str) -> Tuple[float, Dict[str, Any]]:
        """Run DNSSEC validation check against the domain.
        
        Args:
            dom: The domain to check
            
        Returns:
            Tuple of (score, details) where score is between 0 and 1
        """
        try:
            self._report_progress(f"DNSSEC: Checking validation status for {dom}...")
            # Use Google DoH for validation
            j = requests.get(
                GOOGLE_DOH, 
                params={"name": dom, "type": "A", "do": "1"}, 
                timeout=8
            ).json()
            
            # Status 0 means no error, AD flag means DNSSEC validated
            score = 1.0 if j.get("Status") == 0 and j.get("AD", False) else 0.0
            
            self._report_progress(
                f"DNSSEC: {'Validated' if score == 1.0 else 'Not validated'} for {dom}",
                end="\n",
            )
            
            return score, {
                "dnssec_status": j.get("Status"),
                "ad_flag": j.get("AD", False),
            }
            
        except (requests.RequestException, ValueError):
            self._report_progress(f"DNSSEC: Check failed for {dom}", end="\n")
            return 0.0, {
                "dnssec_status": -1,
                "ad_flag": False,
                "error": "Request or JSON parse failed",
            } 