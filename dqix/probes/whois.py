from __future__ import annotations
from typing import Tuple, Dict, Any
import whois
from datetime import datetime

from .base import Probe
from . import register

@register
class WHOISProbe(Probe):
    """Check domain registration information and expiration.
    
    Scoring logic (0–1):
        • Registration info present (0.5)
        • Expiration date > 1 year (0.5)
    """
    
    id, weight = "whois", 0.10
    
    def run(self, dom: str) -> Tuple[float, Dict[str, Any]]:
        """Run WHOIS check against the domain.
        
        Args:
            dom: The domain to check
            
        Returns:
            Tuple of (score, details) where score is between 0 and 1
        """
        try:
            self._report_progress(f"WHOIS: Fetching data for {dom}...")
            w = whois.whois(dom)
            
            # Check if we got any data
            if not w.domain_name:
                self._report_progress(f"WHOIS: No data found for {dom}", end="\n")
                return 0.0, {
                    "whois_org": "No registration data",
                    "error": "No domain data found"
                }
                
            # Get organization name
            org = w.org or w.registrant_organization or "Unknown"
            
            # Check expiration
            exp_date = w.expiration_date
            if isinstance(exp_date, list):
                exp_date = exp_date[0]  # Take first date if multiple
                
            if not exp_date:
                self._report_progress(f"WHOIS: No expiration date for {dom}", end="\n")
                return 0.5, {
                    "whois_org": org,
                    "expiration": "Unknown",
                    "warning": "No expiration date found"
                }
                
            # Calculate days until expiration
            now = datetime.now()
            days_left = (exp_date - now).days
            
            # Score based on expiration
            if days_left > 365:
                score = 1.0
                exp_status = "> 1 year"
            elif days_left > 0:
                score = 0.5
                exp_status = f"{days_left} days"
            else:
                score = 0.0
                exp_status = "expired"
                
            self._report_progress(
                f"WHOIS: {dom} expires in {exp_status} ({org})", end="\n"
            )
            
            return score, {
                "whois_org": org,
                "expiration": exp_status,
                "expiration_date": exp_date.isoformat() if exp_date else None
            }
            
        except whois.parser.PywhoisError as e:
            self._report_progress(f"WHOIS: Error fetching data for {dom}", end="\n")
            return 0.0, {
                "whois_org": "Error fetching WHOIS",
                "error": str(e)
            }
        except Exception as e:
            self._report_progress(f"WHOIS: Unexpected error for {dom}", end="\n")
            return 0.0, {
                "whois_org": "Error processing WHOIS",
                "error": str(e)
            } 