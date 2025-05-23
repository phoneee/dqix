from __future__ import annotations
from typing import Tuple, Dict, Any, List
import dns.resolver
import re

from .base import Probe
from . import register
from ..utils.dns import get_txt_records

@register
class ImpersonationProbe(Probe):
    """Check for domain spoofing protection mechanisms.
    
    Scoring logic (0–1):
        • SPF record (0.25)
        • DMARC record (0.25)
        • MTA-STS record (0.25)
        • BIMI record (0.25)
    """
    
    id, weight = "impersonation", 0.25
    
    def _check_spf(self, domain: str) -> Tuple[float, Dict[str, Any]]:
        """Check SPF record configuration.
        
        Args:
            domain: Domain to check
            
        Returns:
            Tuple of (score, details)
        """
        try:
            txt_records = get_txt_records(domain)
            spf_records = [r for r in txt_records if r.startswith("v=spf1")]
            
            if not spf_records:
                return 0.0, {"spf": "missing"}
                
            spf = spf_records[0]  # Use first SPF record
            
            # Check for common issues
            if "all" not in spf:
                return 0.5, {"spf": "present but no default mechanism"}
                
            # Check for strict policy
            if "-all" in spf:
                return 1.0, {"spf": "present with strict policy (-all)"}
            elif "~all" in spf:
                return 0.75, {"spf": "present with soft policy (~all)"}
            else:
                return 0.5, {"spf": "present with weak policy"}
                
        except Exception as e:
            return 0.0, {"spf": f"error: {str(e)}"}
            
    def _check_dmarc(self, domain: str) -> Tuple[float, Dict[str, Any]]:
        """Check DMARC record configuration.
        
        Args:
            domain: Domain to check
            
        Returns:
            Tuple of (score, details)
        """
        try:
            dmarc_domain = f"_dmarc.{domain}"
            txt_records = get_txt_records(dmarc_domain)
            dmarc_records = [r for r in txt_records if r.startswith("v=DMARC1")]
            
            if not dmarc_records:
                return 0.0, {"dmarc": "missing"}
                
            dmarc = dmarc_records[0]  # Use first DMARC record
            
            # Check for policy
            policy_match = re.search(r"p=([^;]+)", dmarc)
            if not policy_match:
                return 0.5, {"dmarc": "present but no policy"}
                
            policy = policy_match.group(1).lower()
            
            # Score based on policy
            if policy == "reject":
                return 1.0, {"dmarc": "present with reject policy"}
            elif policy == "quarantine":
                return 0.75, {"dmarc": "present with quarantine policy"}
            elif policy == "none":
                return 0.5, {"dmarc": "present with none policy"}
            else:
                return 0.5, {"dmarc": f"present with unknown policy: {policy}"}
                
        except Exception as e:
            return 0.0, {"dmarc": f"error: {str(e)}"}
            
    def _check_mta_sts(self, domain: str) -> Tuple[float, Dict[str, Any]]:
        """Check MTA-STS record configuration.
        
        Args:
            domain: Domain to check
            
        Returns:
            Tuple of (score, details)
        """
        try:
            mta_sts_domain = f"_mta-sts.{domain}"
            txt_records = get_txt_records(mta_sts_domain)
            sts_records = [r for r in txt_records if r.startswith("v=STSv1")]
            
            if not sts_records:
                return 0.0, {"mta_sts": "missing"}
                
            sts = sts_records[0]  # Use first MTA-STS record
            
            # Check for policy
            policy_match = re.search(r"id=([^;]+)", sts)
            if not policy_match:
                return 0.5, {"mta_sts": "present but no policy ID"}
                
            return 1.0, {"mta_sts": "present with policy"}
            
        except Exception as e:
            return 0.0, {"mta_sts": f"error: {str(e)}"}
            
    def _check_bimi(self, domain: str) -> Tuple[float, Dict[str, Any]]:
        """Check BIMI record configuration.
        
        Args:
            domain: Domain to check
            
        Returns:
            Tuple of (score, details)
        """
        try:
            bimi_domain = f"default._bimi.{domain}"
            txt_records = get_txt_records(bimi_domain)
            bimi_records = [r for r in txt_records if r.startswith("v=BIMI1")]
            
            if not bimi_records:
                return 0.0, {"bimi": "missing"}
                
            bimi = bimi_records[0]  # Use first BIMI record
            
            # Check for logo URL
            logo_match = re.search(r"l=([^;]+)", bimi)
            if not logo_match:
                return 0.5, {"bimi": "present but no logo URL"}
                
            return 1.0, {"bimi": "present with logo"}
            
        except Exception as e:
            return 0.0, {"bimi": f"error: {str(e)}"}
            
    def run(self, dom: str) -> Tuple[float, Dict[str, Any]]:
        """Run impersonation protection checks against the domain.
        
        Args:
            dom: The domain to check
            
        Returns:
            Tuple of (score, details) where score is between 0 and 1
        """
        self._report_progress(f"Impersonation: Checking protection mechanisms for {dom}...")
        
        # Run all checks
        spf_score, spf_details = self._check_spf(dom)
        dmarc_score, dmarc_details = self._check_dmarc(dom)
        mta_sts_score, mta_sts_details = self._check_mta_sts(dom)
        bimi_score, bimi_details = self._check_bimi(dom)
        
        # Calculate weighted score
        score = (
            spf_score * 0.25 +
            dmarc_score * 0.25 +
            mta_sts_score * 0.25 +
            bimi_score * 0.25
        )
        
        details = {
            **spf_details,
            **dmarc_details,
            **mta_sts_details,
            **bimi_details
        }
        
        self._report_progress(
            f"Impersonation: Score {score:.2f} for {dom}",
            end="\n"
        )
        
        return round(score, 2), details 