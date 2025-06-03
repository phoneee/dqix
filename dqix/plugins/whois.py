"""WHOIS plugin for DQIX.

This plugin provides a probe to check WHOIS information for domains.
"""

from __future__ import annotations
from typing import Dict, Any, Tuple, Optional, List, Type
from datetime import datetime, timedelta
import whois

from .base import ProbePlugin, register_plugin
from ..core.probes import Probe

class WHOISProbe(Probe):
    """Check WHOIS information."""
    
    id = "whois"
    weight = 0.1
    
    def _get_whois_data(self, domain: str) -> Optional[Dict[str, Any]]:
        """Get WHOIS data for domain.
        
        Args:
            domain: Domain to check
            
        Returns:
            WHOIS data or None if error
        """
        try:
            w = whois.whois(domain)
            return {
                "registrar": w.registrar,
                "creation_date": w.creation_date,
                "expiration_date": w.expiration_date,
                "updated_date": w.updated_date,
                "name_servers": w.name_servers,
                "status": w.status,
                "dnssec": w.dnssec if hasattr(w, "dnssec") else None,
                "registrant": w.registrant if hasattr(w, "registrant") else None,
                "admin": w.admin if hasattr(w, "admin") else None,
                "tech": w.tech if hasattr(w, "tech") else None
            }
        except Exception as e:
            return None
            
    def _check_expiration(self, expiration_date: datetime) -> Tuple[float, str]:
        """Check domain expiration status.
        
        Args:
            expiration_date: Domain expiration date
            
        Returns:
            Tuple of (score, status)
        """
        now = datetime.now()
        days_left = (expiration_date - now).days
        
        if days_left < 0:
            return 0.0, "expired"
        elif days_left < 30:
            return 0.3, "expiring_soon"
        elif days_left < 90:
            return 0.6, "expiring"
        else:
            return 1.0, "valid"
            
    def _check_age(self, creation_date: datetime) -> Tuple[float, str]:
        """Check domain age.
        
        Args:
            creation_date: Domain creation date
            
        Returns:
            Tuple of (score, status)
        """
        now = datetime.now()
        age_days = (now - creation_date).days
        
        if age_days < 30:
            return 0.3, "new"
        elif age_days < 365:
            return 0.6, "young"
        else:
            return 1.0, "established"
            
    def run(self, domain: str) -> Tuple[float, dict]:
        """Run WHOIS check on domain.
        
        Args:
            domain: Domain to check
            
        Returns:
            Tuple of (score, details) where:
            - score is a float between 0 and 1
            - details is a dict with WHOIS information
        """
        data = self._get_whois_data(domain)
        
        if not data:
            return 0.0, {"error": "Failed to get WHOIS data"}
            
        # Calculate score based on data completeness
        score = 0.0
        details = {}
        
        # Check registrar
        if data.get("registrar"):
            score += 0.15
            details["registrar"] = data["registrar"]
            
        # Check dates
        if data.get("creation_date"):
            score += 0.1
            details["creation_date"] = str(data["creation_date"])
            age_score, age_status = self._check_age(data["creation_date"])
            score += age_score * 0.1
            details["age_status"] = age_status
            
        if data.get("expiration_date"):
            score += 0.1
            details["expiration_date"] = str(data["expiration_date"])
            exp_score, exp_status = self._check_expiration(data["expiration_date"])
            score += exp_score * 0.15
            details["expiration_status"] = exp_status
            
        if data.get("updated_date"):
            score += 0.1
            details["updated_date"] = str(data["updated_date"])
            
        # Check name servers
        if data.get("name_servers"):
            score += 0.1
            details["name_servers"] = data["name_servers"]
            
        # Check status
        if data.get("status"):
            score += 0.1
            details["status"] = data["status"]
            
        # Check DNSSEC
        if data.get("dnssec"):
            score += 0.1
            details["dnssec"] = data["dnssec"]
            
        # Check contact info
        if data.get("registrant"):
            score += 0.05
            details["registrant"] = data["registrant"]
            
        if data.get("admin"):
            score += 0.05
            details["admin"] = data["admin"]
            
        if data.get("tech"):
            score += 0.05
            details["tech"] = data["tech"]
            
        return round(score, 2), details

@register_plugin
class WHOISPlugin(ProbePlugin):
    """Plugin that provides WHOIS probe."""
    
    name = "whois"
    version = "1.0.0"
    description = "WHOIS probe for DQIX"
    
    def initialize(self) -> None:
        """Initialize plugin."""
        pass
        
    def cleanup(self) -> None:
        """Clean up plugin resources."""
        pass
        
    def get_probes(self) -> List[Type[Probe]]:
        """Get the probes provided by this plugin.
        
        Returns:
            List containing WHOISProbe
        """
        return [WHOISProbe] 