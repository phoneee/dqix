from __future__ import annotations
from typing import Tuple, Dict, Any, Optional
from dataclasses import dataclass
from datetime import datetime

import whois
from whois.parser import PywhoisError

from ..base import Probe, ProbeData, ScoreCalculator
from .. import register
from ...core.probes import ProbeResult, ProbeCategory
from ...core.cache import ProbeCache
from ...core.exceptions import WHOISProbeError
from ...core.utils import retry

@dataclass
class WHOISData:
    """WHOIS data."""
    domain: str
    registrar: Optional[str]
    creation_date: Optional[datetime]
    expiration_date: Optional[datetime]
    updated_date: Optional[datetime]
    name_servers: list[str]
    status: list[str]
    dnssec: bool
    error: Optional[str] = None

class WHOISScoreCalculator:
    """Calculate score based on WHOIS data."""
    
    @staticmethod
    def calculate_score(data: WHOISData) -> float:
        """Calculate score.
        
        Scoring logic (0–1):
            • Valid registrar (0.2)
            • Valid dates (0.2)
            • Valid name servers (0.2)
            • Valid status (0.2)
            • DNSSEC enabled (0.2)
        """
        if data.error:
            return 0.0
            
        score = 0.0
        total = 5  # Total number of factors
        
        # Check registrar
        if data.registrar:
            score += 0.2
            
        # Check dates
        if all(date is not None for date in [
            data.creation_date,
            data.expiration_date,
            data.updated_date
        ]):
            score += 0.2
            
        # Check name servers
        if len(data.name_servers) >= 2:
            score += 0.2
            
        # Check status
        if data.status and "ok" in [s.lower() for s in data.status]:
            score += 0.2
            
        # Check DNSSEC
        if data.dnssec:
            score += 0.2
            
        return score

@register
class WHOISProbe(Probe):
    """Probe for WHOIS information."""
    
    id = "whois"
    weight = 0.05
    
    def run(self, domain: str) -> Tuple[float, dict]:
        """Run WHOIS check on domain.
        
        Args:
            domain: Domain to check
            
        Returns:
            Tuple of (score, details) where:
            - score is a float between 0 and 1
            - details is a dict with WHOIS information
        """
        try:
            # Get WHOIS data
            w = whois.whois(domain)
            
            # Calculate score based on available information
            score = 0.0
            details = {
                "registrar": w.registrar,
                "creation_date": w.creation_date,
                "expiration_date": w.expiration_date,
                "updated_date": w.updated_date,
                "name_servers": w.name_servers,
                "status": w.status,
                "dnssec": w.dnssec if hasattr(w, 'dnssec') else None,
                "emails": w.emails if hasattr(w, 'emails') else None,
                "org": w.org if hasattr(w, 'org') else None,
                "address": w.address if hasattr(w, 'address') else None,
                "city": w.city if hasattr(w, 'city') else None,
                "state": w.state if hasattr(w, 'state') else None,
                "zipcode": w.zipcode if hasattr(w, 'zipcode') else None,
                "country": w.country if hasattr(w, 'country') else None,
                "name": w.name if hasattr(w, 'name') else None,
                "phone": w.phone if hasattr(w, 'phone') else None,
                "fax": w.fax if hasattr(w, 'fax') else None,
                "registrant": w.registrant if hasattr(w, 'registrant') else None,
                "admin": w.admin if hasattr(w, 'admin') else None,
                "tech": w.tech if hasattr(w, 'tech') else None,
                "abuse": w.abuse if hasattr(w, 'abuse') else None,
                "error": None
            }
            
            # Score based on available information
            if w.registrar:
                score += 0.2
            if w.creation_date:
                score += 0.2
            if w.expiration_date:
                score += 0.2
            if w.name_servers:
                score += 0.2
            if w.status:
                score += 0.2
                
            return score, details
            
        except Exception as e:
            return 0.0, {
                "error": str(e),
                "registrar": None,
                "creation_date": None,
                "expiration_date": None,
                "updated_date": None,
                "name_servers": None,
                "status": None,
                "dnssec": None,
                "emails": None,
                "org": None,
                "address": None,
                "city": None,
                "state": None,
                "zipcode": None,
                "country": None,
                "name": None,
                "phone": None,
                "fax": None,
                "registrant": None,
                "admin": None,
                "tech": None,
                "abuse": None
            } 