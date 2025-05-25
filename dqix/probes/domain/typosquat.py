from __future__ import annotations
from dataclasses import dataclass
from typing import Dict, List, Optional
import difflib
import itertools
import string
import aiohttp
import whois

from ..base import Probe, ProbeResult, ProbeCategory
from ..cache import ProbeCache
from ..exceptions import TyposquatProbeError
from ..utils import retry

@dataclass
class TyposquatData:
    """Typosquat data."""
    domain: str
    similar_domains: List[str]
    registered_similar: List[str]
    levenshtein_scores: Dict[str, float]
    is_typosquat: bool
    risk_level: float
    error: Optional[str] = None

class TyposquatScoreCalculator:
    """Calculate score based on typosquat data."""
    
    @staticmethod
    def calculate_score(data: TyposquatData) -> float:
        """Calculate score.
        
        Scoring logic (0–1):
            • No similar domains (1.0)
            • No registered similar domains (0.8)
            • Low risk level (0.6)
            • Medium risk level (0.4)
            • High risk level (0.2)
        """
        if data.error:
            return 0.0
            
        if not data.similar_domains:
            return 1.0
            
        if not data.registered_similar:
            return 0.8
            
        if data.risk_level < 0.3:
            return 0.6
        elif data.risk_level < 0.7:
            return 0.4
        else:
            return 0.2

class TyposquatProbe(Probe):
    """Probe for checking typosquatting."""
    
    def __init__(self, cache: Optional[ProbeCache] = None):
        """Initialize probe.
        
        Args:
            cache: Optional cache instance
        """
        super().__init__()
        self.category = ProbeCategory.TRUSTWORTHINESS
        self.cache = cache
        
    def _generate_similar_domains(self, domain: str) -> List[str]:
        """Generate similar domains.
        
        Args:
            domain: Domain to check
            
        Returns:
            List of similar domains
        """
        similar = []
        
        # Split domain into parts
        parts = domain.split(".")
        if len(parts) != 2:
            return similar
            
        name, tld = parts
        
        # Generate typos
        for i in range(len(name)):
            # Character substitution
            for c in string.ascii_lowercase:
                if c != name[i]:
                    similar.append(f"{name[:i]}{c}{name[i+1:]}.{tld}")
                    
            # Character deletion
            if i > 0:
                similar.append(f"{name[:i]}{name[i+1:]}.{tld}")
                
            # Character insertion
            for c in string.ascii_lowercase:
                similar.append(f"{name[:i]}{c}{name[i:]}.{tld}")
                
        # Character transposition
        for i in range(len(name) - 1):
            similar.append(f"{name[:i]}{name[i+1]}{name[i]}{name[i+2:]}.{tld}")
            
        return list(set(similar))
        
    def _calculate_levenshtein(self, s1: str, s2: str) -> float:
        """Calculate Levenshtein distance.
        
        Args:
            s1: First string
            s2: Second string
            
        Returns:
            Normalized Levenshtein distance (0-1)
        """
        if len(s1) < len(s2):
            return self._calculate_levenshtein(s2, s1)
            
        if len(s2) == 0:
            return 1.0
            
        previous_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row
            
        return 1.0 - (previous_row[-1] / max(len(s1), len(s2)))
        
    @retry(max_retries=3, initial_delay=1.0)
    async def _check_domain_registration(self, domain: str) -> bool:
        """Check if domain is registered.
        
        Args:
            domain: Domain to check
            
        Returns:
            True if domain is registered
        """
        try:
            w = whois.whois(domain)
            return bool(w.domain_name)
        except Exception:
            return False
            
    async def collect_data(self, domain: str) -> TyposquatData:
        """Collect typosquat data.
        
        Args:
            domain: Domain to check
            
        Returns:
            Typosquat data
        """
        # Check cache first
        if self.cache:
            cached_data = self.cache.get(self.id, domain)
            if cached_data:
                return TyposquatData(**cached_data)
                
        try:
            # Generate similar domains
            similar_domains = self._generate_similar_domains(domain)
            
            # Check registration status
            registered_similar = []
            for similar in similar_domains:
                if await self._check_domain_registration(similar):
                    registered_similar.append(similar)
                    
            # Calculate Levenshtein scores
            levenshtein_scores = {
                similar: self._calculate_levenshtein(domain, similar)
                for similar in registered_similar
            }
            
            # Calculate risk level
            if not registered_similar:
                risk_level = 0.0
            else:
                risk_level = max(levenshtein_scores.values())
                
            data = TyposquatData(
                domain=domain,
                similar_domains=similar_domains,
                registered_similar=registered_similar,
                levenshtein_scores=levenshtein_scores,
                is_typosquat=bool(registered_similar),
                risk_level=risk_level
            )
            
            # Cache result
            if self.cache:
                self.cache.set(self.id, domain, data.__dict__)
                
            return data
            
        except Exception as e:
            return TyposquatData(
                domain=domain,
                similar_domains=[],
                registered_similar=[],
                levenshtein_scores={},
                is_typosquat=False,
                risk_level=0.0,
                error=str(e)
            )
            
    async def run(self, domain: str) -> ProbeResult:
        """Run probe.
        
        Args:
            domain: Domain to check
            
        Returns:
            Probe result
        """
        data = await self.collect_data(domain)
        score = TyposquatScoreCalculator.calculate_score(data)
        
        return ProbeResult(
            probe_id=self.id,
            domain=domain,
            score=score,
            data=data,
            category=self.category
        ) 