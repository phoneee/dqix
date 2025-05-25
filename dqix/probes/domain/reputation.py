from __future__ import annotations
from dataclasses import dataclass
from typing import Dict, List, Optional
import aiohttp
import json

from ..base import Probe, ProbeResult, ProbeCategory
from ..cache import ProbeCache
from ..exceptions import ReputationProbeError
from ..utils import retry

@dataclass
class ReputationData:
    """Domain reputation data."""
    domain: str
    is_blacklisted: bool
    blacklist_sources: List[str]
    malware_detected: bool
    malware_types: List[str]
    phishing_risk: float
    spam_score: float
    trust_score: float
    error: Optional[str] = None

class ReputationScoreCalculator:
    """Calculate score based on reputation data."""
    
    @staticmethod
    def calculate_score(data: ReputationData) -> float:
        """Calculate score.
        
        Scoring logic (0–1):
            • Not blacklisted (0.3)
            • No malware (0.3)
            • Low phishing risk (0.2)
            • Low spam score (0.2)
        """
        if data.error:
            return 0.0
            
        score = 0.0
        
        # Check blacklist status
        if not data.is_blacklisted:
            score += 0.3
            
        # Check malware
        if not data.malware_detected:
            score += 0.3
            
        # Check phishing risk
        if data.phishing_risk < 0.3:
            score += 0.2
        elif data.phishing_risk < 0.7:
            score += 0.1
            
        # Check spam score
        if data.spam_score < 0.3:
            score += 0.2
        elif data.spam_score < 0.7:
            score += 0.1
            
        return score

class ReputationProbe(Probe):
    """Probe for checking domain reputation."""
    
    def __init__(self, cache: Optional[ProbeCache] = None):
        """Initialize probe.
        
        Args:
            cache: Optional cache instance
        """
        super().__init__()
        self.category = ProbeCategory.TRUSTWORTHINESS
        self.cache = cache
        
    @retry(max_retries=3, initial_delay=1.0)
    async def _check_blacklists(self, domain: str) -> tuple[bool, List[str]]:
        """Check domain against blacklists.
        
        Args:
            domain: Domain to check
            
        Returns:
            Tuple of (is_blacklisted, blacklist_sources)
        """
        blacklists = [
            "uribl.com",
            "spamhaus.org",
            "surbl.org"
        ]
        
        blacklisted = False
        sources = []
        
        async with aiohttp.ClientSession() as session:
            for bl in blacklists:
                try:
                    async with session.get(f"http://{bl}/check/{domain}") as response:
                        if response.status == 200:
                            blacklisted = True
                            sources.append(bl)
                except Exception:
                    continue
                    
        return blacklisted, sources
        
    @retry(max_retries=3, initial_delay=1.0)
    async def _check_malware(self, domain: str) -> tuple[bool, List[str]]:
        """Check domain for malware.
        
        Args:
            domain: Domain to check
            
        Returns:
            Tuple of (malware_detected, malware_types)
        """
        # TODO: Implement actual malware checking
        return False, []
        
    @retry(max_retries=3, initial_delay=1.0)
    async def _check_phishing(self, domain: str) -> float:
        """Check domain for phishing risk.
        
        Args:
            domain: Domain to check
            
        Returns:
            Phishing risk score (0-1)
        """
        # TODO: Implement actual phishing checking
        return 0.0
        
    @retry(max_retries=3, initial_delay=1.0)
    async def _check_spam(self, domain: str) -> float:
        """Check domain for spam score.
        
        Args:
            domain: Domain to check
            
        Returns:
            Spam score (0-1)
        """
        # TODO: Implement actual spam checking
        return 0.0
        
    async def collect_data(self, domain: str) -> ReputationData:
        """Collect reputation data.
        
        Args:
            domain: Domain to check
            
        Returns:
            Reputation data
        """
        # Check cache first
        if self.cache:
            cached_data = self.cache.get(self.id, domain)
            if cached_data:
                return ReputationData(**cached_data)
                
        try:
            # Check various reputation factors
            is_blacklisted, blacklist_sources = await self._check_blacklists(domain)
            malware_detected, malware_types = await self._check_malware(domain)
            phishing_risk = await self._check_phishing(domain)
            spam_score = await self._check_spam(domain)
            
            # Calculate trust score
            trust_score = 1.0
            if is_blacklisted:
                trust_score -= 0.3
            if malware_detected:
                trust_score -= 0.3
            trust_score -= phishing_risk * 0.2
            trust_score -= spam_score * 0.2
            trust_score = max(0.0, min(1.0, trust_score))
            
            data = ReputationData(
                domain=domain,
                is_blacklisted=is_blacklisted,
                blacklist_sources=blacklist_sources,
                malware_detected=malware_detected,
                malware_types=malware_types,
                phishing_risk=phishing_risk,
                spam_score=spam_score,
                trust_score=trust_score
            )
            
            # Cache result
            if self.cache:
                self.cache.set(self.id, domain, data.__dict__)
                
            return data
            
        except Exception as e:
            return ReputationData(
                domain=domain,
                is_blacklisted=False,
                blacklist_sources=[],
                malware_detected=False,
                malware_types=[],
                phishing_risk=1.0,
                spam_score=1.0,
                trust_score=0.0,
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
        score = ReputationScoreCalculator.calculate_score(data)
        
        return ProbeResult(
            probe_id=self.id,
            domain=domain,
            score=score,
            data=data,
            category=self.category
        ) 