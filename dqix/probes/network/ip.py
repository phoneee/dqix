from __future__ import annotations
from typing import Dict, Any, Optional, List
from dataclasses import dataclass
import socket
import requests
from requests.exceptions import RequestException
import aiohttp
from aiohttp import ClientError
import geoip2.database
from ..base import Probe, ProbeData, ScoreCalculator, ProbeResult, ProbeCategory
from . import register
from ..cache import ProbeCache
from ..exceptions import IPProbeError

@dataclass
class IPData(ProbeData):
    """Data collected by IPProbe."""
    domain: str
    ip_address: Optional[str]
    is_blacklisted: bool
    blacklist_sources: List[str]
    reputation_score: Optional[float]
    asn: Optional[str]
    country: Optional[str]
    error: Optional[str] = None

class IPScoreCalculator(ScoreCalculator):
    """Calculate score for IP probe."""
    
    def calculate_score(self, data: IPData) -> ProbeResult:
        """Calculate score from IP data.
        
        Scoring logic (0–1):
            • Not Blacklisted (0.4)
            • Good Reputation Score (0.3)
            • Valid ASN (0.15)
            • Valid Country (0.15)
        """
        if data.error:
            return ProbeResult(
                score=0.0,
                details={"error": data.error},
                error=data.error,
                category=ProbeCategory.TRUSTWORTHINESS
            )
            
        score = 0.0
        details = {}
        
        # Check Blacklist Status
        if not data.is_blacklisted:
            score += 0.4
            details["blacklist"] = "clean"
        else:
            details["blacklist"] = f"listed in {', '.join(data.blacklist_sources)}"
            
        # Check Reputation Score
        if data.reputation_score and data.reputation_score >= 0.7:
            score += 0.3
            details["reputation"] = f"good ({data.reputation_score:.2f})"
        else:
            details["reputation"] = "poor"
            
        # Check ASN
        if data.asn:
            score += 0.15
            details["asn"] = data.asn
        else:
            details["asn"] = "unknown"
            
        # Check Country
        if data.country:
            score += 0.15
            details["country"] = data.country
        else:
            details["country"] = "unknown"
            
        return ProbeResult(
            score=round(score, 2),
            details=details,
            data=data,
            category=ProbeCategory.TRUSTWORTHINESS
        )

@register
class IPProbe(Probe):
    """Check IP reputation and blacklists."""
    
    id, weight = "ip", 0.15
    category = ProbeCategory.TRUSTWORTHINESS
    ScoreCalculator = IPScoreCalculator
    
    def __init__(
        self,
        geoip_db_path: str,
        abuseipdb_key: Optional[str] = None,
        cache: Optional[ProbeCache] = None
    ):
        """Initialize probe.
        
        Args:
            geoip_db_path: Path to GeoIP2 database
            abuseipdb_key: Optional AbuseIPDB API key
            cache: Optional cache instance
        """
        super().__init__()
        self.geoip_db_path = geoip_db_path
        self.abuseipdb_key = abuseipdb_key
        self.cache = cache
        
    async def _get_ip_info(self, ip: str) -> tuple[Optional[str], Optional[str]]:
        """Get IP information from GeoIP2.
        
        Args:
            ip: IP address
            
        Returns:
            Tuple of (ASN, country)
        """
        try:
            with geoip2.database.Reader(self.geoip_db_path) as reader:
                asn_response = reader.asn(ip)
                country_response = reader.country(ip)
                
                return (
                    f"AS{asn_response.autonomous_system_number}",
                    country_response.country.iso_code
                )
        except Exception as e:
            raise IPProbeError(f"Failed to get IP info: {str(e)}")
            
    async def _check_blacklists(self, ip: str) -> tuple[bool, List[str]]:
        """Check IP against blacklists.
        
        Args:
            ip: IP address
            
        Returns:
            Tuple of (is_blacklisted, blacklist_sources)
        """
        blacklists = [
            f"zen.spamhaus.org",
            f"multi.surbl.org"
        ]
        
        blacklisted = False
        sources = []
        
        for blacklist in blacklists:
            try:
                reversed_ip = ".".join(reversed(ip.split(".")))
                hostname = f"{reversed_ip}.{blacklist}"
                
                try:
                    socket.gethostbyname(hostname)
                    blacklisted = True
                    sources.append(blacklist)
                except socket.gaierror:
                    pass
                    
            except Exception as e:
                raise IPProbeError(f"Failed to check blacklist {blacklist}: {str(e)}")
                
        return blacklisted, sources
        
    async def _get_reputation_score(self, ip: str) -> float:
        """Get reputation score from AbuseIPDB.
        
        Args:
            ip: IP address
            
        Returns:
            Reputation score between 0 and 1
        """
        if not self.abuseipdb_key:
            return 0.5  # Default score if no API key
            
        try:
            async with aiohttp.ClientSession() as session:
                headers = {
                    "Key": self.abuseipdb_key,
                    "Accept": "application/json"
                }
                
                async with session.get(
                    f"https://api.abuseipdb.com/api/v2/check",
                    params={"ipAddress": ip},
                    headers=headers
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        score = data.get("data", {}).get("abuseConfidenceScore", 50)
                        return 1.0 - (score / 100.0)
                    else:
                        return 0.5
                        
        except Exception as e:
            raise IPProbeError(f"Failed to get reputation score: {str(e)}")
            
    async def collect_data(self, domain: str) -> IPData:
        """Collect IP data for the domain.
        
        Args:
            domain: The domain to check
            
        Returns:
            IPData containing IP information
        """
        # Check cache first
        if self.cache:
            cached_data = self.cache.get(self.id, domain)
            if cached_data:
                return IPData(**cached_data)
                
        try:
            # Resolve IP
            ip = socket.gethostbyname(domain)
            
            # Get IP info
            asn, country = await self._get_ip_info(ip)
            
            # Check blacklists
            is_blacklisted, blacklist_sources = await self._check_blacklists(ip)
            
            # Get reputation score
            reputation_score = await self._get_reputation_score(ip)
            
            data = IPData(
                domain=domain,
                ip_address=ip,
                is_blacklisted=is_blacklisted,
                blacklist_sources=blacklist_sources,
                reputation_score=reputation_score,
                asn=asn,
                country=country
            )
            
            # Cache result
            if self.cache:
                self.cache.set(self.id, domain, data.__dict__)
                
            return data
            
        except Exception as e:
            self.logger.error(f"Error collecting IP data: {str(e)}", exc_info=True)
            return IPData(
                domain=domain,
                ip_address=None,
                is_blacklisted=False,
                blacklist_sources=[],
                reputation_score=None,
                asn=None,
                country=None,
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
        score = IPScoreCalculator.calculate_score(data)
        
        return ProbeResult(
            probe_id=self.id,
            domain=domain,
            score=score,
            data=data,
            category=self.category
        ) 