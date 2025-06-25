"""Security headers probe."""

import aiohttp
from typing import Dict, Any

from ...domain.entities import Domain, ProbeCategory, ProbeConfig, ProbeResult
from .base import BaseProbe


class SecurityHeadersProbe(BaseProbe):
    """Checks HTTP security headers."""
    
    def __init__(self):
        super().__init__("security_headers", ProbeCategory.SECURITY)
    
    async def check(self, domain: Domain, config: ProbeConfig) -> ProbeResult:
        """Check security headers for domain."""
        try:
            timeout = aiohttp.ClientTimeout(total=config.timeout)
            
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(f"https://{domain.name}") as response:
                    headers = dict(response.headers)
                    
                    score = self._calculate_security_score(headers)
                    details = self._extract_security_details(headers)
                    
                    return self._create_result(domain, score, details)
                    
        except Exception as e:
            return self._create_result(
                domain, 
                0.0, 
                {"error": str(e)}, 
                error=str(e)
            )
    
    def _calculate_security_score(self, headers: Dict[str, str]) -> float:
        """Calculate security headers score."""
        score = 0.0
        
        # Check for important security headers
        security_headers = {
            "strict-transport-security": 0.25,  # HSTS
            "x-frame-options": 0.15,
            "x-content-type-options": 0.15,
            "x-xss-protection": 0.1,
            "content-security-policy": 0.25,
            "referrer-policy": 0.1,
        }
        
        for header, weight in security_headers.items():
            if header in [h.lower() for h in headers.keys()]:
                score += weight
        
        return min(1.0, score)
    
    def _extract_security_details(self, headers: Dict[str, str]) -> Dict[str, Any]:
        """Extract security header details."""
        details = {}
        
        # Normalize header names to lowercase for comparison
        lower_headers = {k.lower(): v for k, v in headers.items()}
        
        security_headers = [
            "strict-transport-security",
            "x-frame-options", 
            "x-content-type-options",
            "x-xss-protection",
            "content-security-policy",
            "referrer-policy"
        ]
        
        for header in security_headers:
            if header in lower_headers:
                details[header] = lower_headers[header]
            else:
                details[header] = None
        
        return details 