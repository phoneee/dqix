from __future__ import annotations
from typing import Dict, Any, Optional
from dataclasses import dataclass
import aiohttp
from aiohttp import ClientError

from ..base import Probe, ProbeData, ScoreCalculator, ProbeResult, ProbeCategory
from ..utils import retry
from . import register
from ..cache import ProbeCache

@dataclass
class HTTPData(ProbeData):
    """Data collected by HTTPProbe."""
    domain: str
    headers: Dict[str, str]
    has_strict_transport_security: bool
    has_content_security_policy: bool
    has_x_frame_options: bool
    has_x_content_type_options: bool
    has_xss_protection: bool
    has_referrer_policy: bool
    has_permissions_policy: bool
    error: Optional[str] = None

class HTTPScoreCalculator(ScoreCalculator):
    """Calculate score for HTTP probe."""
    
    def calculate_score(self, data: HTTPData) -> ProbeResult:
        """Calculate score from HTTP data.
        
        Scoring logic (0–1):
            • HSTS (0.2)
            • CSP (0.2)
            • X-Frame-Options (0.15)
            • X-Content-Type-Options (0.15)
            • X-XSS-Protection (0.15)
            • Referrer-Policy (0.15)
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
        
        # Check HSTS
        if data.has_strict_transport_security:
            score += 0.2
            details["hsts"] = "enabled"
        else:
            details["hsts"] = "disabled"
            
        # Check CSP
        if data.has_content_security_policy:
            score += 0.2
            details["csp"] = "enabled"
        else:
            details["csp"] = "disabled"
            
        # Check X-Frame-Options
        if data.has_x_frame_options:
            score += 0.15
            details["x_frame_options"] = "enabled"
        else:
            details["x_frame_options"] = "disabled"
            
        # Check X-Content-Type-Options
        if data.has_x_content_type_options:
            score += 0.15
            details["x_content_type_options"] = "enabled"
        else:
            details["x_content_type_options"] = "disabled"
            
        # Check X-XSS-Protection
        if data.has_xss_protection:
            score += 0.15
            details["xss_protection"] = "enabled"
        else:
            details["xss_protection"] = "disabled"
            
        # Check Referrer-Policy
        if data.has_referrer_policy:
            score += 0.15
            details["referrer_policy"] = "enabled"
        else:
            details["referrer_policy"] = "disabled"
            
        return ProbeResult(
            score=round(score, 2),
            details=details,
            data=data,
            category=ProbeCategory.TRUSTWORTHINESS
        )

@register
class HTTPProbe(Probe):
    """Check HTTP security headers."""
    
    id, weight = "http", 0.15
    category = ProbeCategory.TRUSTWORTHINESS
    ScoreCalculator = HTTPScoreCalculator
    
    def __init__(self, cache: Optional[ProbeCache] = None):
        """Initialize probe.
        
        Args:
            cache: Optional cache instance
        """
        super().__init__()
        self.cache = cache
        
    def _check_headers(self, headers: Dict[str, str]) -> tuple[bool, bool, bool, bool, bool, bool]:
        """Check security headers."""
        hsts = "strict-transport-security" in headers
        csp = "content-security-policy" in headers
        xfo = "x-frame-options" in headers
        xcto = "x-content-type-options" in headers
        xss = "x-xss-protection" in headers
        rp = "referrer-policy" in headers
        return hsts, csp, xfo, xcto, xss, rp
            
    @retry(max_retries=3, delay=1.0)
    async def collect_data(self, domain: str) -> HTTPData:
        """Collect HTTP data for the domain.
        
        Args:
            domain: The domain to check
            
        Returns:
            HTTPData containing HTTP information
        """
        try:
            url = f"https://{domain}"
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=10) as response:
                    headers = {k.lower(): v for k, v in response.headers.items()}
                    
                    hsts, csp, xfo, xcto, xss, rp = self._check_headers(headers)
                    
                    return HTTPData(
                        domain=domain,
                        headers=headers,
                        has_strict_transport_security=hsts,
                        has_content_security_policy=csp,
                        has_x_frame_options=xfo,
                        has_x_content_type_options=xcto,
                        has_xss_protection=xss,
                        has_referrer_policy=rp,
                        has_permissions_policy="permissions-policy" in headers
                    )
                    
        except ClientError as e:
            self.logger.error(f"Error collecting HTTP data: {str(e)}", exc_info=True)
            return HTTPData(
                domain=domain,
                headers={},
                has_strict_transport_security=False,
                has_content_security_policy=False,
                has_x_frame_options=False,
                has_x_content_type_options=False,
                has_xss_protection=False,
                has_referrer_policy=False,
                has_permissions_policy=False,
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
        score = self.ScoreCalculator.calculate_score(data)
        
        return ProbeResult(
            probe_id=self.id,
            domain=domain,
            score=score.score,
            data=score.data,
            category=self.category
        ) 