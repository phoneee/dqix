from __future__ import annotations
from typing import Tuple, Dict, Any, List, Optional
from dataclasses import dataclass
import re

import requests
from bs4 import BeautifulSoup

from .base import Probe, ProbeData, ScoreCalculator
from . import register
from ..utils.dns import domain_variants
from ..utils.http import get_https_url, fetch_url

@dataclass
class SRIData(ProbeData):
    """Data collected by SRIProbe."""
    domain: str
    html: Optional[str]
    scripts: List[Dict[str, Any]]
    styles: List[Dict[str, Any]]
    error: Optional[str] = None

class SRIScoreCalculator(ScoreCalculator):
    """Calculate score for SRI probe."""
    
    def calculate_score(self, data: SRIData) -> Tuple[float, Dict[str, Any]]:
        """Calculate score from SRI data.
        
        Scoring logic (0–1):
            • Scripts with SRI (0.5)
            • Styles with SRI (0.5)
        """
        if data.error:
            return 0.0, {"error": data.error}
            
        if not data.html:
            return 0.0, {"sri": "no_html"}
            
        score = 0.0
        details = {}
        
        # Check scripts
        scripts_with_sri = [s for s in data.scripts if s.get("integrity")]
        if scripts_with_sri:
            score += 0.5
            details["scripts"] = "with_sri"
        else:
            details["scripts"] = "no_sri"
            
        # Check styles
        styles_with_sri = [s for s in data.styles if s.get("integrity")]
        if styles_with_sri:
            score += 0.5
            details["styles"] = "with_sri"
        else:
            details["styles"] = "no_sri"
            
        details["script_count"] = len(data.scripts)
        details["style_count"] = len(data.styles)
        
        return round(score, 2), details

@register
class SRIProbe(Probe):
    """Check Subresource Integrity (SRI) implementation."""
    
    id, weight = "sri", 0.15
    ScoreCalculator = SRIScoreCalculator
    
    def _parse_html(self, html: str) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        """Parse HTML to extract scripts and styles with SRI."""
        soup = BeautifulSoup(html, "html.parser")
        
        # Get scripts
        scripts = []
        for script in soup.find_all("script", src=True):
            scripts.append({
                "src": script.get("src", ""),
                "integrity": script.get("integrity", ""),
                "crossorigin": script.get("crossorigin", "")
            })
            
        # Get styles
        styles = []
        for style in soup.find_all("link", rel="stylesheet"):
            styles.append({
                "href": style.get("href", ""),
                "integrity": style.get("integrity", ""),
                "crossorigin": style.get("crossorigin", "")
            })
            
        return scripts, styles
        
    def collect_data(self, domain: str) -> SRIData:
        """Collect SRI data for the domain.
        
        Args:
            domain: The domain to check
            
        Returns:
            SRIData containing SRI information
        """
        try:
            self._report_progress(f"SRI: Checking integrity for {domain}...")
            
            # Get homepage
            url = get_https_url(domain)
            resp = fetch_url(url)
            
            if not resp.ok:
                return SRIData(
                    domain=domain,
                    html=None,
                    scripts=[],
                    styles=[],
                    error=f"HTTP {resp.status_code}"
                )
                
            # Parse HTML
            scripts, styles = self._parse_html(resp.text)
            
            return SRIData(
                domain=domain,
                html=resp.text,
                scripts=scripts,
                styles=styles
            )
            
        except Exception as e:
            return SRIData(
                domain=domain,
                html=None,
                scripts=[],
                styles=[],
                error=str(e)
            ) 