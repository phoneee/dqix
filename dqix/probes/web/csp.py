from __future__ import annotations
from typing import Tuple, Dict, Any, List, Optional
from dataclasses import dataclass
import requests
from urllib.parse import urlparse
import re

from ..base import Probe, ProbeData, ScoreCalculator
from .. import register
from dqix.utils.dns import domain_variants
from dqix.utils.http import get_https_url, fetch_url, is_gaierror_like

@dataclass
class CSPData(ProbeData):
    """Data collected by CSPProbe."""
    domain: str
    csp_header: Optional[str]
    report_uri: Optional[str]
    directives: Dict[str, List[str]]
    error: Optional[str] = None

class CSPScoreCalculator(ScoreCalculator):
    """Calculate score for CSP probe."""
    
    def _parse_directives(self, csp: str) -> Dict[str, List[str]]:
        """Parse CSP header into directives."""
        directives = {}
        for directive in csp.split(";"):
            directive = directive.strip()
            if not directive:
                continue
                
            if " " in directive:
                name, value = directive.split(" ", 1)
                directives[name.lower()] = [v.strip() for v in value.split()]
            else:
                directives[directive.lower()] = []
                
        return directives
        
    def calculate_score(self, data: CSPData) -> Tuple[float, Dict[str, Any]]:
        """Calculate score from CSP data.
        
        Scoring logic (0–1):
            • CSP header present (0.2)
            • default-src present (0.2)
            • script-src present (0.2)
            • style-src present (0.2)
            • report-uri present (0.2)
        """
        if data.error:
            return 0.0, {"error": data.error}
            
        if not data.csp_header:
            return 0.0, {"csp": "missing"}
            
        score = 0.0
        details = {}
        
        # Check presence of key directives
        if "default-src" in data.directives:
            score += 0.2
            details["default_src"] = "present"
        else:
            details["default_src"] = "missing"
            
        if "script-src" in data.directives:
            score += 0.2
            details["script_src"] = "present"
        else:
            details["script_src"] = "missing"
            
        if "style-src" in data.directives:
            score += 0.2
            details["style_src"] = "present"
        else:
            details["style_src"] = "missing"
            
        if data.report_uri:
            score += 0.2
            details["report_uri"] = "present"
        else:
            details["report_uri"] = "missing"
            
        # Check for unsafe-inline/unsafe-eval
        unsafe = False
        for directive in ["script-src", "style-src"]:
            if directive in data.directives:
                for value in data.directives[directive]:
                    if value in ["unsafe-inline", "unsafe-eval"]:
                        unsafe = True
                        break
                        
        if unsafe:
            details["unsafe_directives"] = "present"
        else:
            details["unsafe_directives"] = "absent"
            
        return round(score, 2), details

@register
class CSPProbe(Probe):
    """Check Content Security Policy configuration."""
    
    id, weight = "csp", 0.15
    ScoreCalculator = CSPScoreCalculator
    
    def collect_data(self, domain: str) -> CSPData:
        """Collect CSP data for the domain.
        
        Args:
            domain: The domain to check
            
        Returns:
            CSPData containing CSP configuration
        """
        try:
            self._report_progress(f"CSP: Checking policy for {domain}...")
            
            # Get CSP header
            url = get_https_url(domain)
            resp = fetch_url(url)
            
            csp_header = resp.headers.get("Content-Security-Policy")
            if not csp_header:
                return CSPData(
                    domain=domain,
                    csp_header=None,
                    report_uri=None,
                    directives={}
                )
                
            # Parse directives
            directives = self._parse_directives(csp_header)
            
            # Extract report-uri
            report_uri = None
            if "report-uri" in directives:
                report_uri = directives["report-uri"][0]
                
            return CSPData(
                domain=domain,
                csp_header=csp_header,
                report_uri=report_uri,
                directives=directives
            )
            
        except Exception as e:
            return CSPData(
                domain=domain,
                csp_header=None,
                report_uri=None,
                directives={},
                error=str(e)
            ) 