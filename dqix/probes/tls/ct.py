from __future__ import annotations
from typing import Tuple, Dict, Any, List, Optional
from dataclasses import dataclass
import json
import time
from datetime import datetime, timedelta, timezone

import requests
import base64
import struct

from ..base import Probe, ProbeData, ScoreCalculator
from .. import register
from dqix.utils.dns import domain_variants

# Google's CT API endpoint
CT_API = "https://transparencyreport.google.com/transparencyreport/api/v3/httpsreport/ct/certsearch"

@dataclass
class CTData(ProbeData):
    """Data collected by CTProbe."""
    domain: str
    certificates: List[Dict[str, Any]]
    log_count: int
    monitoring_enabled: bool
    error: Optional[str] = None

class CTScoreCalculator(ScoreCalculator):
    """Calculate score for CT probe."""
    
    def calculate_score(self, data: CTData) -> Tuple[float, Dict[str, Any]]:
        """Calculate score from CT data.
        
        Scoring logic (0–1):
            • Certificates found in logs (0.3)
            • Multiple logs (0.3)
            • Monitoring enabled (0.4)
        """
        if data.error:
            return 0.0, {"error": data.error}
            
        if not data.certificates:
            return 0.0, {"ct": "no_certificates"}
            
        score = 0.0
        details = {}
        
        # Check certificates in logs
        if data.certificates:
            score += 0.3
            details["certificates"] = "found"
        else:
            details["certificates"] = "not_found"
            
        # Check multiple logs
        if data.log_count >= 2:
            score += 0.3
            details["logs"] = "multiple"
        else:
            details["logs"] = "single"
            
        # Check monitoring
        if data.monitoring_enabled:
            score += 0.4
            details["monitoring"] = "enabled"
        else:
            details["monitoring"] = "disabled"
            
        details["cert_count"] = len(data.certificates)
        details["log_count"] = data.log_count
        
        return round(score, 2), details

@register
class CTProbe(Probe):
    """Check Certificate Transparency logs."""
    
    id, weight = "ct", 0.15
    ScoreCalculator = CTScoreCalculator
    
    def _query_ct_api(self, domain: str) -> List[Dict[str, Any]]:
        """Query Google's CT API for certificates."""
        try:
            # Format request
            params = {
                "domain": domain,
                "include_subdomains": "true",
                "include_expired": "false"
            }
            
            # Make request
            resp = requests.get(CT_API, params=params, timeout=10)
            resp.raise_for_status()
            
            # Parse response
            data = resp.text
            if not data.startswith(")]}'"):
                return []
                
            # Remove XSSI prefix
            data = data[4:]
            
            # Parse JSON
            certs = json.loads(data)
            if not certs or not isinstance(certs, list):
                return []
                
            # Extract certificate info
            result = []
            for cert in certs:
                if not isinstance(cert, list) or len(cert) < 3:
                    continue
                    
                result.append({
                    "serial": cert[0],
                    "issuer": cert[1],
                    "not_before": cert[2],
                    "not_after": cert[3],
                    "logs": cert[4] if len(cert) > 4 else []
                })
                
            return result
            
        except Exception:
            return []
            
    def collect_data(self, domain: str) -> CTData:
        """Collect CT data for the domain.
        
        Args:
            domain: The domain to check
            
        Returns:
            CTData containing CT information
        """
        try:
            self._report_progress(f"CT: Checking logs for {domain}...")
            
            # Query CT API
            certificates = self._query_ct_api(domain)
            
            # Count unique logs
            logs = set()
            for cert in certificates:
                logs.update(cert.get("logs", []))
                
            # Check for monitoring
            monitoring_enabled = False
            for cert in certificates:
                if len(cert.get("logs", [])) >= 2:
                    monitoring_enabled = True
                    break
                    
            return CTData(
                domain=domain,
                certificates=certificates,
                log_count=len(logs),
                monitoring_enabled=monitoring_enabled
            )
            
        except Exception as e:
            return CTData(
                domain=domain,
                certificates=[],
                log_count=0,
                monitoring_enabled=False,
                error=str(e)
            ) 