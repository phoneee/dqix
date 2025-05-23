from __future__ import annotations
from typing import Tuple, Dict, Any, List
import requests

from .base import Probe
from . import register
from ..utils.dns import domain_variants
from ..utils.http import get_https_url, fetch_url, is_gaierror_like

@register
class HeaderProbe(Probe):
    """Check HTTP security headers and best practices.
    
    Scoring logic (0–1):
        • HSTS (0.20)
        • CSP (0.20)
        • X-Frame-Options (0.15)
        • X-Content-Type-Options (0.15)
        • Referrer-Policy (0.15)
        • Permissions-Policy (0.15)
    """
    
    id, weight = "headers", 0.10
    
    def _check_hsts(self, headers: Dict[str, str]) -> Tuple[float, Dict[str, Any]]:
        """Check HSTS header configuration.
        
        Args:
            headers: Response headers
            
        Returns:
            Tuple of (score, details)
        """
        hsts = headers.get("Strict-Transport-Security", "").lower()
        if not hsts:
            return 0.0, {"hsts": "missing"}
            
        # Check for max-age
        if "max-age=" not in hsts:
            return 0.5, {"hsts": "present but no max-age"}
            
        # Parse max-age value
        try:
            max_age = int(hsts.split("max-age=")[1].split(";")[0])
            if max_age >= 31536000:  # 1 year
                return 1.0, {"hsts": "present with max-age >= 1 year"}
            else:
                return 0.75, {"hsts": f"present with max-age {max_age}"}
        except (ValueError, IndexError):
            return 0.5, {"hsts": "present but invalid max-age"}
            
    def _check_csp(self, headers: Dict[str, str]) -> Tuple[float, Dict[str, Any]]:
        """Check Content-Security-Policy header.
        
        Args:
            headers: Response headers
            
        Returns:
            Tuple of (score, details)
        """
        csp = headers.get("Content-Security-Policy", "")
        if not csp:
            return 0.0, {"csp": "missing"}
            
        # Basic CSP present
        return 1.0, {"csp": "present"}
        
    def _check_frame_options(self, headers: Dict[str, str]) -> Tuple[float, Dict[str, Any]]:
        """Check X-Frame-Options header.
        
        Args:
            headers: Response headers
            
        Returns:
            Tuple of (score, details)
        """
        xfo = headers.get("X-Frame-Options", "").lower()
        if not xfo:
            return 0.0, {"x_frame_options": "missing"}
            
        if xfo in ["deny", "sameorigin"]:
            return 1.0, {"x_frame_options": xfo}
        else:
            return 0.5, {"x_frame_options": "invalid value"}
            
    def _check_content_type(self, headers: Dict[str, str]) -> Tuple[float, Dict[str, Any]]:
        """Check X-Content-Type-Options header.
        
        Args:
            headers: Response headers
            
        Returns:
            Tuple of (score, details)
        """
        xcto = headers.get("X-Content-Type-Options", "").lower()
        if xcto == "nosniff":
            return 1.0, {"x_content_type_options": "present"}
        else:
            return 0.0, {"x_content_type_options": "missing"}
            
    def _check_referrer(self, headers: Dict[str, str]) -> Tuple[float, Dict[str, Any]]:
        """Check Referrer-Policy header.
        
        Args:
            headers: Response headers
            
        Returns:
            Tuple of (score, details)
        """
        ref = headers.get("Referrer-Policy", "").lower()
        if not ref:
            return 0.0, {"referrer_policy": "missing"}
            
        # Strict policies
        if ref in ["strict-origin-when-cross-origin", "strict-origin", "no-referrer"]:
            return 1.0, {"referrer_policy": ref}
        # Less strict but still good
        elif ref in ["origin-when-cross-origin", "origin", "same-origin"]:
            return 0.75, {"referrer_policy": ref}
        else:
            return 0.5, {"referrer_policy": "present but weak"}
            
    def _check_permissions(self, headers: Dict[str, str]) -> Tuple[float, Dict[str, Any]]:
        """Check Permissions-Policy header.
        
        Args:
            headers: Response headers
            
        Returns:
            Tuple of (score, details)
        """
        pp = headers.get("Permissions-Policy", "")
        if not pp:
            return 0.0, {"permissions_policy": "missing"}
            
        # Basic policy present
        return 1.0, {"permissions_policy": "present"}
        
    def run(self, original_domain: str) -> Tuple[float, Dict[str, Any]]:
        """Run header checks against the domain.
        
        Args:
            original_domain: The domain to check
            
        Returns:
            Tuple of (score, details) where score is between 0 and 1
        """
        variants = domain_variants(original_domain)
        last_err = None
        
        for dom in variants:
            try:
                self._report_progress(f"Headers: Checking {dom}...")
                url = get_https_url(dom)
                resp = fetch_url(url)
                
                # Run all header checks
                hsts_score, hsts_details = self._check_hsts(resp.headers)
                csp_score, csp_details = self._check_csp(resp.headers)
                frame_score, frame_details = self._check_frame_options(resp.headers)
                type_score, type_details = self._check_content_type(resp.headers)
                ref_score, ref_details = self._check_referrer(resp.headers)
                perm_score, perm_details = self._check_permissions(resp.headers)
                
                # Calculate weighted score
                score = (
                    hsts_score * 0.20 +
                    csp_score * 0.20 +
                    frame_score * 0.15 +
                    type_score * 0.15 +
                    ref_score * 0.15 +
                    perm_score * 0.15
                )
                
                details = {
                    "attempted_domain": dom,
                    "original_domain": original_domain,
                    **hsts_details,
                    **csp_details,
                    **frame_details,
                    **type_details,
                    **ref_details,
                    **perm_details
                }
                
                return round(score, 2), details
                
            except requests.RequestException as e:
                if is_gaierror_like(e):
                    last_err = str(e)
                    continue
                return 0.0, {
                    "error": f"Request failed: {str(e)}",
                    "attempted_domain": dom,
                    "original_domain": original_domain
                }
            except Exception as e:
                return 0.0, {
                    "error": f"Unexpected error: {str(e)}",
                    "attempted_domain": dom,
                    "original_domain": original_domain
                }
                
        return 0.0, {
            "error": last_err or "All domain variants failed",
            "original_domain": original_domain
        } 