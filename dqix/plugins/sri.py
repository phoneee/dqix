"""Subresource Integrity (SRI) plugin for DQIX.

This plugin provides a probe to check if a website implements Subresource Integrity
for its external resources (scripts and stylesheets).
"""

from __future__ import annotations
from typing import Tuple, Dict, Any, List, Optional
from dataclasses import dataclass
import re
import hashlib
import base64

import requests
from bs4 import BeautifulSoup

from .base import ProbePlugin, register_plugin
from ..core.probes import Probe
from ..utils.dns import domain_variants
from ..utils.http import get_https_url, fetch_url

@dataclass
class SRIData:
    """Data collected by SRIProbe."""
    domain: str
    html: Optional[str]
    scripts: List[Dict[str, Any]]
    styles: List[Dict[str, Any]]
    error: Optional[str] = None

class SRIProbe(Probe):
    """Check Subresource Integrity (SRI) implementation."""
    
    id = "sri"
    weight = 0.15
    
    def _parse_html(self, html: str) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        """Parse HTML to extract scripts and styles with SRI."""
        soup = BeautifulSoup(html, "html.parser")
        
        # Get scripts
        scripts = []
        for script in soup.find_all("script", src=True):
            scripts.append({
                "src": script.get("src", ""),
                "integrity": script.get("integrity", ""),
                "crossorigin": script.get("crossorigin", ""),
                "async": script.get("async", False),
                "defer": script.get("defer", False)
            })
            
        # Get styles
        styles = []
        for style in soup.find_all("link", rel="stylesheet"):
            styles.append({
                "href": style.get("href", ""),
                "integrity": style.get("integrity", ""),
                "crossorigin": style.get("crossorigin", ""),
                "media": style.get("media", "all")
            })
            
        return scripts, styles
        
    def _check_hash_algorithm(self, integrity: str) -> Tuple[float, str]:
        """Check hash algorithm used in SRI.
        
        Args:
            integrity: SRI integrity value
            
        Returns:
            Tuple of (score, algorithm)
        """
        if not integrity:
            return 0.0, "none"
            
        # Parse hash algorithm
        match = re.match(r"^(sha\d+)-", integrity)
        if not match:
            return 0.0, "invalid"
            
        algorithm = match.group(1)
        if algorithm == "sha512":
            return 1.0, algorithm
        elif algorithm == "sha384":
            return 0.8, algorithm
        elif algorithm == "sha256":
            return 0.6, algorithm
        else:
            return 0.4, algorithm
            
    def _check_resource(self, url: str) -> Tuple[float, Dict[str, Any]]:
        """Check resource availability and size.
        
        Args:
            url: Resource URL
            
        Returns:
            Tuple of (score, details)
        """
        try:
            resp = requests.head(url, timeout=5)
            if not resp.ok:
                return 0.0, {"error": f"HTTP {resp.status_code}"}
                
            size = int(resp.headers.get("content-length", 0))
            if size > 1024 * 1024:  # > 1MB
                return 0.5, {"size": size, "status": "large"}
            else:
                return 1.0, {"size": size, "status": "ok"}
                
        except Exception as e:
            return 0.0, {"error": str(e)}
            
    def run(self, domain: str) -> Tuple[float, dict]:
        """Run SRI check on domain.
        
        Args:
            domain: Domain to check
            
        Returns:
            Tuple of (score, details) where:
            - score is a float between 0 and 1
            - details is a dict with SRI information
        """
        try:
            # Get homepage
            url = get_https_url(domain)
            resp = fetch_url(url)
            
            if not resp.ok:
                return 0.0, {
                    "error": f"HTTP {resp.status_code}",
                    "scripts": [],
                    "styles": []
                }
                
            # Parse HTML
            scripts, styles = self._parse_html(resp.text)
            
            # Calculate score
            score = 0.0
            details = {
                "scripts": [],
                "styles": []
            }
            
            # Check scripts
            script_score = 0.0
            for script in scripts:
                script_details = {
                    "src": script["src"],
                    "has_integrity": bool(script["integrity"]),
                    "has_crossorigin": bool(script["crossorigin"]),
                    "async": script["async"],
                    "defer": script["defer"]
                }
                
                # Check integrity
                if script["integrity"]:
                    hash_score, algorithm = self._check_hash_algorithm(script["integrity"])
                    script_details["hash_algorithm"] = algorithm
                    script_score += hash_score
                    
                # Check resource
                if script["src"]:
                    resource_score, resource_details = self._check_resource(script["src"])
                    script_details.update(resource_details)
                    script_score += resource_score
                    
                details["scripts"].append(script_details)
                
            if scripts:
                score += (script_score / len(scripts)) * 0.5
                
            # Check styles
            style_score = 0.0
            for style in styles:
                style_details = {
                    "href": style["href"],
                    "has_integrity": bool(style["integrity"]),
                    "has_crossorigin": bool(style["crossorigin"]),
                    "media": style["media"]
                }
                
                # Check integrity
                if style["integrity"]:
                    hash_score, algorithm = self._check_hash_algorithm(style["integrity"])
                    style_details["hash_algorithm"] = algorithm
                    style_score += hash_score
                    
                # Check resource
                if style["href"]:
                    resource_score, resource_details = self._check_resource(style["href"])
                    style_details.update(resource_details)
                    style_score += resource_score
                    
                details["styles"].append(style_details)
                
            if styles:
                score += (style_score / len(styles)) * 0.5
                
            details["script_count"] = len(scripts)
            details["style_count"] = len(styles)
            
            return round(score, 2), details
            
        except Exception as e:
            return 0.0, {
                "error": str(e),
                "scripts": [],
                "styles": []
            }

@register_plugin
class SRIPlugin(ProbePlugin):
    """Plugin that provides SRI probe."""
    
    name = "sri"
    version = "1.0.0"
    description = "Subresource Integrity (SRI) probe for DQIX"
    
    def initialize(self) -> None:
        """Initialize plugin."""
        pass
        
    def cleanup(self) -> None:
        """Clean up plugin resources."""
        pass
        
    def get_probes(self) -> List[Type[Probe]]:
        """Get the probes provided by this plugin.
        
        Returns:
            List containing SRIProbe
        """
        return [SRIProbe] 