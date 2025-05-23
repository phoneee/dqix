"""Thin wrapper around `aiohttp` / `requests` for future async refactor.
Currently only basic sync helpers are provided.
"""
from __future__ import annotations

from typing import Dict, Any, Optional
import requests
from urllib.parse import urlparse


DEFAULT_HEADERS: Dict[str, str] = {
    "User-Agent": "DQIX Probe/1.0",
}


def get_https_url(domain: str, path: str = "") -> str:
    """Construct HTTPS URL for a domain.
    
    Args:
        domain: Domain name
        path: Optional path to append
        
    Returns:
        Full HTTPS URL
    """
    # Ensure path starts with /
    if path and not path.startswith("/"):
        path = "/" + path
    return f"https://{domain}{path}"

def fetch_url(
    url: str,
    timeout: int = 8,
    allow_redirects: bool = True,
    headers: Optional[Dict[str, str]] = None,
) -> requests.Response:
    """Fetch URL with common settings.
    
    Args:
        url: URL to fetch
        timeout: Request timeout in seconds
        allow_redirects: Whether to follow redirects
        headers: Optional headers to send
        
    Returns:
        Response object
        
    Raises:
        requests.RequestException: On request failure
    """
    if headers is None:
        headers = {"User-Agent": "DQIX Probe/1.0"}
        
    return requests.get(
        url,
        timeout=timeout,
        allow_redirects=allow_redirects,
        headers=headers,
    )

def is_gaierror_like(e: Exception) -> bool:
    """Check if exception is DNS resolution-like error.
    
    Args:
        e: Exception to check
        
    Returns:
        True if error appears to be DNS-related
    """
    err_str = str(e).lower()
    return any(
        msg in err_str
        for msg in [
            "failed to resolve",
            "nodename nor servname",
            "dns lookup failed",
            "name or service not known",
        ]
    ) 