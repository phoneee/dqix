"""TLS/SSL security probe."""

import ssl
import socket
from typing import Dict, Any

from ...domain.entities import Domain, ProbeCategory, ProbeConfig, ProbeResult
from .base import BaseProbe


class TLSProbe(BaseProbe):
    """Checks TLS/SSL configuration."""
    
    def __init__(self):
        super().__init__("tls", ProbeCategory.SECURITY)
    
    async def check(self, domain: Domain, config: ProbeConfig) -> ProbeResult:
        """Check TLS configuration for domain."""
        try:
            # Get SSL certificate info
            context = ssl.create_default_context()
            with socket.create_connection((domain.name, 443), timeout=config.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=domain.name) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    version = ssock.version()
            
            # Calculate score based on TLS version and cipher strength
            score = self._calculate_tls_score(version, cipher)
            
            details = {
                "tls_version": version,
                "cipher_suite": cipher[0] if cipher else None,
                "certificate_subject": cert.get("subject", []) if cert else [],
                "certificate_issuer": cert.get("issuer", []) if cert else [],
                "expires": cert.get("notAfter") if cert else None,
            }
            
            return self._create_result(domain, score, details)
            
        except Exception as e:
            return self._create_result(
                domain, 
                0.0, 
                {"error": str(e)}, 
                error=str(e)
            )
    
    def _calculate_tls_score(self, version: str | None, cipher: tuple | None) -> float:
        """Calculate TLS security score."""
        score = 0.0
        
        # TLS version scoring
        if version:
            if version == "TLSv1.3":
                score += 0.6
            elif version == "TLSv1.2":
                score += 0.4
            else:
                score += 0.1  # Older versions get minimal score
        
        # Cipher suite scoring (basic)
        if cipher and len(cipher) >= 3:
            cipher_name = cipher[0]
            if "AES" in cipher_name:
                score += 0.3
            if "GCM" in cipher_name or "CCM" in cipher_name:
                score += 0.1
        
        return min(1.0, score) 