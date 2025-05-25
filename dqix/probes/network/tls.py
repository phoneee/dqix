from __future__ import annotations
from typing import Dict, Any, Optional
from dataclasses import dataclass
import ssl
import socket
import datetime
import OpenSSL.crypto

from ..base import Probe, ProbeData, ScoreCalculator, ProbeResult, ProbeCategory
from . import register

@dataclass
class TLSData(ProbeData):
    """Data collected by TLSProbe."""
    domain: str
    has_certificate: bool
    is_valid: bool
    issuer: Optional[str]
    expiry_date: Optional[datetime.datetime]
    days_until_expiry: Optional[int]
    protocol_version: Optional[str]
    cipher_suite: Optional[str]
    error: Optional[str] = None

class TLSScoreCalculator(ScoreCalculator):
    """Calculate score for TLS probe."""
    
    def calculate_score(self, data: TLSData) -> ProbeResult:
        """Calculate score from TLS data.
        
        Scoring logic (0–1):
            • Has Certificate (0.2)
            • Is Valid (0.2)
            • Days Until Expiry > 30 (0.2)
            • Modern Protocol (TLS 1.2+) (0.2)
            • Strong Cipher Suite (0.2)
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
        
        # Check Certificate Presence
        if data.has_certificate:
            score += 0.2
            details["certificate"] = "present"
        else:
            details["certificate"] = "missing"
            
        # Check Certificate Validity
        if data.is_valid:
            score += 0.2
            details["validity"] = "valid"
        else:
            details["validity"] = "invalid"
            
        # Check Expiry
        if data.days_until_expiry and data.days_until_expiry > 30:
            score += 0.2
            details["expiry"] = f"{data.days_until_expiry} days"
        else:
            details["expiry"] = "expiring soon"
            
        # Check Protocol Version
        if data.protocol_version and data.protocol_version >= "TLSv1.2":
            score += 0.2
            details["protocol"] = "modern"
        else:
            details["protocol"] = "outdated"
            
        # Check Cipher Suite
        if data.cipher_suite and "ECDHE" in data.cipher_suite:
            score += 0.2
            details["cipher"] = "strong"
        else:
            details["cipher"] = "weak"
            
        return ProbeResult(
            score=round(score, 2),
            details=details,
            data=data,
            category=ProbeCategory.TRUSTWORTHINESS
        )

@register
class TLSProbe(Probe):
    """Check SSL/TLS configuration and security."""
    
    id, weight = "tls", 0.15
    category = ProbeCategory.TRUSTWORTHINESS
    ScoreCalculator = TLSScoreCalculator
    
    def _get_certificate_info(self, hostname: str) -> tuple[bool, bool, Optional[str], Optional[datetime.datetime], Optional[int], Optional[str], Optional[str]]:
        """Get SSL/TLS certificate information."""
        try:
            context = ssl.create_default_context()
            with socket.create_connection((hostname, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert(binary_form=True)
                    if cert:
                        x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, cert)
                        issuer = x509.get_issuer().CN
                        not_after = datetime.datetime.strptime(x509.get_notAfter().decode('ascii'), '%Y%m%d%H%M%SZ')
                        days_until_expiry = (not_after - datetime.datetime.now()).days
                        protocol_version = ssock.version()
                        cipher_suite = ssock.cipher()[0]
                        return True, True, issuer, not_after, days_until_expiry, protocol_version, cipher_suite
            return False, False, None, None, None, None, None
        except Exception:
            return False, False, None, None, None, None, None
            
    def collect_data(self, domain: str) -> TLSData:
        """Collect TLS data for the domain.
        
        Args:
            domain: The domain to check
            
        Returns:
            TLSData containing TLS information
        """
        try:
            has_cert, is_valid, issuer, expiry, days, protocol, cipher = self._get_certificate_info(domain)
            
            return TLSData(
                domain=domain,
                has_certificate=has_cert,
                is_valid=is_valid,
                issuer=issuer,
                expiry_date=expiry,
                days_until_expiry=days,
                protocol_version=protocol,
                cipher_suite=cipher
            )
            
        except Exception as e:
            self.logger.error(f"Error collecting TLS data: {str(e)}", exc_info=True)
            return TLSData(
                domain=domain,
                has_certificate=False,
                is_valid=False,
                issuer=None,
                expiry_date=None,
                days_until_expiry=None,
                protocol_version=None,
                cipher_suite=None,
                error=str(e)
            ) 