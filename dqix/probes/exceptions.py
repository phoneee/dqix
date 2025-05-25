from __future__ import annotations
from typing import Optional

class ProbeError(Exception):
    """Base exception for probe errors."""
    
    def __init__(self, message: str, domain: Optional[str] = None):
        """Initialize exception.
        
        Args:
            message: Error message
            domain: Optional domain name
        """
        self.message = message
        self.domain = domain
        super().__init__(f"{message} (domain: {domain})" if domain else message)

class DNSProbeError(ProbeError):
    """Exception raised for DNS probe errors."""
    pass

class TLSProbeError(ProbeError):
    """Exception raised for TLS probe errors."""
    pass

class HTTPProbeError(ProbeError):
    """Exception raised for HTTP probe errors."""
    pass

class IPProbeError(ProbeError):
    """Exception raised for IP probe errors."""
    pass

class WHOISProbeError(ProbeError):
    """Exception raised for WHOIS probe errors."""
    pass

class ReputationProbeError(ProbeError):
    """Exception raised for reputation probe errors."""
    pass

class TyposquatProbeError(ProbeError):
    """Exception raised for typosquat probe errors."""
    pass

class MXProbeError(ProbeError):
    """Exception raised for MX probe errors."""
    pass

class SPFProbeError(ProbeError):
    """Exception raised for SPF probe errors."""
    pass

class DKIMProbeError(ProbeError):
    """Exception raised for DKIM probe errors."""
    pass

class DMARCProbeError(ProbeError):
    """Exception raised for DMARC probe errors."""
    pass

class ConnectionError(ProbeError):
    """Exception raised for connection errors."""
    pass

class TimeoutError(ProbeError):
    """Exception raised for timeout errors."""
    pass

class ValidationError(ProbeError):
    """Exception raised for validation errors."""
    pass

class ConfigurationError(ProbeError):
    """Exception raised for configuration errors."""
    pass 