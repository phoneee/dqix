"""Async-friendly DNS helper functions for DQIX.
Currently implemented synchronously via `dnspython` but the
API is prepared for future `aiodns` refactor.
"""
from __future__ import annotations

from typing import List, Set
import dns.resolver

__all__ = [
    "domain_variants",
    "get_txt_records",
    "get_caa_records",
    "get_mx_records",
    "get_ns_records",
    "get_soa_record",
    "get_a_records",
    "get_aaaa_records",
]


def domain_variants(domain: str) -> List[str]:
    """Get list of domain variants to try.
    
    Args:
        domain: Original domain name
        
    Returns:
        List of domain variants in order of preference
    """
    # Remove any protocol prefix
    domain = domain.lower().strip()
    if domain.startswith(("http://", "https://")):
        domain = domain.split("://", 1)[1]
        
    # Remove any path
    domain = domain.split("/", 1)[0]
    
    # Remove any port
    domain = domain.split(":", 1)[0]
    
    # Try www and non-www variants
    variants = []
    if domain.startswith("www."):
        variants = [domain, domain[4:]]
    else:
        variants = [domain, f"www.{domain}"]
        
    return variants


def get_txt_records(domain: str) -> List[str]:
    """Get all TXT records for a domain.
    
    Args:
        domain: Domain to query
        
    Returns:
        List of TXT record strings, empty list on error
    """
    try:
        answers = dns.resolver.resolve(domain, "TXT", raise_on_no_answer=False)
        return [r.to_text().strip('"') for r in answers]
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        return []
    except Exception:
        return []


def get_caa_records(domain: str) -> List[str]:
    """Return CAA records for *domain* (empty list on error)."""
    try:
        resolver = dns.resolver.Resolver()
        return [r.to_text() for r in resolver.resolve(domain, "CAA")]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
        return []
    except Exception:
        return []


def get_mx_records(domain: str) -> List[str]:
    """Get all MX records for a domain.
    
    Args:
        domain: Domain to query
        
    Returns:
        List of MX hostnames, empty list on error
    """
    try:
        answers = dns.resolver.resolve(domain, "MX", raise_on_no_answer=False)
        return [str(r.exchange).rstrip(".") for r in answers]
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        return []
    except Exception:
        return []


def get_ns_records(domain: str) -> List[str]:
    """Get all NS records for a domain.
    
    Args:
        domain: Domain to query
        
    Returns:
        List of nameserver hostnames, empty list on error
    """
    try:
        answers = dns.resolver.resolve(domain, "NS", raise_on_no_answer=False)
        return [str(r.target).rstrip(".") for r in answers]
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        return []
    except Exception:
        return []


def get_soa_record(domain: str) -> List[str]:
    """Get SOA record for a domain.
    
    Args:
        domain: Domain to query
        
    Returns:
        List containing SOA record string if found, empty list on error
    """
    try:
        answers = dns.resolver.resolve(domain, "SOA", raise_on_no_answer=False)
        return [str(r) for r in answers]
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        return []
    except Exception:
        return []


def get_a_records(domain: str) -> List[str]:
    """Get all A records for a domain.
    
    Args:
        domain: Domain to query
        
    Returns:
        List of IPv4 addresses, empty list on error
    """
    try:
        answers = dns.resolver.resolve(domain, "A", raise_on_no_answer=False)
        return [str(r) for r in answers]
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        return []
    except Exception:
        return []


def get_aaaa_records(domain: str) -> List[str]:
    """Get all AAAA records for a domain.
    
    Args:
        domain: Domain to query
        
    Returns:
        List of IPv6 addresses, empty list on error
    """
    try:
        answers = dns.resolver.resolve(domain, "AAAA", raise_on_no_answer=False)
        return [str(r) for r in answers]
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        return []
    except Exception:
        return [] 