"""Async-friendly DNS helper functions for DQIX.
Currently implemented synchronously via `dnspython` but the
API is prepared for future `aiodns` refactor.
"""
from __future__ import annotations

from typing import List, Set, Any, Optional, Tuple
import dns.resolver
import dns.dnssec
import dns.rdatatype
from datetime import datetime

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


def query_records(domain: str, rdtype: str) -> List[Any]:
    """Query DNS records of specified type.
    
    Args:
        domain: Domain to query
        rdtype: Record type (A, AAAA, NS, SOA, MX, DS, DNSKEY, RRSIG, NSEC)
        
    Returns:
        List of DNS records, empty list on error
    """
    try:
        answers = dns.resolver.resolve(domain, rdtype, raise_on_no_answer=False)
        return list(answers) if answers else []
    except dns.resolver.NoAnswer:
        return []
    except Exception:
        return []


def get_dnssec_info(domain: str) -> Tuple[Optional[str], List[str], List[str], List[str], Optional[int], Optional[int], Optional[datetime]]:
    """Get DNSSEC information for a domain.
    
    Args:
        domain: Domain to check
        
    Returns:
        Tuple of (ds_record, dnskey_records, rrsig_records, nsec_records, algorithm, key_length, signature_expiry)
    """
    resolver = dns.resolver.Resolver()
    resolver.use_edns(0, dns.flags.DO)
    
    # Get DS record
    try:
        ds_records = resolver.resolve(domain, 'DS')
        ds_record = str(ds_records[0]) if ds_records else None
    except:
        ds_record = None

    # Get DNSKEY records
    try:
        dnskey_records = resolver.resolve(domain, 'DNSKEY')
        dnskey_list = [str(r) for r in dnskey_records]
        # Extract algorithm and key length from first DNSKEY
        if dnskey_list:
            parts = dnskey_list[0].split()
            algorithm = int(parts[2])
            key_length = len(parts[3]) * 4  # Base64 length to bits
        else:
            algorithm = None
            key_length = None
    except:
        dnskey_list = []
        algorithm = None
        key_length = None

    # Get RRSIG records
    try:
        rrsig_records = resolver.resolve(domain, 'RRSIG')
        rrsig_list = [str(r) for r in rrsig_records]
        # Extract signature expiry from first RRSIG
        if rrsig_list:
            parts = rrsig_list[0].split()
            expiry = datetime.strptime(parts[8], "%Y%m%d%H%M%S")
        else:
            expiry = None
    except:
        rrsig_list = []
        expiry = None

    # Get NSEC records
    try:
        nsec_records = resolver.resolve(domain, 'NSEC')
        nsec_list = [str(r) for r in nsec_records]
    except:
        nsec_list = []

    return ds_record, dnskey_list, rrsig_list, nsec_list, algorithm, key_length, expiry


def domain_variants(domain: str) -> List[str]:
    """Generate domain name variants to try.
    
    Args:
        domain: Original domain name
        
    Returns:
        List of domain variants to try
    """
    variants = [domain]
    if not domain.startswith('www.'):
        variants.append(f'www.{domain}')
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