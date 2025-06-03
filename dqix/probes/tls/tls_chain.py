from __future__ import annotations
from typing import Tuple, Dict, Any, List, Optional
from dataclasses import dataclass
import ssl
import socket
from datetime import datetime, timezone
import certifi

try:
    import OpenSSL.crypto
    HAS_OPENSSL = True
except ImportError:
    HAS_OPENSSL = False

from ..base import Probe, ProbeData, ScoreCalculator
from .. import register
from dqix.utils.dns import domain_variants

@dataclass
class TLSChainData(ProbeData):
    """Data collected by TLSChainProbe."""
    domain: str
    chain_length: int
    root_trusted: bool
    intermediates_trusted: bool
    expiry_dates: List[datetime]
    issuer_orgs: List[str]
    error: Optional[str] = None

class TLSChainScoreCalculator(ScoreCalculator):
    """Calculate score for TLS chain probe."""
    
    def calculate_score(self, data: TLSChainData) -> Tuple[float, Dict[str, Any]]:
        """Calculate score from TLS chain data.
        
        Scoring logic (0–1):
            • Chain length ≥ 2 (0.25)
            • Root CA trusted (0.25)
            • All intermediates trusted (0.25)
            • No expired certificates (0.25)
        """
        if data.error:
            return 0.0, {"error": data.error}
            
        score = 0.0
        details = {}
        
        # Check chain length
        if data.chain_length >= 2:
            score += 0.25
            details["chain_length"] = "sufficient"
        else:
            details["chain_length"] = "insufficient"
            
        # Check root trust
        if data.root_trusted:
            score += 0.25
            details["root_trusted"] = True
        else:
            details["root_trusted"] = False
            
        # Check intermediate trust
        if data.intermediates_trusted:
            score += 0.25
            details["intermediates_trusted"] = True
        else:
            details["intermediates_trusted"] = False
            
        # Check expiry dates
        now = datetime.now()
        expired = any(exp < now for exp in data.expiry_dates)
        if not expired:
            score += 0.25
            details["cert_expiry"] = "valid"
        else:
            details["cert_expiry"] = "expired"
            
        details["issuers"] = data.issuer_orgs
        details["expiry_dates"] = [d.isoformat() for d in data.expiry_dates]
        
        return round(score, 2), details

@register
class TLSChainProbe(Probe):
    """Check TLS certificate chain validation."""
    
    id, weight = "tls_chain", 0.15
    ScoreCalculator = TLSChainScoreCalculator
    
    def _get_cert_chain(self, domain: str) -> Tuple[List[Any], Optional[str]]:
        """Get certificate chain for domain."""
        if not HAS_OPENSSL:
            return [], "OpenSSL module not available"
            
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                    chain = ssock.getpeercert(binary_form=True)
                    if not chain:
                        return [], "No certificate chain"
                        
                    # Convert to OpenSSL certs
                    certs = []
                    for cert in chain:
                        x509 = OpenSSL.crypto.load_certificate(
                            OpenSSL.crypto.FILETYPE_ASN1, cert
                        )
                        certs.append(x509)
                    return certs, None
                    
        except Exception as e:
            return [], str(e)
            
    def _verify_chain(self, certs: List[Any]) -> Tuple[bool, bool]:
        """Verify certificate chain trust."""
        if not HAS_OPENSSL:
            return False, False
            
        if not certs:
            return False, False
            
        # Check root trust
        root = certs[-1]
        root_trusted = False
        try:
            store = OpenSSL.crypto.X509Store()
            store.load_locations(None, "/etc/ssl/certs")
            store_ctx = OpenSSL.crypto.X509StoreContext(store, root)
            store_ctx.verify_certificate()
            root_trusted = True
        except:
            pass
            
        # Check intermediate trust
        intermediates_trusted = True
        for cert in certs[:-1]:
            try:
                store = OpenSSL.crypto.X509Store()
                store.load_locations(None, "/etc/ssl/certs")
                store_ctx = OpenSSL.crypto.X509StoreContext(store, cert)
                store_ctx.verify_certificate()
            except:
                intermediates_trusted = False
                break
                
        return root_trusted, intermediates_trusted
        
    def collect_data(self, domain: str) -> TLSChainData:
        """Collect TLS chain data for the domain.
        
        Args:
            domain: The domain to check
            
        Returns:
            TLSChainData containing chain validation results
        """
        if not HAS_OPENSSL:
            return TLSChainData(
                domain=domain,
                chain_length=0,
                root_trusted=False,
                intermediates_trusted=False,
                expiry_dates=[],
                issuer_orgs=[],
                error="OpenSSL module not available"
            )
            
        try:
            self._report_progress(f"TLS Chain: Checking certificate chain for {domain}...")
            
            # Get certificate chain
            certs, err = self._get_cert_chain(domain)
            if err:
                return TLSChainData(
                    domain=domain,
                    chain_length=0,
                    root_trusted=False,
                    intermediates_trusted=False,
                    expiry_dates=[],
                    issuer_orgs=[],
                    error=err
                )
                
            # Verify chain
            root_trusted, intermediates_trusted = self._verify_chain(certs)
            
            # Extract details
            expiry_dates = []
            issuer_orgs = []
            for cert in certs:
                expiry = datetime.strptime(
                    cert.get_notAfter().decode(), "%Y%m%d%H%M%SZ"
                )
                expiry_dates.append(expiry)
                
                issuer = cert.get_issuer()
                org = issuer.get_attributes_by_nid(
                    OpenSSL.crypto.NID_organizationName
                )
                issuer_orgs.append(org[0].value if org else "Unknown")
                
            return TLSChainData(
                domain=domain,
                chain_length=len(certs),
                root_trusted=root_trusted,
                intermediates_trusted=intermediates_trusted,
                expiry_dates=expiry_dates,
                issuer_orgs=issuer_orgs
            )
            
        except Exception as e:
            return TLSChainData(
                domain=domain,
                chain_length=0,
                root_trusted=False,
                intermediates_trusted=False,
                expiry_dates=[],
                issuer_orgs=[],
                error=str(e)
            ) 