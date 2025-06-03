from __future__ import annotations
from typing import Tuple, Dict, Any, List, Optional
from dataclasses import dataclass
import requests

from ..base import Probe, ProbeData, ScoreCalculator
from .. import register
from dqix.utils.dns import get_dnssec_info, domain_variants, query_records

# Google's DNS-over-HTTPS endpoint
GOOGLE_DOH = "https://dns.google/resolve"
CLOUDFLARE_DOH = "https://cloudflare-dns.com/dns-query"

@dataclass
class DNSSECData(ProbeData):
    """Data collected by DNSSECProbe."""
    domain: str
    status: int
    ad_flag: bool
    ds_record: Optional[str] = None
    dnskey_records: List[str] = None
    rrsig_records: List[str] = None
    nsec_records: List[str] = None
    algorithm: Optional[int] = None
    key_length: Optional[int] = None
    signature_expiry: Optional[datetime] = None
    cloudflare_status: Optional[int] = None
    cloudflare_ad_flag: Optional[bool] = None
    error: Optional[str] = None

class DNSSECScoreCalculator(ScoreCalculator):
    """Calculate score for DNSSEC probe."""
    
    def calculate_score(self, data: DNSSECData) -> Tuple[float, Dict[str, Any]]:
        """Calculate score from DNSSEC data.
        
        Scoring logic (0-1):
        - Basic DNSSEC enabled (0.25)
        - Chain of trust validated (0.25)
        - Multiple resolver validation (0.25)
        - Modern algorithm & key length (0.25)
        """
        if data.error:
            return 0.0, {
                "dnssec_status": -1,
                "ad_flag": False,
                "error": data.error
            }
            
        score = 0.0
        details = {
            "dnssec_status": data.status,
            "ad_flag": data.ad_flag,
            "ds_record": data.ds_record,
            "algorithm": data.algorithm,
            "key_length": data.key_length,
            "signature_expiry": data.signature_expiry.isoformat() if data.signature_expiry else None,
            "cloudflare_status": data.cloudflare_status,
            "cloudflare_ad_flag": data.cloudflare_ad_flag
        }

        # Basic DNSSEC enabled
        if data.ds_record and data.dnskey_records and data.rrsig_records:
            score += 0.25
            details["basic_dnssec"] = True
        else:
            details["basic_dnssec"] = False

        # Chain of trust validated
        if data.status == 0 and data.ad_flag:
            score += 0.25
            details["chain_valid"] = True
        else:
            details["chain_valid"] = False

        # Multiple resolver validation
        if data.cloudflare_status == 0 and data.cloudflare_ad_flag:
            score += 0.25
            details["multi_resolver"] = True
        else:
            details["multi_resolver"] = False

        # Modern algorithm & key length
        if data.algorithm in [13, 14] and data.key_length >= 256:
            score += 0.25
            details["modern_crypto"] = True
        else:
            details["modern_crypto"] = False

        return score, details

@register
class DNSSECProbe(Probe):
    """Check DNSSEC validation status using multiple resolvers."""
    
    id, weight = "dnssec", 0.20
    ScoreCalculator = DNSSECScoreCalculator
    
    def collect_data(self, domain: str) -> DNSSECData:
        """Collect DNSSEC validation data for the domain.
        
        Args:
            domain: The domain to check
            
        Returns:
            DNSSECData containing validation status
        """
        try:
            self._report_progress(f"DNSSEC: Checking validation status for {domain}...")
            
            # Check with Google DoH
            google_response = requests.get(
                GOOGLE_DOH, 
                params={"name": domain, "type": "A", "do": "1"}, 
                timeout=8
            ).json()
            
            # Check with Cloudflare DoH
            cloudflare_response = requests.get(
                CLOUDFLARE_DOH,
                params={"name": domain, "type": "A", "do": "1"},
                timeout=8
            ).json()

            # Get DNSSEC records using shared utility
            ds_record, dnskey_list, rrsig_list, nsec_list, algorithm, key_length, expiry = get_dnssec_info(domain)
            
            self._report_progress(
                f"DNSSEC: {'Validated' if google_response.get('Status') == 0 and google_response.get('AD', False) else 'Not validated'} for {domain}",
                end="\n",
            )
            
            return DNSSECData(
                domain=domain,
                status=google_response.get("Status", -1),
                ad_flag=google_response.get("AD", False),
                ds_record=ds_record,
                dnskey_records=dnskey_list,
                rrsig_records=rrsig_list,
                nsec_records=nsec_list,
                algorithm=algorithm,
                key_length=key_length,
                signature_expiry=expiry,
                cloudflare_status=cloudflare_response.get("Status", -1),
                cloudflare_ad_flag=cloudflare_response.get("AD", False)
            )
            
        except Exception as e:
            self._report_progress(f"DNSSEC: Check failed for {domain}", end="\n")
            return DNSSECData(
                domain=domain,
                status=-1,
                ad_flag=False,
                error=str(e)
            ) 