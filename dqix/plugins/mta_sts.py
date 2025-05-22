from __future__ import annotations  # Good practice
import dns.resolver
import dns.exception  # For specific DNS exceptions

from dqix.core import register
from dqix.core.probes import Probe  # Assuming Probe is accessible
from typing import Tuple, Dict, Any  # For type hints


class MTAstsProbe(Probe):
    id, weight = "mta_sts", 0.10  # Default weight

    def run(self, dom: str) -> Tuple[float, Dict[str, Any]]:
        mta_sts_domain = f"_mta-sts.{dom}"
        details: Dict[str, Any] = {
            "query_domain": mta_sts_domain,
            "mta_sts_record_found": False,  # Default
        }

        try:
            txt_records = dns.resolver.resolve(
                mta_sts_domain, "TXT", lifetime=5
            )  # Add a timeout

            sts_v1_policy = None
            for record in txt_records:
                record_text = record.to_text().strip().strip('"')
                if record_text.startswith("v=STSv1"):
                    sts_v1_policy = record_text  # Store the policy
                    break  # Found a valid policy

            if sts_v1_policy:
                details["mta_sts_record_found"] = True
                details["policy"] = sts_v1_policy
                return 1.0, details
            else:
                details["reason"] = "No v=STSv1 policy found in TXT records"
                return 0.0, details

        except dns.resolver.NXDOMAIN:
            details["error"] = "NXDOMAIN"
            return 0.0, details
        except dns.resolver.NoAnswer:
            details["error"] = "NoAnswer (No TXT records)"
            return 0.0, details
        except dns.exception.Timeout:
            details["error"] = "DNS query timed out"
            return 0.0, details
        except dns.exception.DNSException as e:  # Catch other DNS specific errors
            details["error"] = f"DNS error: {str(e)}"
            return 0.0, details
        except Exception as e:  # Catch any other unexpected errors
            details["error"] = f"Unexpected error: {str(e)}"
            # Consider logging this exception for debugging purposes
            return 0.0, details


register(MTAstsProbe)
