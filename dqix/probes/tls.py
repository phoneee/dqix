from __future__ import annotations
import ssl
import socket
import requests
from typing import Tuple, Dict, Any

from .base import Probe
from . import register
from ..utils.dns import domain_variants

# TLS probing backend selection
TLS_METHOD: str = "ssllabs"  # {ssllabs, sslyze, nmap}

def set_tls_method(method: str) -> None:
    """Configure which backend TLSProbe should use when computing the grade.
    
    Args:
        method: One of "ssllabs" (remote API – detailed but slow),
               "sslyze" (local – fast), "nmap" (local – fast)
    """
    global TLS_METHOD
    TLS_METHOD = method.lower().strip()

def _grade_to_score(grade: str) -> float:
    """Convert SSL Labs grade to a score between 0 and 1."""
    grade_map = {
        "A+": 1.0,
        "A": 0.95,
        "A-": 0.90,
        "B+": 0.85,
        "B": 0.80,
        "B-": 0.75,
        "C+": 0.70,
        "C": 0.65,
        "C-": 0.60,
        "D+": 0.55,
        "D": 0.50,
        "D-": 0.45,
        "E+": 0.40,
        "E": 0.35,
        "E-": 0.30,
        "F": 0.0,
    }
    return grade_map.get(grade.upper(), 0.0)

@register
class TLSProbe(Probe):
    """Check TLS/SSL configuration and security."""
    
    id, weight = "tls", 0.20
    
    def _handshake_ok(self, dom: str) -> bool:
        """Test basic TLS handshake."""
        self._report_progress(f"TLS: Testing basic handshake for {dom}...")
        ctx = ssl.create_default_context()
        # socket.getaddrinfo will raise socket.gaierror if dom doesn't resolve
        addrinfo = socket.getaddrinfo(dom, 443, proto=socket.IPPROTO_TCP)
        for fam, *_ in addrinfo:
            try:
                with socket.socket(fam, socket.SOCK_STREAM) as raw:
                    raw.settimeout(6)
                    raw.connect((dom, 443))
                    with ctx.wrap_socket(raw, server_hostname=dom):
                        self._report_progress(
                            f"TLS: Handshake successful for {dom}", end="\n"
                        )
                        return True
            except (
                socket.timeout,
                socket.error,
                ssl.SSLError,
                ConnectionRefusedError,
                OSError,
            ):
                continue
            except Exception:
                continue
        self._report_progress(f"TLS: Handshake failed for {dom}", end="\n")
        return False
        
    def _grade_api(self, dom: str) -> str | None:
        """Get grade from SSL Labs API."""
        try:
            self._report_progress(f"TLS: Querying SSL Labs API for {dom}...")
            r = requests.get(
                "https://api.ssllabs.com/api/v3/analyze",
                params={"host": dom, "startNew": "off", "fromCache": "on"},
                timeout=8,
            )
            r.raise_for_status()
            j = r.json()
            if j.get("status") == "READY":
                grade = j.get("endpoints", [{}])[0].get("grade", "F")
                self._report_progress(
                    f"TLS: SSL Labs grade for {dom} is {grade}", end="\n"
                )
                return grade
            self._report_progress(f"TLS: SSL Labs not ready for {dom}", end="\n")
            return None
        except (requests.RequestException, ValueError, IndexError, KeyError):
            self._report_progress(f"TLS: SSL Labs API error for {dom}", end="\n")
            return None
            
    def run(self, original_domain: str) -> Tuple[float, Dict[str, Any]]:
        """Run TLS checks against the domain.
        
        Args:
            original_domain: The domain to check
            
        Returns:
            Tuple of (score, details) where score is between 0 and 1
        """
        variants = domain_variants(original_domain)
        last_resolution_error_message = (
            f"No successful connection for {original_domain} or its variants."
        )

        for dom_to_try in variants:
            current_details = {
                "attempted_domain": dom_to_try,
                "original_domain": original_domain,
            }
            grade = None
            try:
                # Select backend
                global TLS_METHOD
                if TLS_METHOD == "sslyze":
                    grade = self._grade_sslyze(dom_to_try)
                elif TLS_METHOD == "nmap":
                    grade = self._grade_nmap(dom_to_try)
                else:  # default: ssllabs
                    grade = self._grade_api(dom_to_try)

                if grade is not None:
                    score_val = _grade_to_score(str(grade))
                    current_details["tls_grade"] = grade
                    return score_val, current_details

                # Fallback to Basic Handshake if no grade from API/sslyze
                ok = self._handshake_ok(dom_to_try)  # Can raise socket.gaierror
                score_val = 1.0 if ok else 0.0
                current_details["tls_grade"] = "local_handshake"
                current_details["tls_ok"] = ok
                return score_val, current_details

            except socket.gaierror as e:
                last_resolution_error_message = (
                    f"Resolution/connection failed for {dom_to_try}: {e}"
                )
                continue  # Try the next variant
            except requests.exceptions.ConnectionError as e:
                # Check if it's a resolution-like error from requests
                err_str = str(e).lower()
                if (
                    "failed to resolve" in err_str
                    or "nodename nor servname" in err_str
                    or "dns lookup failed" in err_str
                ):
                    last_resolution_error_message = (
                        f"Requests connection (resolution) error for {dom_to_try}: {e}"
                    )
                    continue  # Try next variant
                else:  # Other connection error
                    current_details["tls_grade"] = "Error"
                    current_details["error"] = f"Connection error for {dom_to_try}: {e}"
                    return 0.0, current_details
            except requests.exceptions.SSLError as e:
                current_details["tls_grade"] = "Error"
                current_details["error"] = f"SSL error for {dom_to_try}: {e}"
                return 0.0, current_details
            except Exception as e_general:
                current_details["tls_grade"] = "Error"
                current_details["error"] = (
                    f"Unexpected error processing {dom_to_try}: {type(e_general).__name__} - {e_general}"
                )
                return 0.0, current_details

        # If loop completes, all variants failed with resolution-like errors
        final_error_details = {
            "original_domain": original_domain,
            "attempted_variants": variants,
            "tls_grade": "Error",
            "error": "All domain variants failed DNS resolution or basic connection for TLS check.",
            "last_resolution_error": last_resolution_error_message,
        }
        return 0.0, final_error_details 