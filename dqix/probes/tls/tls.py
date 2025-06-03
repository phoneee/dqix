from __future__ import annotations
import ssl
import socket
import requests
from typing import Tuple, Dict, Any, Optional, List
from dataclasses import dataclass
from datetime import datetime, timezone

from ..base import Probe, ProbeData, ScoreCalculator
from .. import register
from dqix.utils.dns import domain_variants

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

@dataclass
class TLSData(ProbeData):
    """Data collected by TLSProbe."""
    attempted_domain: str
    original_domain: str
    tls_grade: Optional[str] = None
    tls_ok: Optional[bool] = None
    error: Optional[str] = None
    attempted_variants: Optional[List[str]] = None
    last_resolution_error: Optional[str] = None

class TLSScoreCalculator(ScoreCalculator):
    """Calculate score for TLS probe."""
    
    def _grade_to_score(self, grade: str) -> float:
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
    
    def calculate_score(self, data: TLSData) -> Tuple[float, Dict[str, Any]]:
        """Calculate score from TLS data.
        
        Args:
            data: TLS probe data
            
        Returns:
            Tuple of (score, details) where score is between 0 and 1
        """
        if data.error:
            return 0.0, {
                "original_domain": data.original_domain,
                "attempted_domain": data.attempted_domain,
                "tls_grade": "Error",
                "error": data.error
            }
            
        if data.tls_grade == "local_handshake":
            score = 1.0 if data.tls_ok else 0.0
            return score, {
                "original_domain": data.original_domain,
                "attempted_domain": data.attempted_domain,
                "tls_grade": "local_handshake",
                "tls_ok": data.tls_ok
            }
            
        if data.tls_grade:
            score = self._grade_to_score(str(data.tls_grade))
            return score, {
                "original_domain": data.original_domain,
                "attempted_domain": data.attempted_domain,
                "tls_grade": data.tls_grade
            }
            
        # If we get here, all variants failed
        return 0.0, {
            "original_domain": data.original_domain,
            "attempted_variants": data.attempted_variants,
            "tls_grade": "Error",
            "error": "All domain variants failed DNS resolution or basic connection for TLS check.",
            "last_resolution_error": data.last_resolution_error
        }

@register
class TLSProbe(Probe):
    """Check TLS/SSL configuration and security."""
    
    id, weight = "tls", 0.20
    ScoreCalculator = TLSScoreCalculator
    
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
    
    def _grade_sslyze(self, dom: str) -> Optional[str]:
        """Get grade using sslyze (placeholder)."""
        # TODO: Implement sslyze backend
        return None
    
    def _grade_nmap(self, dom: str) -> Optional[str]:
        """Get grade using nmap (placeholder)."""
        # TODO: Implement nmap backend
        return None
            
    def collect_data(self, original_domain: str) -> TLSData:
        """Collect TLS data for the domain.
        
        Args:
            original_domain: The domain to check
            
        Returns:
            TLSData containing all collected TLS information
        """
        variants = domain_variants(original_domain)
        last_resolution_error_message = (
            f"No successful connection for {original_domain} or its variants."
        )

        for dom_to_try in variants:
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
                    return TLSData(
                        attempted_domain=dom_to_try,
                        original_domain=original_domain,
                        tls_grade=grade
                    )

                # Fallback to Basic Handshake if no grade from API/sslyze
                ok = self._handshake_ok(dom_to_try)
                return TLSData(
                    attempted_domain=dom_to_try,
                    original_domain=original_domain,
                    tls_grade="local_handshake",
                    tls_ok=ok
                )

            except socket.gaierror as e:
                last_resolution_error_message = (
                    f"Resolution/connection failed for {dom_to_try}: {e}"
                )
                continue
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
                    continue
                else:  # Other connection error
                    return TLSData(
                        attempted_domain=dom_to_try,
                        original_domain=original_domain,
                        tls_grade="Error",
                        error=f"Connection error for {dom_to_try}: {e}"
                    )
            except requests.exceptions.SSLError as e:
                return TLSData(
                    attempted_domain=dom_to_try,
                    original_domain=original_domain,
                    tls_grade="Error",
                    error=f"SSL error for {dom_to_try}: {e}"
                )
            except Exception as e_general:
                return TLSData(
                    attempted_domain=dom_to_try,
                    original_domain=original_domain,
                    tls_grade="Error",
                    error=f"Unexpected error processing {dom_to_try}: {type(e_general).__name__} - {e_general}"
                )

        # If loop completes, all variants failed with resolution-like errors
        return TLSData(
            original_domain=original_domain,
            attempted_domain=original_domain,  # Use original as attempted since all failed
            attempted_variants=variants,
            tls_grade="Error",
            error="All domain variants failed DNS resolution or basic connection for TLS check.",
            last_resolution_error=last_resolution_error_message
        ) 