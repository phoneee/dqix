from __future__ import annotations
import time
import ssl
import socket
import requests
import logging
from typing import Tuple, Dict, Optional

from ..core.probes import Probe, register
from ..utils.dns import domain_variants, grade_to_score

logger = logging.getLogger(__name__)

# Default probing backend for TLSProbe
TLS_METHOD: str = "ssllabs"  # {ssllabs, sslyze, nmap}

def set_tls_method(method: str) -> None:
    """Configure which backend TLSProbe should use when computing the grade.

    Accepted values: "ssllabs" (remote API – detailed but slow),
    "sslyze" (local – fast), "nmap" (local – fast).
    """
    global TLS_METHOD
    TLS_METHOD = method.lower().strip()

@register
class TLSProbe(Probe):
    """Check TLS/SSL configuration and security."""
    
    id, weight = "tls", 0.20

    def _handshake_ok(self, dom: str) -> bool:
        """Test basic TLS handshake."""
        logger.info(f"TLS: Testing basic handshake for {dom}...")
        ctx = ssl.create_default_context()
        # socket.getaddrinfo will raise socket.gaierror if dom doesn't resolve
        addrinfo = socket.getaddrinfo(dom, 443, proto=socket.IPPROTO_TCP)
        for fam, *_ in addrinfo:
            try:
                with socket.socket(fam, socket.SOCK_STREAM) as raw:
                    raw.settimeout(6)
                    raw.connect((dom, 443))
                    with ctx.wrap_socket(raw, server_hostname=dom):
                        logger.info(f"TLS: Handshake successful for {dom}")
                        return True
            except (socket.timeout, socket.error, ssl.SSLError, ConnectionRefusedError, OSError):
                continue
            except Exception:
                continue
        logger.info(f"TLS: Handshake failed for {dom}")
        return False

    def _grade_api(self, dom: str) -> Optional[str]:
        """Get SSL Labs grade."""
        try:
            logger.info(f"TLS: Checking SSL Labs grade for {dom}...")
            p = {"host": dom, "all": "done", "fromCache": "on", "maxAge": "1"}
            js = requests.get("https://api.ssllabs.com/api/v3/analyze", params=p, timeout=10).json()
            max_retries = 18
            retries = 0
            while js.get("status") in {"DNS", "IN_PROGRESS"} and retries < max_retries:
                logger.info(f"TLS: SSL Labs scan in progress for {dom} (attempt {retries + 1}/{max_retries})...")
                time.sleep(10)
                js = requests.get("https://api.ssllabs.com/api/v3/analyze", params=p, timeout=60).json()
                retries += 1

            if js.get("status") == "READY" and js.get("endpoints"):
                grade_endpoint = next(
                    (ep for ep in js["endpoints"] if ep.get("grade") and ep.get("serverName", "").lower() == dom.lower()),
                    None,
                )
                if not grade_endpoint and js["endpoints"]:
                    grade_endpoint = next((ep for ep in js["endpoints"] if ep.get("grade")), None)
                if grade_endpoint:
                    logger.info(f"TLS: Got grade {grade_endpoint['grade']} for {dom}")
                    return grade_endpoint["grade"]
            logger.info(f"TLS: No grade available from SSL Labs for {dom}")
            return None
        except (requests.exceptions.Timeout) as e:
            logger.info(f"TLS: SSL Labs API timeout for {dom}")
            raise socket.gaierror(f"API request timed out for {dom}") from e
        except (requests.exceptions.ConnectionError):
            raise
        except (ValueError, KeyError, TypeError):
            logger.info(f"TLS: Error parsing SSL Labs response for {dom}")
            return None

    def _grade_sslyze(self, dom: str) -> Optional[str]:
        """Get grade using SSLyze."""
        try:
            logger.info(f"TLS: Running deep scan with SSLyze for {dom}...")
            from sslyze import Scanner, ServerScanRequest, ServerNetworkLocation

            req = ServerScanRequest(
                server_location=ServerNetworkLocation(dom, 443),
                scan_commands={"regular"},
            )
            scanner = Scanner()
            scanner.queue_scan(req)
            for res in scanner.get_results():
                if res.scan_status == res.ScanStatusEnum.ERROR:
                    logger.info(f"TLS: SSLyze scan error for {dom}")
                    return "F"
                tls13 = (
                    any(
                        r.tls_version.name == "TLS_1_3"
                        for r in res.scan_result.tls_1_3_cipher_suites.result.accepted_cipher_suites
                    )
                    if res.scan_result.tls_1_3_cipher_suites.result
                    else False
                )
                weak_ciphers_found = False
                if res.scan_result.tls_1_2_cipher_suites.result:
                    weak_ciphers_found = any(
                        "RC4" in c.name or "3DES" in c.name
                        for c in res.scan_result.tls_1_2_cipher_suites.result.accepted_cipher_suites
                    )
                logger.info(
                    f"TLS: SSLyze scan complete for {dom} (TLS1.3: {tls13}, weak ciphers: {weak_ciphers_found})"
                )
                return "D" if weak_ciphers_found else ("A" if tls13 else "C")
            logger.info(f"TLS: SSLyze scan failed for {dom}")
            return "F"
        except (ServerConnectivityError, ServerHostnameCouldNotBeResolved) as e:
            logger.info(f"TLS: SSLyze connectivity error for {dom}")
            raise socket.gaierror(f"SSLyze failed to connect/resolve {dom}: {e}") from e
        except ImportError:
            logger.info(f"TLS: SSLyze not available for {dom}")
            return None
        except Exception:
            logger.info(f"TLS: Unexpected SSLyze error for {dom}")
            return "F"

    def _grade_nmap(self, dom: str) -> Optional[str]:
        """Get grade using nmap."""
        try:
            import subprocess
            import re
            import shutil

            if not shutil.which("nmap"):
                logger.info("TLS: nmap not installed")
                return None

            logger.info(f"TLS: Running nmap scan for {dom}…")
            cmd = [
                "nmap",
                "--script=ssl-enum-ciphers",
                "-p",
                "443",
                "--unprivileged",
                dom,
            ]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=30, check=False)
            txt = res.stdout

            # Basic parsing
            tls_versions = set(re.findall(r"TLSv[0-9.]+", txt))
            weak = bool(re.search(r"RC4|3DES|DES\b|NULL\b|EXPORT|MD5|IDEA", txt, re.IGNORECASE))
            tls13 = any(v.startswith("TLSv1.3") for v in tls_versions)
            tls12 = any(v.startswith("TLSv1.2") for v in tls_versions)

            # Heuristic grading
            if tls13 and not weak:
                grade = "A"
            elif (tls13 or tls12) and not weak:
                grade = "B"
            elif weak:
                grade = "D"
            else:
                grade = "C"

            logger.info(f"TLS: nmap scan complete for {dom} → grade {grade}")
            return grade

        except subprocess.TimeoutExpired:
            logger.info("TLS: nmap scan timeout")
            return "F"
        except Exception:
            logger.info("TLS: nmap scan error")
            return "F"

    def run(self, original_domain: str) -> Tuple[float, Dict]:
        """Run TLS probe against domain."""
        variants = domain_variants(original_domain)
        last_resolution_error_message = f"No successful connection for {original_domain} or its variants."

        for dom_to_try in variants:
            current_details = {
                "attempted_domain": dom_to_try,
                "original_domain": original_domain,
            }
            grade = None
            try:
                # Select backend
                if TLS_METHOD == "sslyze":
                    grade = self._grade_sslyze(dom_to_try)
                elif TLS_METHOD == "nmap":
                    grade = self._grade_nmap(dom_to_try)
                else:  # default: ssllabs
                    grade = self._grade_api(dom_to_try)

                if grade is not None:
                    score_val = grade_to_score(str(grade))
                    current_details["tls_grade"] = grade
                    return score_val, current_details

                # Fallback to Basic Handshake if no grade from API/sslyze
                ok = self._handshake_ok(dom_to_try)
                score_val = 1.0 if ok else 0.0
                current_details["tls_grade"] = "local_handshake"
                current_details["tls_ok"] = ok
                return score_val, current_details

            except socket.gaierror as e:
                last_resolution_error_message = f"Resolution/connection failed for {dom_to_try}: {e}"
                continue
            except requests.exceptions.ConnectionError as e:
                err_str = str(e).lower()
                if (
                    "failed to resolve" in err_str
                    or "nodename nor servname" in err_str
                    or "dns lookup failed" in err_str
                ):
                    last_resolution_error_message = f"Requests connection (resolution) error for {dom_to_try}: {e}"
                    continue
                else:
                    current_details["tls_grade"] = "Error"
                    current_details["error"] = f"Connection error for {dom_to_try}: {e}"
                    return 0.0, current_details
            except requests.exceptions.SSLError as e:
                current_details["tls_grade"] = "Error"
                current_details["error"] = f"SSL error for {dom_to_try}: {e}"
                return 0.0, current_details
            except Exception as e_general:
                current_details["tls_grade"] = "Error"
                current_details["error"] = f"Unexpected error processing {dom_to_try}: {type(e_general).__name__} - {e_general}"
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