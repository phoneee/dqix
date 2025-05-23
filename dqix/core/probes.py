from __future__ import annotations
import time
import ssl
import socket
import requests
import re
import dns.resolver
import whois
from typing import Tuple, List, Dict  # Added List, Dict
from dqix.core import register
from bs4 import BeautifulSoup

# Import sslyze errors if DQIX_TLS_DEEP is used
try:
    from sslyze.errors import ServerConnectivityError, ServerHostnameCouldNotBeResolved
except ImportError:
    # Mock them if sslyze is not installed, so type hints and except blocks don't break
    class ServerConnectivityError(Exception):
        pass

    class ServerHostnameCouldNotBeResolved(Exception):
        pass


SSL_API = "https://api.ssllabs.com/api/v3/analyze"
GOOGLE_DOH = "https://dns.google/resolve"

# Refined Regexes
SPF_RE = re.compile(r"^v=spf1", re.I)
DMARC_POLICY_RE = re.compile(r"v\s*=\s*DMARC1\s*;\s*p\s*=\s*(\w+)", re.I)


# ---------------------------------------------------------------------------
# TLS probing backend selection
# ---------------------------------------------------------------------------

# Default probing backend for TLSProbe.  "ssllabs" keeps previous behaviour.
TLS_METHOD: str = "ssllabs"  # {ssllabs, sslyze, nmap}


def set_tls_method(method: str):
    """Configure which backend TLSProbe should use when computing the grade.

    Accepted values: "ssllabs" (remote API – detailed but slow),
    "sslyze" (local – fast), "nmap" (local – fast).
    """

    global TLS_METHOD
    TLS_METHOD = method.lower().strip()


# ---------------------------------------------------------------------------
# Verbosity and colour helpers
# ---------------------------------------------------------------------------
VERBOSE_LEVEL: int = 0  # 0 = silent, 1 = -v, 2 = --debug


def set_verbosity_level(level: int):
    global VERBOSE_LEVEL
    VERBOSE_LEVEL = max(0, min(level, 2))


# ANSI colour support (falls back gracefully)
try:
    from colorama import Fore, Style, init as _colorama_init

    _colorama_init()

    _CLR_INFO = Fore.CYAN
    _CLR_RESET = Style.RESET_ALL
except ImportError:  # pragma: no cover – optional dependency
    _CLR_INFO = ""
    _CLR_RESET = ""


# Helper function to get domain variants (original, www, non-www)
def _get_domain_variants(domain: str) -> List[str]:
    """Return possible host variants (original, with and without `www.`)."""
    domain = domain.strip().lower()
    variants: List[str] = [domain]

    if domain.startswith("www."):
        # Already has www – add bare domain as alternative.
        bare = domain[4:]
        if bare:
            variants.append(bare)
    else:
        # Add www. sub-domain when domain looks like a hostname (contains a dot and longer than 3 chars)
        if len(domain) > 3 and "." in domain:
            variants.append(f"www.{domain}")

    # Deduplicate while preserving order
    return list(dict.fromkeys(variants))


# Helper function to fetch TXT records
def _get_txt_records(name: str) -> List[str]:
    try:
        resolver = dns.resolver.Resolver()
        return [rdata.to_text().strip('"') for rdata in resolver.resolve(name, "TXT")]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
        return []
    except Exception:
        return []


# Helper function to parse DMARC records comprehensively
def _parse_dmarc_tags(dmarc_string: str) -> Dict[str, str]:
    tags = {}
    if dmarc_string.lower().startswith("v=dmarc1"):
        for part in dmarc_string.split(";"):
            part = part.strip()
            if "=" in part:
                key, value = part.split("=", 1)
                tags[key.strip().lower()] = value.strip().lower()
    return tags


class Probe:
    id: str
    weight: float

    @staticmethod
    def _report_progress(msg: str, level: int = 1, end: str = "\r"):
        """Print progress message respecting global verbosity.

        Args:
            msg: message to print
            level: 1 for verbose, 2 for debug. 0 always suppressed.
            end: end param for print
        """
        if VERBOSE_LEVEL >= level:
            print(f"\033[K{_CLR_INFO}{msg}{_CLR_RESET}", end=end)

    def run(self, domain: str) -> Tuple[float, dict]: ...


# ────────── TLS ────────────────────────────────────────────────────────────
@register
class TLSProbe(Probe):
    id, weight = "tls", 0.20

    def _handshake_ok(self, dom):
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

    def _grade_api(self, dom):
        try:
            self._report_progress(f"TLS: Checking SSL Labs grade for {dom}...")
            p = {"host": dom, "all": "done", "fromCache": "on", "maxAge": "1"}
            # This can raise requests.exceptions.ConnectionError (e.g., DNS failure), Timeout
            js = requests.get(SSL_API, params=p, timeout=10).json()
            max_retries = 18
            retries = 0
            while js.get("status") in {"DNS", "IN_PROGRESS"} and retries < max_retries:
                self._report_progress(
                    f"TLS: SSL Labs scan in progress for {dom} (attempt {retries + 1}/{max_retries})..."
                )
                time.sleep(10)
                # This can also raise requests.exceptions.ConnectionError, Timeout
                js = requests.get(SSL_API, params=p, timeout=60).json()
                retries += 1

            if js.get("status") == "READY" and js.get("endpoints"):
                grade_endpoint = next(
                    (
                        ep
                        for ep in js["endpoints"]
                        if ep.get("grade")
                        and ep.get("serverName", "").lower() == dom.lower()
                    ),
                    None,
                )
                if not grade_endpoint and js["endpoints"]:
                    grade_endpoint = next(
                        (ep for ep in js["endpoints"] if ep.get("grade")), None
                    )
                if grade_endpoint:
                    self._report_progress(
                        f"TLS: Got grade {grade_endpoint['grade']} for {dom}", end="\n"
                    )
                    return grade_endpoint["grade"]
            self._report_progress(
                f"TLS: No grade available from SSL Labs for {dom}", end="\n"
            )
            return None
        except (
            requests.exceptions.Timeout
        ) as e:  # More specific: Timeout is a connectivity issue
            self._report_progress(f"TLS: SSL Labs API timeout for {dom}", end="\n")
            raise socket.gaierror(
                f"API request timed out for {dom}"
            ) from e  # Treat as resolution/connectivity issue
        except (
            requests.exceptions.ConnectionError
        ):  # Raised for DNS failure by requests
            raise  # Re-raise for the main run method to catch and decide on variants
        except (
            ValueError,
            KeyError,
            TypeError,
        ):  # JSON parsing or unexpected structure
            self._report_progress(
                f"TLS: Error parsing SSL Labs response for {dom}", end="\n"
            )
            return None  # API failed, but not a connection issue for *this* variant.

    def _grade_sslyze(self, dom):
        try:
            self._report_progress(f"TLS: Running deep scan with SSLyze for {dom}...")
            from sslyze import Scanner, ServerScanRequest, ServerNetworkLocation

            req = ServerScanRequest(
                server_location=ServerNetworkLocation(dom, 443),
                scan_commands={"regular"},
            )
            scanner = Scanner()
            scanner.queue_scan(req)
            for res in scanner.get_results():
                if res.scan_status == res.ScanStatusEnum.ERROR:
                    self._report_progress(f"TLS: SSLyze scan error for {dom}", end="\n")
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
                self._report_progress(
                    f"TLS: SSLyze scan complete for {dom} (TLS1.3: {tls13}, weak ciphers: {weak_ciphers_found})",
                    end="\n",
                )
                return "D" if weak_ciphers_found else ("A" if tls13 else "C")
            self._report_progress(f"TLS: SSLyze scan failed for {dom}", end="\n")
            return "F"
        except (ServerConnectivityError, ServerHostnameCouldNotBeResolved) as e:
            # Re-raise as a gaierror so the main run loop can try the next variant
            self._report_progress(f"TLS: SSLyze connectivity error for {dom}", end="\n")
            raise socket.gaierror(f"SSLyze failed to connect/resolve {dom}: {e}") from e
        except ImportError:
            self._report_progress(f"TLS: SSLyze not available for {dom}", end="\n")
            return None  # sslyze not available
        except Exception:
            self._report_progress(f"TLS: Unexpected SSLyze error for {dom}", end="\n")
            return "F"  # Default to F for other sslyze errors

    def run(self, original_domain: str) -> Tuple[float, dict]:
        variants = _get_domain_variants(original_domain)
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
                # -------------------- select backend --------------------
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
            except requests.exceptions.ConnectionError as e:  # From _grade_api
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
                else:  # Other connection error (e.g., server down, connection refused after resolution)
                    current_details["tls_grade"] = "Error"
                    current_details["error"] = f"Connection error for {dom_to_try}: {e}"
                    return 0.0, current_details
            except (
                requests.exceptions.SSLError
            ) as e:  # E.g. if www variant resolves but has SSL issue
                current_details["tls_grade"] = "Error"
                current_details["error"] = f"SSL error for {dom_to_try}: {e}"
                return (
                    0.0,
                    current_details,
                )  # Stop, SSL issue is specific to this variant
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

    # Backwards-compat alias for tests (test_tls patches _grade_from_sslyze)
    _grade_from_sslyze = _grade_sslyze

    # ---------------------- nmap backend ---------------------------

    def _grade_nmap(self, dom):
        """Quick TLS grade using nmap's ssl-enum-ciphers script.

        Returns a letter grade (A-F) or None if nmap not available.
        The heuristic is intentionally simple – sufficient for relative scoring
        and avoids the latency of SSL Labs.
        """

        try:
            import subprocess
            import re
            import shutil

            if not shutil.which("nmap"):
                self._report_progress("TLS: nmap not installed", end="\n")
                return None

            self._report_progress(f"TLS: Running nmap scan for {dom}…")
            cmd = [
                "nmap",
                "--script=ssl-enum-ciphers",
                "-p",
                "443",
                "--unprivileged",  # avoid root requirement where possible
                dom,
            ]
            res = subprocess.run(
                cmd, capture_output=True, text=True, timeout=30, check=False
            )
            txt = res.stdout

            # Basic parsing
            tls_versions = set(re.findall(r"TLSv[0-9.]+", txt))
            weak = bool(
                re.search(
                    r"RC4|3DES|DES\b|NULL\b|EXPORT|MD5|IDEA", txt, re.IGNORECASE
                )
            )
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

            self._report_progress(
                f"TLS: nmap scan complete for {dom} → grade {grade}", end="\n"
            )
            return grade

        except subprocess.TimeoutExpired:
            self._report_progress("TLS: nmap scan timeout", end="\n")
            return "F"
        except Exception:
            # Any unforeseen error defaults to failure grade (F) but we keep flow.
            self._report_progress("TLS: nmap scan error", end="\n")
            return "F"


# ────────── DNS Basic ───────────────────────────────────────────────────────
@register
class DNSBasicProbe(Probe):
    """Validate presence of essential DNS records.

    Scoring logic (0–1):
        • A/AAAA present (0.25)
        • ≥2 NS records (0.25)
        • SOA present (0.25)
        • MX present (0.25) – if none, partial credit 0.10 (domain may be web-only)
    """

    id, weight = "dns_basic", 0.05

    def run(self, original_domain: str):
        from dqix.utils.dns import domain_variants
        import dns.resolver

        variants = domain_variants(original_domain)
        last_err = None

        for dom in variants:
            try:
                self._report_progress(f"DNSBasic: querying records for {dom}…")

                a_ok = bool(self._query_any(dom, "A") or self._query_any(dom, "AAAA"))
                ns_records = self._query_any(dom, "NS")
                ns_ok = len(ns_records) >= 2
                soa_ok = bool(self._query_any(dom, "SOA"))
                mx_records = self._query_any(dom, "MX")
                mx_ok = bool(mx_records)

                score = 0.0
                score += 0.25 if a_ok else 0.0
                score += 0.25 if ns_ok else 0.0
                score += 0.25 if soa_ok else 0.0
                score += 0.25 if mx_ok else 0.10  # partial credit

                details = {
                    "a_present": a_ok,
                    "ns_count": len(ns_records),
                    "soa_present": soa_ok,
                    "mx_present": mx_ok,
                }

                return round(score, 2), details
            except Exception as e:
                last_err = str(e)
                continue

        return 0.0, {"error": last_err or "DNS query failed"}

    # ------------------------------------------------------------------

    def _query_any(self, domain: str, rdtype: str):
        import dns.resolver

        try:
            answers = dns.resolver.resolve(domain, rdtype, raise_on_no_answer=False)
            return list(answers) if answers else []
        except dns.resolver.NoAnswer:
            return []
        except Exception:
            return []


# ────────── DKIM ─────────────────────────────────────────────────────────────
@register
class DKIMProbe(Probe):
    """Check for DKIM TXT records for common selectors."""
    id, weight = "dkim", 0.03

    COMMON_SELECTORS = ["default", "selector1", "google", "mail", "smtp", "dkim"]

    def run(self, original_domain: str):
        from dqix.utils.dns import get_txt_records
        selectors = self.COMMON_SELECTORS
        found = False
        found_selector = None
        for sel in selectors:
            name = f"{sel}._domainkey.{original_domain}"
            txts = get_txt_records(name)
            for t in txts:
                if t.lower().startswith("v=dkim1"):
                    found = True
                    found_selector = sel
                    break
            if found:
                break
        score = 1.0 if found else 0.0
        return score, {"dkim_found": found, "selector": found_selector}


# Re-export migrated CAAProbe (now in dqix.probes.caa) for backward compatibility
from dqix.probes.caa import CAAProbe  # noqa: F401

# ────────── Accessibility (HTML) ─────────────────────────────────────────────
@register
class AccessibilityProbe(Probe):
    """Check for basic HTML accessibility: <title>, <img alt>, <label for>."""
    id, weight = "accessibility", 0.08

    def run(self, original_domain: str):
        url = f"https://{original_domain}"
        try:
            resp = requests.get(url, timeout=8)
            html = resp.text
        except Exception as e:
            return 0.0, {"error": f"Failed to fetch HTML: {e}"}

        soup = BeautifulSoup(html, "html.parser")

        # 1. <title>
        has_title = bool(soup.title and soup.title.string and soup.title.string.strip())

        # 2. <img alt>
        imgs = soup.find_all("img")
        img_missing_alt = [img for img in imgs if not img.has_attr("alt") or img["alt"] == None]
        img_empty_alt = [img for img in imgs if img.has_attr("alt") and img["alt"] == ""]
        img_with_alt = [img for img in imgs if img.has_attr("alt") and img["alt"]]

        # 3. <label for>
        labels = soup.find_all("label")
        label_for = {lbl.get("for") for lbl in labels if lbl.get("for")}
        inputs = soup.find_all(["input", "select", "textarea"])
        input_ids = {inp.get("id") for inp in inputs if inp.get("id")}
        inputs_without_label = [inp for inp in inputs if inp.get("id") and inp.get("id") not in label_for]

        # Score: 0.4 for title, 0.3 for all img alt, 0.3 for all input label
        score = 0.0
        if has_title:
            score += 0.4
        if imgs:
            if not img_missing_alt:
                score += 0.3
        else:
            score += 0.3  # No images, no penalty
        if inputs:
            if not inputs_without_label:
                score += 0.3
        else:
            score += 0.3  # No inputs, no penalty

        details = {
            "has_title": has_title,
            "img_count": len(imgs),
            "img_missing_alt": len(img_missing_alt),
            "img_empty_alt": len(img_empty_alt),
            "input_count": len(inputs),
            "inputs_without_label": len(inputs_without_label),
        }
        return round(score, 2), details


# ────────── Cookie Policy ────────────────────────────────────────────────────
@register
class CookieProbe(Probe):
    """Check for Set-Cookie, Secure/HttpOnly/SameSite, and cookie banner/privacy link."""
    id, weight = "cookie", 0.04

    def run(self, original_domain: str):
        url = f"https://{original_domain}"
        try:
            resp = requests.get(url, timeout=8)
            html = resp.text
            cookies = resp.cookies
            set_cookie_headers = resp.headers.get("Set-Cookie", "")
        except Exception as e:
            return 0.0, {"error": f"Failed to fetch: {e}"}

        # 1. Check Set-Cookie headers
        has_cookie = bool(set_cookie_headers)
        secure = "Secure" in set_cookie_headers
        httponly = "HttpOnly" in set_cookie_headers
        samesite = "SameSite" in set_cookie_headers

        # 2. Check for cookie banner or privacy link in HTML
        soup = BeautifulSoup(html, "html.parser")
        banner_keywords = ["cookie", "consent", "gdpr", "privacy"]
        banner_found = False
        for tag in soup.find_all(["div", "section", "footer", "a", "span"]):
            text = (tag.get_text() or "").lower()
            if any(kw in text for kw in banner_keywords):
                banner_found = True
                break

        # Score: 0.4 for Secure+HttpOnly+SameSite, 0.3 for banner, 0.3 for Set-Cookie present
        score = 0.0
        if has_cookie:
            score += 0.3
        if secure and httponly and samesite:
            score += 0.4
        if banner_found:
            score += 0.3

        details = {
            "has_cookie": has_cookie,
            "secure": secure,
            "httponly": httponly,
            "samesite": samesite,
            "banner_found": banner_found,
        }
        return round(score, 2), details


# ────────── WCAG/Usability ──────────────────────────────────────────────────
@register
class WCAGUsabilityProbe(Probe):
    """Check for font-size, viewport meta, skip link, and descriptive link text."""
    id, weight = "wcag_usability", 0.05

    def run(self, original_domain: str):
        url = f"https://{original_domain}"
        try:
            resp = requests.get(url, timeout=8)
            html = resp.text
        except Exception as e:
            return 0.0, {"error": f"Failed to fetch HTML: {e}"}

        soup = BeautifulSoup(html, "html.parser")

        # 1. Font size (at least one style >= 16px or 1em)
        font_ok = False
        for tag in soup.find_all(style=True):
            style = tag["style"].lower()
            if "font-size" in style:
                if any(sz in style for sz in ["16px", "1em", "larger", "large"]):
                    font_ok = True
                    break
        # Also check for <body style="font-size:...">
        body = soup.body
        if body and body.has_attr("style") and not font_ok:
            style = body["style"].lower()
            if "font-size" in style and any(sz in style for sz in ["16px", "1em", "larger", "large"]):
                font_ok = True

        # 2. Viewport meta tag
        viewport_ok = bool(soup.find("meta", attrs={"name": "viewport"}))

        # 3. Skip link (a[href^="#"] near top)
        skip_ok = False
        for a in soup.find_all("a", href=True):
            if a["href"].startswith("#") and ("skip" in (a.get_text() or "").lower() or "main" in a["href"].lower()):
                skip_ok = True
                break

        # 4. Descriptive link text (no "click here", "read more", etc. as only text)
        bad_link_texts = {"click here", "read more", "more", "here"}
        links = soup.find_all("a", href=True)
        # Strict: all links must be descriptive
        link_text_ok = all(
            a.get_text().strip().lower() not in bad_link_texts and len(a.get_text().strip()) > 3
            for a in links
        ) if links else True

        # Score: 0.25 font, 0.25 viewport, 0.25 skip, 0.25 link text
        score = 0.0
        if font_ok:
            score += 0.25
        if viewport_ok:
            score += 0.25
        if skip_ok:
            score += 0.25
        if link_text_ok:
            score += 0.25

        details = {
            "font_ok": font_ok,
            "viewport_ok": viewport_ok,
            "skip_ok": skip_ok,
            "link_text_ok": link_text_ok,
            "link_count": len(links),
        }
        return round(score, 2), details


# ────────── DNSSEC ─────────────────────────────────────────────────────────
@register
class DNSSECProbe(Probe):
    id, weight = "dnssec", 0.20

    def run(self, dom):  # Stays with original domain
        try:
            self._report_progress(f"DNSSEC: Checking validation status for {dom}...")
            # Use Google DoH for now, but could use utils.dns in future
            j = requests.get(
                GOOGLE_DOH, params={"name": dom, "type": "A", "do": "1"}, timeout=8
            ).json()
            score = 1.0 if j.get("Status") == 0 and j.get("AD", False) else 0.0
            self._report_progress(
                f"DNSSEC: {'Validated' if score == 1.0 else 'Not validated'} for {dom}",
                end="\n",
            )
            return score, {
                "dnssec_status": j.get("Status"),
                "ad_flag": j.get("AD", False),
            }
        except (requests.RequestException, ValueError):
            self._report_progress(f"DNSSEC: Check failed for {dom}", end="\n")
            return 0.0, {
                "dnssec_status": -1,
                "ad_flag": False,
                "error": "Request or JSON parse failed",
            }


# ────────── HTTP headers ───────────────────────────────────────────────────
@register
class HeaderProbe(Probe):
    id, weight = "headers", 0.10

    def run(self, original_domain: str) -> Tuple[float, dict]:
        from dqix.utils.dns import domain_variants
        variants = domain_variants(original_domain)
        self._report_progress(
            f"Headers: Will check variants {', '.join(variants)} for {original_domain}..."
        )
        last_resolution_error_message = (
            f"No successful connection for {original_domain} or its variants."
        )

        for dom_to_try in variants:
            self._report_progress(f"Headers: Testing HTTPS headers for {dom_to_try}...")
            current_details = {
                "attempted_domain": dom_to_try,
                "original_domain": original_domain,
            }
            try:
                headers_config = {"User-Agent": "DQIX Probe/1.0"}
                r = requests.get(
                    f"https://{dom_to_try}",
                    timeout=8,
                    allow_redirects=True,
                    headers=headers_config,
                )

                # FakeResponse in tests has no raise_for_status / status_code, so guard the calls.
                if hasattr(r, "raise_for_status"):
                    r.raise_for_status()  # Raise HTTPError for 4xx/5xx responses

                h = {k.lower(): v for k, v in r.headers.items()}
                hsts = "strict-transport-security" in h
                csp = (
                    "content-security-policy" in h
                    or "content-security-policy-report-only" in h
                )

                score = 0.0
                if hsts:
                    score += 0.5
                if csp:
                    score += 0.5

                self._report_progress(
                    f"Headers: Found HSTS={hsts}, CSP={csp} for {dom_to_try}", end="\n"
                )
                current_details.update(
                    {
                        "hsts": hsts,
                        "csp": csp,
                        "status_code": getattr(r, "status_code", None),
                    }
                )
                return score, current_details

            except requests.exceptions.HTTPError as e:
                self._report_progress(
                    f"Headers: HTTP error {e.response.status_code if e.response else 'unknown'} for {dom_to_try}",
                    end="\n",
                )
                current_details["error"] = f"HTTP error for {dom_to_try}: {e}"
                current_details["status_code"] = (
                    e.response.status_code if e.response else None
                )
                return 0.0, current_details  # Stop, server reachable but erroring
            except requests.exceptions.SSLError as e:
                self._report_progress(f"Headers: SSL error for {dom_to_try}", end="\n")
                current_details["error"] = f"SSL error for {dom_to_try}: {e}"
                return 0.0, current_details  # Stop, SSL issue specific to this variant
            except requests.exceptions.Timeout as e:
                self._report_progress(f"Headers: Request timed out for {dom_to_try}")
                last_resolution_error_message = (
                    f"Request timed out for {dom_to_try}: {e}"
                )
                continue  # Try next variant
            except requests.exceptions.ConnectionError as e:
                err_str = str(e).lower()
                # More robust check for gaierror wrapped by requests
                is_gaierror_like = False
                if isinstance(e.args[0], socket.gaierror) or (
                    e.args
                    and e.args[0]
                    and "NewConnectionError" in type(e.args[0]).__name__
                    and "[errno 8]" in str(e.args[0]).lower()
                ):
                    is_gaierror_like = True

                if (
                    "failed to resolve" in err_str
                    or "nodename nor servname" in err_str
                    or "dns lookup failed" in err_str
                    or is_gaierror_like
                ):
                    self._report_progress(
                        f"Headers: DNS resolution failed for {dom_to_try}"
                    )
                    last_resolution_error_message = (
                        f"Connection (resolution) error for {dom_to_try}: {e}"
                    )
                    continue  # Try next variant
                else:
                    self._report_progress(
                        f"Headers: Connection error for {dom_to_try}", end="\n"
                    )
                    current_details["error"] = f"Connection error for {dom_to_try}: {e}"
                    return 0.0, current_details  # Stop, non-resolution connection error
            except Exception as e_general:
                self._report_progress(
                    f"Headers: Unexpected error for {dom_to_try}", end="\n"
                )
                current_details["error"] = (
                    f"Unexpected error processing {dom_to_try}: {type(e_general).__name__} - {e_general}"
                )
                return 0.0, current_details

        self._report_progress(
            f"Headers: All variants failed for {original_domain}", end="\n"
        )
        final_error_details = {
            "original_domain": original_domain,
            "attempted_variants": variants,
            "error": "All domain variants failed DNS resolution or basic connection for HTTP headers check.",
            "last_resolution_error": last_resolution_error_message,
        }
        return 0.0, final_error_details


# ────────── Mail (SPF/DMARC) ───────────────────────────────────────────────
@register
class MailProbe(Probe):
    id, weight = "mail", 0.15

    def run(self, dom):  # Stays with original domain
        from dqix.utils.dns import get_txt_records
        self._report_progress(f"Mail: Checking SPF record for {dom}...")
        spf_record_present = any(
            SPF_RE.match(t if isinstance(t, str) else str(t)) for t in get_txt_records(dom)
        )
        self._report_progress(
            f"Mail: SPF {'found' if spf_record_present else 'not found'} for {dom}"
        )

        self._report_progress(f"Mail: Checking DMARC record for {dom}...")
        dmarc_policy = None
        dmarc_record_text = ""
        dmarc_records = get_txt_records(f"_dmarc.{dom}")
        if dmarc_records:
            first_rec = dmarc_records[0]
            dmarc_record_text = (
                first_rec if isinstance(first_rec, str) else str(first_rec)
            )
            m = DMARC_POLICY_RE.search(dmarc_record_text)
            if m:
                dmarc_policy = m.group(1).lower()
        self._report_progress(
            f"Mail: DMARC policy is '{dmarc_policy or 'none'}' for {dom}", end="\n"
        )

        score = 0.0
        if spf_record_present:
            score += 0.5
        if dmarc_policy in {"reject", "quarantine"}:
            score += 0.5
        elif dmarc_policy:
            score += 0.2
        return score, {
            "spf_present": spf_record_present,
            "dmarc_policy": dmarc_policy or "none",
            "dmarc_record": dmarc_record_text[:200],
        }


# ────────── WHOIS transparency ─────────────────────────────────────────────
@register
class WHOISProbe(Probe):
    id, weight = "whois", 0.10
    BAD_ORG_KEYWORDS = {
        "redacted",
        "proxy",
        "private",
        "gdpr",
        "privacy",
        "whoisguard",
        "domains by proxy",
    }

    def run(self, dom):  # Stays with original domain
        try:
            self._report_progress(f"WHOIS: Querying registration data for {dom}...")
            w = whois.whois(dom)
            org_name = str(
                w.get("org", "") or w.get("registrant_organization", "")
            ).lower()
            if not org_name and w and hasattr(w, "text"):
                raw_text_lower = w.text.lower()
                if any(
                    keyword in raw_text_lower
                    for keyword in [
                        "redacted for privacy",
                        "registrant information restricted",
                    ]
                ):
                    self._report_progress(
                        f"WHOIS: Information redacted/restricted for {dom}", end="\n"
                    )
                    return 0.0, {"whois_org": "Redacted/Restricted in raw text"}
            if not org_name or any(
                bad_keyword in org_name for bad_keyword in self.BAD_ORG_KEYWORDS
            ):
                self._report_progress(
                    f"WHOIS: No clear organization info for {dom}", end="\n"
                )
                return 0.0, {"whois_org": org_name or "Not Found/Empty"}
            self._report_progress(f"WHOIS: Found organization info for {dom}", end="\n")
            return 1.0, {"whois_org": org_name}
        except AttributeError:
            self._report_progress(f"WHOIS: Error parsing data for {dom}", end="\n")
            return 0.0, {
                "whois_org": "Error parsing WHOIS data",
                "error": "AttributeError",
            }
        except Exception as e:
            self._report_progress(f"WHOIS: Error fetching data for {dom}", end="\n")
            return 0.0, {"whois_org": "Error fetching WHOIS", "error": str(e)}


# ────────── Impersonation Risk (New Probe) ─────────────────────────────────
@register
class ImpersonationProbe(Probe):
    id, weight = "impersonation", 0.25

    def run(self, dom: str) -> Tuple[float, dict]:  # Stays with original domain
        from dqix.utils.dns import get_txt_records
        self._report_progress(
            f"Impersonation: Starting deep email security check for {dom}..."
        )
        details = {
            "spf_present": False,
            "dmarc_present": False,
            "dmarc_policy": "none",
            "dmarc_aspf_mode": "relaxed",
            "dmarc_adkim_mode": "relaxed",
            "dmarc_pct": 100,
            "dkim_implied_by_dmarc": False,
            "raw_dmarc": "",
        }
        current_score = 0.0
        self._report_progress(f"Impersonation: Checking SPF record for {dom}...")
        if any(SPF_RE.match(t) for t in get_txt_records(dom)):
            details["spf_present"] = True
            current_score += 0.2
        self._report_progress(
            f"Impersonation: SPF {'found' if details['spf_present'] else 'not found'} for {dom}"
        )

        self._report_progress(f"Impersonation: Checking DMARC alignment for {dom}...")
        dmarc_records = get_txt_records(f"_dmarc.{dom}")
        if dmarc_records:
            details["dmarc_present"] = True
            dmarc_tags = _parse_dmarc_tags(dmarc_records[0])
            details["raw_dmarc"] = dmarc_records[0][:200]
            if dmarc_tags:
                details["dmarc_policy"] = dmarc_tags.get("p", "none")
                details["dmarc_aspf_mode"] = dmarc_tags.get("aspf", "r")
                details["dmarc_adkim_mode"] = dmarc_tags.get("adkim", "r")
                details["dmarc_pct"] = int(dmarc_tags.get("pct", "100"))
                if details["dmarc_policy"] == "reject":
                    current_score += 0.4
                elif details["dmarc_policy"] == "quarantine":
                    current_score += 0.25
                elif details["dmarc_policy"] != "none":
                    current_score += 0.1
                if details["dmarc_pct"] < 100 and details["dmarc_policy"] in (
                    "reject",
                    "quarantine",
                ):
                    current_score *= details["dmarc_pct"] / 100.0
                if details["dmarc_aspf_mode"] == "s":
                    current_score += 0.2
                elif details["dmarc_aspf_mode"] == "r":
                    current_score += 0.1
                if "adkim" in dmarc_tags:
                    details["dkim_implied_by_dmarc"] = True
                    if details["dmarc_adkim_mode"] == "s":
                        current_score += 0.2
                    elif details["dmarc_adkim_mode"] == "r":
                        current_score += 0.1
        self._report_progress(
            f"Impersonation: DMARC {'found' if details['dmarc_present'] else 'not found'}, "
            f"policy={details['dmarc_policy']}, "
            f"SPF alignment={details['dmarc_aspf_mode']}, "
            f"DKIM alignment={details['dmarc_adkim_mode']}, "
            f"enforcement={details['dmarc_pct']}% for {dom}",
            end="\n",
        )
        final_score = max(0.0, min(1.0, current_score))
        return round(final_score, 3), details


# ---------------------------------------------------------------------------
# Helper – map letter grade to numeric score (0-1)
# ---------------------------------------------------------------------------


def _grade_to_score(letter: str) -> float:
    """Convert SSL letter grade (A-F, optional +/-) to score in [0,1]."""

    base = {
        "A": 1.0,
        "B": 0.9,
        "C": 0.7,
        "D": 0.4,
        "E": 0.2,
        "F": 0.0,
    }
    if not letter:
        return 0.0
    letter = letter.upper().strip()
    return base.get(letter[0], 0.0)


# ---------------------------------------------------------------------------
# Verbose print util used by *all* probes
# ---------------------------------------------------------------------------
