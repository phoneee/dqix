
from __future__ import annotations
import time, ssl, socket, requests, re, dns.resolver, whois, json, shutil, subprocess
from typing import Tuple
from . import register

SSL_API = "https://api.dev.ssllabs.com/api/v3/analyze"
GOOGLE_DOH = "https://dns.google/resolve"
SPF_RE = re.compile(r"^v=spf1", re.I)
DMARC_RE = re.compile(r"v\s*=\s*DMARC1;\s*p\s*=\s*(\w+)", re.I)

class Probe:
    id: str
    weight: float
    passive: bool = True
    def run(self, domain:str)->Tuple[float,dict]:
        raise NotImplementedError

# TLS Probe
@register
class TLSProbe(Probe):
    id = "tls"
    weight = 0.20
    def _local_tls(self, domain):
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((domain,443),timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=domain):
                    return True
        except Exception:
            return False
    def run(self,domain):
        try:
            params={"host":domain,"all":"done","fromCache":"on"}
            r=requests.get(SSL_API,params=params,timeout=15).json()
            while r.get("status") in {"DNS","IN_PROGRESS"}:
                time.sleep(8)
                r=requests.get(SSL_API,params=params,timeout=15).json()
            ok=r["endpoints"][0]["grade"]>="B"
            return (1.0 if ok else 0.0, {"tls_grade": r["endpoints"][0]["grade"]})
        except Exception:
            ok=self._local_tls(domain)
            return (1.0 if ok else 0.0, {"tls_fallback": ok})

@register
class DNSSECProbe(Probe):
    id="dnssec"
    weight=0.20
    def run(self,domain):
        j=requests.get(GOOGLE_DOH,params={"name":domain,"type":"A","do":"1"},timeout=8).json()
        status=j.get("Status"); ad=j.get("AD",False)
        score=1.0 if status==0 and ad else 0.0
        return score, {"dnssec_status":status,"ad":ad}

@register
class HeaderProbe(Probe):
    id="headers"
    weight=0.10
    def run(self,domain):
        try:
            r=requests.get(f"https://{domain}",timeout=8,allow_redirects=True)
            h={k.lower():v for k,v in r.headers.items()}
            ok = "strict-transport-security" in h and "content-security-policy" in h
            return (1.0 if ok else 0.0, {"hsts": "strict-transport-security" in h, "csp":"content-security-policy" in h})
        except Exception:
            return 0.0, {}

@register
class MailProbe(Probe):
    id="mail"
    weight=0.15
    def _txt(self,name):
        try: return [t.to_text().strip('"') for t in dns.resolver.resolve(name,'TXT')]
        except Exception: return []
    def run(self,domain):
        spf=any(SPF_RE.match(t) for t in self._txt(domain))
        dmarc_pol=None
        for t in self._txt(f"_dmarc.{domain}"):
            m=DMARC_RE.search(t)
            if m: dmarc_pol=m.group(1).lower(); break
        score = 1.0 if (spf and dmarc_pol in {"reject","quarantine"}) else 0.5 if spf or dmarc_pol else 0.0
        return score, {"spf":spf,"dmarc":dmarc_pol or ""}

@register
class WHOISProbe(Probe):
    id="whois"
    weight=0.10
    def run(self,domain):
        bad={"redacted","proxy","private","gdpr",""}
        try:
            w=whois.whois(domain)
            good = not (str(w.get("org","")).lower() in bad)
            return 1.0 if good else 0.0, {"whois_org":w.get("org")}
        except Exception:
            return 0.0, {}

@register
class TLSProbe(Probe):
    """
    Tier‑1: local TLS 1.3 handshake (always)
    Tier‑2: SSLyze regular scan if library present or if DQIX_TLS_DEEP env set.

    Letter grade mapped to numeric:
        A/B → 1.0
        C   → 0.7
        D   → 0.4
        F   → 0.0
    """
    id = "tls"
    weight = 0.20
    passive = True

    def _handshake_ok(self, domain: str) -> bool:
        import ssl, socket
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=8) as sock:
                with ctx.wrap_socket(sock, server_hostname=domain):
                    return True
        except Exception:
            return False

    def _grade_from_sslyze(self, domain: str):
        import os
        deep = os.getenv("DQIX_TLS_DEEP") == "1"
        try:
            from sslyze import (
                Scanner, ServerScanRequest, ServerNetworkLocation
            )
        except ModuleNotFoundError:
            return None  # library not installed

        if not deep:
            return None
        try:
            scanner = Scanner()
            req = ServerScanRequest(
                server_location=ServerNetworkLocation(hostname=domain, port=443),
                scan_commands={'regular'}
            )
            result = next(scanner.queue_scans_and_await_results([req]))
            # heuristic grading
            has_tls13 = any(
                ec.tls_version.name == "TLS_1_3"
                for ec in result.accepted_cipher_suites
            )
            weak_cipher = any(
                "RC4" in c.name or "3DES" in c.name
                for r in result.accepted_cipher_suites
                for c in r.accepted_cipher_suites
            )
            if weak_cipher:
                return 'D'
            return 'A' if has_tls13 else 'C'
        except Exception:
            return 'F'

    def run(self, domain: str):
        grade = self._grade_from_sslyze(domain)
        if grade is None:
            # fallback: handshake only
            ok = self._handshake_ok(domain)
            return (1.0 if ok else 0.0, {"tls_grade": "local", "tls_ok": ok})
        num = {'A':1.0,'B':0.9,'C':0.7,'D':0.4,'F':0.0}.get(grade,0.0)
        return num, {"tls_grade": grade}
