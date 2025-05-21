#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Domain‑Quality‑Index (DQI) – version 3
=====================================

Computes a 0‑100 “quality” score for each domain based on web‑ and mail‑
security hygiene, performance, accessibility and registration transparency.

New in v3
---------
* Fine‑grained DNSSEC health (valid / bogus / unsigned + delegation penalties)
* E‑mail controls now include DKIM and a composite “impersonation‑risk” rating
* Helper to print national adoption rates (DNSSEC‑signed %, DKIM %, DMARC %)
* Thread‑pool parallelism for fast batch scans

Dependencies
------------
pip install requests dnspython python-whois tldextract dkimpy
External CLIs (optional but recommended):
  • lighthouse   – npm install -g lighthouse
  • openssl      – system binary (for TLS handshake fallback)
  • jq / pa11y   – if you extend accessibility checks
"""

from __future__ import annotations

import concurrent.futures as cf
import json
import re
import shutil
import subprocess
import time
from pathlib import Path
from typing import Dict, Tuple

import requests
import dns.resolver
import whois
import tldextract
import dkim

# ---------------------------------------------------------------------------#
# Configuration constants
# ---------------------------------------------------------------------------#
SSL_LABS_API = "https://api.dev.ssllabs.com/api/v3/analyze"
GOOGLE_DOH   = "https://dns.google/resolve"          # DNSSEC‑validating resolver

SPF_RE   = re.compile(r"^v=spf1", re.I)
DMARC_RE = re.compile(r"v\s*=\s*DMARC1;\s*p\s*=\s*(\w+)", re.I)

DEFAULT_DKIM_SELECTORS = (
    "default", "google", "selector1", "selector2", "s1", "s2",
)

WEIGHTS: Dict[str, float] = {
    "tls":           0.20,
    "dnssec":        0.20,
    "headers":       0.10,
    "mail":          0.15,
    "whois":         0.10,
    "lighthouse":    0.10,
    "impersonation": 0.15,      # derived from mail sub‑scores
}

# ---------------------------------------------------------------------------#
# TLS / HTTPS
# ---------------------------------------------------------------------------#
def ssl_labs_grade(domain: str, min_grade: str = "B", wait: bool = True) -> bool:
    """
    Return True if SSL Labs grade ≥ *min_grade*.
    Uses the dev API to avoid volume limits.
    """
    params = {"host": domain, "all": "done", "fromCache": "on"}
    r = requests.get(SSL_LABS_API, params=params, timeout=30)
    r.raise_for_status()
    data = r.json()

    while wait and data.get("status") in {"DNS", "IN_PROGRESS"}:
        time.sleep(15)
        data = requests.get(SSL_LABS_API, params=params, timeout=30).json()

    try:
        grade = data["endpoints"][0]["grade"]
    except (KeyError, IndexError):
        return False
    return grade >= min_grade


# ---------------------------------------------------------------------------#
# DNSSEC health
# ---------------------------------------------------------------------------#
def _google_dnssec(domain: str, qtype: str = "A") -> dict:
    r = requests.get(
        GOOGLE_DOH, params={"name": domain, "type": qtype, "do": "1"}, timeout=8
    )
    r.raise_for_status()
    return r.json()


def dnssec_score(domain: str) -> float:
    """
    1.0  – good chain (AD bit, Status 0)
    0.25 – DNSSEC present but bogus (Status 2 / SERVFAIL)
    0.0  – unsigned
    delegation penalties:
        • DS ⇄ DNSKEY mismatch  – -0.10
        • RSA key < 1024 bits   – -0.05
    """
    js = _google_dnssec(domain)
    status = js.get("Status")
    ad     = js.get("AD", False)

    if status == 0 and ad:
        base = 1.0
    elif status == 2:                # SERVFAIL – signature bogus
        base = 0.25
    else:
        return 0.0                   # no DNSSEC

    # delegation checks
    try:
        ds  = dns.resolver.resolve(domain, "DS")
        dsk = {(r.key_tag, r.algorithm) for r in ds}
        k   = dns.resolver.resolve(domain, "DNSKEY")
        ksk = {(r.key_tag, r.algorithm) for r in k}
        if not (dsk & ksk):
            base -= 0.10
        for r in k:
            if r.algorithm in {5, 7, 8, 13} and len(r.key) * 8 < 1024:
                base -= 0.05
                break
    except Exception:
        pass

    return max(base, 0.0)


# ---------------------------------------------------------------------------#
# HTTP Security headers
# ---------------------------------------------------------------------------#
def secure_headers(domain: str) -> bool:
    try:
        r = requests.get(f"https://{domain}", timeout=8, allow_redirects=True)
    except Exception:
        return False
    h = {k.lower(): v for k, v in r.headers.items()}
    return "strict-transport-security" in h and "content-security-policy" in h


# ---------------------------------------------------------------------------#
# WHOIS transparency
# ---------------------------------------------------------------------------#
def whois_transparent(domain: str) -> bool:
    """Registrations that hide *org* or *name* count as opaque."""
    bad_tokens = {"redacted", "gdpr", "private", "proxy", "whoisguard", None, ""}
    try:
        w = whois.whois(domain)
        org = str(w.get("org", "")).lower()
        name = str(w.get("name", "")).lower()
        if any(tok in org for tok in bad_tokens) or any(tok in name for tok in bad_tokens):
            return False
    except Exception:
        return False
    return True


# ---------------------------------------------------------------------------#
# Lighthouse (performance + accessibility)
# ---------------------------------------------------------------------------#
def lighthouse_ok(domain: str) -> bool:
    if not shutil.which("lighthouse"):
        return False
    try:
        out = subprocess.check_output(
            [
                "lighthouse",
                f"https://{domain}",
                "--quiet",
                "--output=json",
                "--output-path=stdout",
            ],
            stderr=subprocess.DEVNULL,
            timeout=120,
            text=True,
        )
        report = json.loads(out)
        lcp_ok = report["audits"]["largest-contentful-paint"]["numericValue"] <= 4000
        a11y   = report["categories"]["accessibility"]["score"] * 100
        return lcp_ok and a11y >= 70
    except Exception:
        return False


# ---------------------------------------------------------------------------#
# Mail‑domain security
# ---------------------------------------------------------------------------#
def _txt_records(name: str):
    try:
        return [r.to_text().strip('"') for r in dns.resolver.resolve(name, "TXT")]
    except Exception:
        return []


def has_spf(domain: str) -> bool:
    return any(SPF_RE.match(txt) for txt in _txt_records(domain))


def dmarc_policy(domain: str) -> str | None:
    txts = _txt_records(f"_dmarc.{domain}")
    for t in txts:
        m = DMARC_RE.search(t)
        if m:
            return m.group(1).lower()
    return None


def dkim_dns_record(domain: str, selectors=DEFAULT_DKIM_SELECTORS) -> bool:
    for sel in selectors:
        try:
            txts = _txt_records(f"{sel}._domainkey.{domain}")
            if any(t.lower().startswith("v=dkim1") for t in txts):
                return True
        except Exception:
            pass
    return False


def impersonation_rating(spf_ok: bool, dkim_ok: bool, dmarc_pol: str | None) -> float:
    """
    Simple rubric:
        • SPF + DKIM + DMARC (quarantine/reject)  → 1.0
        • any 2 controls, or DMARC p=none        → 0.6
        • exactly 1                               → 0.3
        • 0                                       → 0.0
    """
    pieces = sum([spf_ok, dkim_ok, bool(dmarc_pol)])
    if pieces == 3 and dmarc_pol in {"quarantine", "reject"}:
        return 1.0
    if pieces >= 2:
        return 0.6
    if pieces == 1:
        return 0.3
    return 0.0


def mail_scores(domain: str) -> Tuple[float, Dict[str, bool | str]]:
    spf_ok = has_spf(domain)
    dmarc_pol = dmarc_policy(domain)
    dkim_ok = dkim_dns_record(domain)
    rating = impersonation_rating(spf_ok, dkim_ok, dmarc_pol)
    return rating, {
        "spf": spf_ok,
        "dkim": dkim_ok,
        "dmarc": dmarc_pol or "",
        "impersonation": rating,
    }


# ---------------------------------------------------------------------------#
# Main scoring function
# ---------------------------------------------------------------------------#
def score(domain: str) -> Tuple[float, Dict[str, object]]:
    mail_rating, mail_detail = mail_scores(domain)

    results: Dict[str, object] = {
        "tls": ssl_labs_grade(domain),
        "dnssec": dnssec_score(domain),          # 0‑1 float
        "headers": secure_headers(domain),
        "mail": mail_rating,                     # 0‑1 float
        "whois": whois_transparent(domain),
        "lighthouse": lighthouse_ok(domain),
        "impersonation": mail_rating,            # alias for clarity
        **mail_detail,
    }

    total = 0.0
    for k, w in WEIGHTS.items():
        val = results.get(k)
        if isinstance(val, bool):
            total += w * (1.0 if val else 0.0)
        elif isinstance(val, (int, float)):
            total += w * val
        else:
            total += 0.0

    return round(total * 100, 1), results


# ---------------------------------------------------------------------------#
# Helpers for batch scanning
# ---------------------------------------------------------------------------#
def calc_adoption(df, column: str, threshold: float | None = None) -> float:
    if threshold is None:
        mask = df[column].astype(bool)
    else:
        mask = df[column] >= threshold
    return mask.mean() * 100


def scan(domains, max_workers: int = 20):
    with cf.ThreadPoolExecutor(max_workers=max_workers) as exe:
        for d, res in zip(domains, exe.map(score, domains)):
            yield d, res


# ---------------------------------------------------------------------------#
# CLI
# ---------------------------------------------------------------------------#
def _load_domains_from_file(path: Path):
    with path.open() as fh:
        for line in fh:
            dom = line.strip()
            if dom and not dom.startswith("#"):
                yield dom


def main():
    import argparse
    import pandas as pd

    ap = argparse.ArgumentParser(description="Compute Domain‑Quality‑Index (DQI)")
    ap.add_argument("sources", nargs="+",
                    help="Domain names or paths to text files listing domains")
    ap.add_argument("-j", "--jobs", type=int, default=20,
                    help="Parallel worker threads (default 20)")
    ap.add_argument("-o", "--output", type=Path, help="Write results to CSV/Parquet")
    args = ap.parse_args()

    domains = []
    for src in args.sources:
        p = Path(src)
        if p.exists():
            domains.extend(_load_domains_from_file(p))
        else:
            domains.append(src.strip())

    rows = []
    for dom, (score_val, detail) in scan(domains, args.jobs):
        rows.append({"domain": dom, "dqi": score_val, **detail})
        print(f"{dom:<30} DQI={score_val:>5}")

    df = pd.DataFrame(rows).sort_values("dqi", ascending=False)
    # Adoption stats
    print("\n--- Summary ---")
    print(f"DNSSEC‑signed     : {calc_adoption(df,'dnssec',0.25):5.1f}%")
    print(f"DMARC (>=0.6)     : {calc_adoption(df,'mail',0.6):5.1f}%")
    print(f"DKIM present      : {calc_adoption(df,'dkim'):5.1f}%")

    if args.output:
        if args.output.suffix.lower() == ".parquet":
            df.to_parquet(args.output, index=False)
        else:
            df.to_csv(args.output, index=False)
        print(f"\nSaved → {args.output}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())