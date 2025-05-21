#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DQI v1  – HTTPS + DNSSEC only

• TLS grade comes from the SSL Labs v3 API  [oai_citation:0‡GitHub](https://github.com/ssllabs/ssllabs-scan/blob/master/ssllabs-api-docs-v3.md?utm_source=chatgpt.com)  
• DNSSEC presence/validity is inferred from Google Public DNS DoH JSON
  (“Status==0” and “AD”: true)  [oai_citation:1‡Google for Developers](https://developers.google.com/speed/public-dns/docs/doh/json?utm_source=chatgpt.com)

Weighting: 50 % TLS, 50 % DNSSEC  →  score 0-100
"""
import requests, sys, time

SSL_LABS = "https://api.dev.ssllabs.com/api/v3/analyze"
GOOGLE_DOH = "https://dns.google/resolve"

def tls_ok(domain):
    r = requests.get(SSL_LABS, params={"host": domain, "all": "on"}, timeout=30).json()
    while r.get("status") in {"DNS", "IN_PROGRESS"}:
        time.sleep(10)
        r = requests.get(SSL_LABS, params={"host": domain}, timeout=30).json()
    return r.get("endpoints", [{}])[0].get("grade", "F") >= "B"

def dnssec_ok(domain):
    j = requests.get(GOOGLE_DOH, params={"name": domain, "type": "A", "do": "1"}, timeout=8).json()
    return j.get("Status") == 0 and j.get("AD", False)

def score(domain):
    return 50 * tls_ok(domain) + 50 * dnssec_ok(domain)

if __name__ == "__main__":
    for d in sys.argv[1:]:
        print(f"{d:30}  DQI={score(d)}")
