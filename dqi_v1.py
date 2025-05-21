
#!/usr/bin/env python3
"""Domain Quality Index – v1
Checks:
  • TLS grade (SSL Labs API)
  • DNSSEC presence via Google DoH
Weight: 50 / 50
"""
import time, sys, requests

SSL_LABS = "https://api.dev.ssllabs.com/api/v3/analyze"
GOOGLE_DOH = "https://dns.google/resolve"

def tls_ok(domain):
    r = requests.get(SSL_LABS, params={"host": domain, "all": "on"}, timeout=30).json()
    while r.get("status") in {"DNS", "IN_PROGRESS"}:
        time.sleep(8)
        r = requests.get(SSL_LABS, params={"host": domain}, timeout=30).json()
    return r.get("endpoints", [{}])[0].get("grade", "F") >= "B"

def dnssec_ok(domain):
    j = requests.get(GOOGLE_DOH, params={"name": domain, "type":"A", "do":"1"}, timeout=8).json()
    return j.get("Status")==0 and j.get("AD", False)

def score(domain):
    return 50 * tls_ok(domain) + 50 * dnssec_ok(domain), dict(tls=tls_ok(domain), dnssec=dnssec_ok(domain))

if __name__ == "__main__":
    for d in sys.argv[1:]:
        print(d, score(d)[0])
