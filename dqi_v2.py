
#!/usr/bin/env python3
"""Domain Quality Index – v2
Adds HSTS/CSP headers, SPF+DMARC, WHOIS transparency.
Weights: TLS .30, DNSSEC .30, headers .15, mail .15, whois .10
"""
import re, time, sys, requests, dns.resolver, whois

SSL_LABS = "https://api.dev.ssllabs.com/api/v3/analyze"
GOOGLE_DOH = "https://dns.google/resolve"
SPF_RE = re.compile(r"^v=spf1", re.I)
DMARC_RE = re.compile(r"v=DMARC1", re.I)
W = dict(tls=.30, dnssec=.30, headers=.15, mail=.15, whois=.10)

def tls_ok(d):
    j = requests.get(SSL_LABS, params={"host": d}, timeout=30).json()
    while j.get("status") in {"DNS","IN_PROGRESS"}:
        time.sleep(8)
        j = requests.get(SSL_LABS, params={"host": d}, timeout=30).json()
    return j.get("endpoints",[{}])[0].get("grade","F") >= "B"

def dnssec_ok(d):
    j = requests.get(GOOGLE_DOH, params={"name":d,"type":"A","do":"1"}, timeout=8).json()
    return j.get("Status")==0 and j.get("AD",False)

def headers_ok(d):
    try:
        r = requests.get(f"https://{d}", timeout=8, allow_redirects=True)
    except:
        return False
    h = {k.lower():v for k,v in r.headers.items()}
    return "strict-transport-security" in h and "content-security-policy" in h

def _txt(name):
    try:
        return [t.to_text().strip('"') for t in dns.resolver.resolve(name,'TXT')]
    except:
        return []

def mail_ok(d):
    spf = any(SPF_RE.match(t) for t in _txt(d))
    dmarc = any(DMARC_RE.search(t) for t in _txt(f"_dmarc.{d}"))
    return spf and dmarc

def whois_ok(d):
    bad = {"redacted","private","proxy","gdpr",""}
    try:
        w = whois.whois(d)
        return not (str(w.get("org","")).lower() in bad or str(w.get("name","")).lower() in bad)
    except:
        return False

def score(domain):
    parts = dict(tls=tls_ok(domain), dnssec=dnssec_ok(domain), headers=headers_ok(domain),
                 mail=mail_ok(domain), whois=whois_ok(domain))
    total = sum(W[k]*(1.0 if v else 0.0) for k,v in parts.items())
    return round(total*100,1), parts

if __name__ == "__main__":
    for dom in sys.argv[1:]:
        print(dom, score(dom)[0])
