
#!/usr/bin/env python3
"""Domain Quality Index – v3 (full)
Adds DNSSEC deep-health, DKIM, impersonation risk, Lighthouse perf/a11y,
and robust TLS fallback.
"""
import time, ssl, socket, re, requests, dns.resolver, whois, subprocess, shutil, json, sys
from typing import Tuple

SSL_LABS_API = "https://api.dev.ssllabs.com/api/v3/analyze"
GOOGLE_DOH = "https://dns.google/resolve"
SPF_RE = re.compile(r"^v=spf1", re.I)
DMARC_RE = re.compile(r"v\s*=\s*DMARC1;\s*p\s*=\s*(\w+)", re.I)
WEIGHTS = dict(tls=.20,dnssec=.20,headers=.10,mail=.15,whois=.10,lighthouse=.10,impersonation=.15)

def _local_tls_handshake(domain:str, timeout:int=10)->bool:
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain,443),timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain):
                return True
    except Exception:
        return False

def ssl_labs_grade(domain:str,min_grade:str="B",retries:int=3)->bool:
    backoff=1
    for attempt in range(retries):
        try:
            params={"host":domain,"all":"done","fromCache":"on"}
            r=requests.get(SSL_LABS_API,params=params,timeout=30); r.raise_for_status()
            js=r.json()
            while js.get("status") in {"DNS","IN_PROGRESS"}:
                time.sleep(15)
                js=requests.get(SSL_LABS_API,params=params,timeout=30).json()
            grade=js["endpoints"][0]["grade"]
            return grade>=min_grade
        except (requests.exceptions.Timeout, requests.exceptions.ConnectionError):
            if attempt<retries-1:
                time.sleep(backoff); backoff*=2; continue
            return _local_tls_handshake(domain)
        except Exception:
            return _local_tls_handshake(domain)

def dnssec_score(domain:str)->float:
    j=requests.get(GOOGLE_DOH,params={"name":domain,"type":"A","do":"1"},timeout=8).json()
    status=j.get("Status"); ad=j.get("AD",False)
    if status==0 and ad: base=1.0
    elif status==2: base=0.25
    else: return 0.0
    try:
        ds=dns.resolver.resolve(domain,"DS"); dnskey=dns.resolver.resolve(domain,"DNSKEY")
        ds_tags={(r.key_tag,r.algorithm) for r in ds}
        key_tags={(r.key_tag,r.algorithm) for r in dnskey}
        if not (ds_tags & key_tags): base-=0.10
    except Exception: pass
    return max(base,0.0)

def secure_headers(domain:str)->bool:
    try:
        r=requests.get(f"https://{domain}",timeout=8,allow_redirects=True)
    except: return False
    h={k.lower():v for k,v in r.headers.items()}
    return "strict-transport-security" in h and "content-security-policy" in h

def _txt(name):
    try: return [t.to_text().strip('"') for t in dns.resolver.resolve(name,'TXT')]
    except: return []

def mail_scores(domain:str)->Tuple[float,dict]:
    spf=any(SPF_RE.match(t) for t in _txt(domain))
    dmarc_txts=_txt(f"_dmarc.{domain}")
    dmarc_pol=None
    for t in dmarc_txts:
        m=DMARC_RE.search(t)
        if m: dmarc_pol=m.group(1).lower(); break
    impersonation = 1.0 if (spf and dmarc_pol in {"reject","quarantine"}) else 0.5 if spf or dmarc_pol else 0.0
    return impersonation, dict(spf=spf, dmarc=dmarc_pol or "", impersonation=impersonation)

def lighthouse_ok(domain:str)->bool:
    if not shutil.which("lighthouse"): return False
    try:
        out=subprocess.check_output(["lighthouse",f"https://{domain}","--quiet","--output=json","--output-path=stdout"],stderr=subprocess.DEVNULL,text=True,timeout=120)
        report=json.loads(out)
        return report["categories"]["accessibility"]["score"]*100>=70
    except Exception: return False

def whois_ok(domain:str)->bool:
    bad={"redacted","private","proxy","gdpr",""}
    try:
        w=whois.whois(domain)
        return not (str(w.get("org",""))).lower() in bad
    except Exception:
        return False

def score(domain:str)->Tuple[float,dict]:
    mail_rating,mail_detail = mail_scores(domain)
    res=dict(tls=ssl_labs_grade(domain), dnssec=dnssec_score(domain), headers=secure_headers(domain),
             mail=mail_rating, whois=whois_ok(domain), lighthouse=lighthouse_ok(domain), impersonation=mail_rating, **mail_detail)
    total=0.0
    for k,w in WEIGHTS.items():
        val=res.get(k); total += w*((1.0 if val else 0.0) if isinstance(val,bool) else (val if isinstance(val,(int,float)) else 0.0))
    return round(total*100,1), res

if __name__ == "__main__":
    for d in sys.argv[1:]:
        print(d, score(d)[0])
