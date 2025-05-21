
# DQIX – Domain Quality Index (refactored)

**DQIX** benchmarks the security & governance hygiene of public‑service domains.  
Version 3 now drops all calls to the unstable `api.dev.ssllabs.com` and uses a *local* two‑tier TLS checker:

1. **Tier‑1 (always):** one Python TLS 1.3 handshake (`ssl.create_default_context`) – fast, offline‑safe.  
2. **Tier‑2 (optional):** [SSLyze] regular scan (<5 s) for cipher, protocol and vuln checks.  
   Enable by installing `sslyze` and setting `DQIX_TLS_DEEP=1`.

This design removes every external API time‑out while preserving an A/B/C/D/F style grade.  
Dependencies: `requests`, `dnspython`, `python-whois`, `pyyaml`, **`sslyze` (optional)**.

## Package layout

```
dqix/
  cli.py              # python -m dqix.cli -l 2 example.com
  presets/            # level1/2/3 YAML weight maps
  core/
      probes.py       # pluggable Probe classes (TLS, DNSSEC, HSTS, Mail, WHOIS)
  plugins/            # future: mta_sts.py, rpki.py ...
```

## Quick start

```bash
pip install requests dnspython python-whois pyyaml         # mandatory
pip install sslyze                                         # optional deep TLS scan
python -m dqix.cli -l 3 www.bot.or.th
```

```
www.bot.or.th                 DQI-L3=84.0   (tls_grade=A)
```

## References

* SSLyze GitHub repo (fast TLS scanner) citeturn0search0  
* OWASP WSTG recommends SSLyze for TLS testing citeturn0search11  
* Mozilla TLS Observatory rate‑limit note citeturn0search2  
* Testssl.sh issue citing slow scans citeturn0search3  
* Python `ssl` handshake docs (CERT_REQUIRED) citeturn0search5  
* Google DoH JSON spec with `AD` bit citeturn0search7  
* APNIC DNSSEC validation stats for TH citeturn0search6  
* OONI Probe <90 s test constraint citeturn0search8  
* RFC 8460 – SMTP TLS Reporting for v4 roadmap citeturn0search9  
* SSL Labs doc showing `api.dev.ssllabs.com` is non‑prod citeturn0search4  
* Additional SSLyze fork mirror citeturn0search10  



## Compliance Levels

| Level | Objective | Metrics (weights) |
|-------|-----------|-------------------|
| **1** | *“Must not be broken”* – basic channel security and DNS integrity | TLS (60%), DNSSEC presence (40%) |
| **2** | *“Safe by default”* – adds HTTP header hygiene and e‑mail anti‑spoofing | TLS 30, DNSSEC quality 25, HSTS/CSP 15, SPF+DMARC 20, WHOIS 10 |
| **3** | *“Policy aligned”* – full impersonation‑risk model and optional Lighthouse | TLS 20, DNSSEC deep‑health 20, Headers 10, Mail 15, WHOIS 10, Impersonation 25 |

Each YAML preset under `dqix/presets/` maps exactly to these weights and can be tuned without touching Python.

---
