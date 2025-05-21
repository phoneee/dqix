# DQI project structure generated archive# Domain Quality Index (DQI)

DQI benchmarks the operational hygiene of public-facing domains – initially for
Thai .th public-service sites, but generic enough for any TLD.

| Version | Focus | Checks included | LoC |
|---------|-------|-----------------|-----|
| **v1**  | Feasibility | TLS grade, DNSSEC presence | ~70 |
| **v2**  | Hardening   | + HTTP security headers, SPF & DMARC, WHOIS check | ~140 |
| **v3**  | Production  | + DNSSEC deep-health, DKIM, impersonation-risk, Lighthouse, batch CLI | ~350 |

## Approach

1. **Public data first** – SSL Labs API  [oai_citation:9‡GitHub](https://github.com/ssllabs/ssllabs-scan/blob/master/ssllabs-api-docs-v3.md?utm_source=chatgpt.com), Google DoH  [oai_citation:10‡Google for Developers](https://developers.google.com/speed/public-dns/docs/doh/json?utm_source=chatgpt.com), DNS TXT, Lighthouse CLI, no paid feeds.  
2. **Incremental design** – each version keeps the same public function
   `score(domain) → (dqi, detail)` so downstream scripts never break.
3. **Transparent weights** – tweakable `WEIGHTS` dict; scores normalised to 0-100.
4. **Lightweight deps** – pure-Python (`requests`, `dnspython`  [oai_citation:11‡dnspython](https://dnspython.readthedocs.io/en/latest/resolver-class.html?utm_source=chatgpt.com),
   `python-whois`, `dkimpy`), optional CLIs (Lighthouse, pa11y).
5. **Batch & trend** – v3 emits Parquet; combine with APNIC DNSSEC-validation
   JSON for macro charts  [oai_citation:12‡stats.labs.apnic.net](https://stats.labs.apnic.net/dnssec/AS2675?utm_source=chatgpt.com).

## Roadmap

* **v4** – MTA-STS & TLS-RPT TXT checks, RPKI origin validation  
* **v5** – OWASP ZAP vulnerability sweep, containerised runner  
* **CI/CD** – GitHub Action that fails if any critical `.go.th` site drops below
  DQI ≥ 70.

## Timeline & Constraint Levels

| Version | Timeline / Tag | Technical scope | Policy coverage | Operational constraint |
|---------|----------------|-----------------|-----------------|------------------------|
| **v1**  | 2025‑05 (tag `v1.0.0`) | TLS grade + DNSSEC presence | None – feasibility only | Single‑thread, ≤1 API call per domain |
| **v2**  | 2025‑05 (tag `v2.0.0`) | + HSTS/CSP, SPF + DMARC, WHOIS | Maps to Draft Digital Gov Sec Guideline §4.1 | Still headless; no Chromium dependency |
| **v3**  | 2025‑05 (tag `v3.0.0`) | + DNSSEC deep‑health, DKIM, impersonation risk, Lighthouse | Aligns with MoDES Cybersecurity Baseline v1 (2023) | Lighthouse requires Chrome; needs 300 MB memory / 20 threads |
| **v4** (planned) | Q3 2025 | + MTA‑STS, TLS‑RPT, RPKI origin validation | Will cover NBTC Notice on e‑mail security (draft) | Outbound SMTP(`starttls`) probes; heavy DNS queries |
| **v5** (planned) | Q4 2025 | OWASP ZAP passive scan, containerised CI gate | Maps to NIST 800‑53 rev. 5 SA‑11 | Requires Docker + ≥1 vCPU per scan |

> **Constraint level** summarises CPU / bandwidth assumptions and whether the probe is “active” or “passive” from a network‑measurement standpoint.

---

## OONI Template Discussion

OONI tests run on volunteer devices and must be: **(1) non‑intrusive**, **(2) deterministic**, and **(3) quick (< 90 s)**.  
DQI’s passive look‑ups (DNS/TXT, WHOIS, SSL Labs metadata) satisfy (1) and (2) but the Lighthouse pass can exceed 45 s on low‑power handsets, and external APIs break the “deterministic” rule.  

| DQI check | OONI‑compatible? | Notes |
|-----------|-----------------|-------|
| DNSSEC AD‑bit via DoH | ✅ | Already used by OONI’s DNS consistency test |
| TLS grade (SSL Labs) | ⚠️ | Requires 3rd‑party API; can be stubbed with local `openssl s_client` |
| HSTS/CSP header fetch | ✅ | 1 HTTP GET – acceptable |
| SPF/DMARC/DKIM TXT | ✅ | 3 DNS queries – acceptable |
| Lighthouse perf/a11y | ❌ | Heavy Chrome dependency |

**Prototype plan**

1. Wrap the ✅ checks into a **custom OONI “domain‑quality” template** (Python + Twisted reactor).  
2. Emit a JSON blob conforming to the OONI measurement schema (`test_keys.domain_quality`).  
3. Submit a pull‑request to `ooni/spec` once the Python probe proves stable.  
4. Keep the full DQI (with Lighthouse & SSL Labs) as an *offline* enrichment pipeline run on cloud VMs.

Until the OONI patch is accepted, stakeholders can rely on the **Python CLI (`dqi_v3.py`)**; it outputs JSON that can be imported into Power BI or OONI Explorer by post‑processing.

---

### Dependencies

```bash
pip install requests dnspython python-whois tldextract dkimpy pandas
npm install -g lighthouse   # optional but recommended
```

Run:

```
python dqi_v3.py www.bot.or.th -o result.parquet
```

