# Probe Scoring Logic

This page documents **how each probe converts raw evidence into a 0–1 score**.  
The formulas are intentionally simple so that anyone can reproduce them with the same inputs.  
Reference numbers correspond to the bibliography in [`README.md`](../README.md#references).

---

## Transport Security

### TLS  
* A+ = 1.0, A = 0.95, A- = 0.90, … F = 0.0 (SSL Labs/sslyze/nmap grade)  
* Handshake-only (no grade available) = 1.0 (but the probe's **weight** is lower)  
* *Ref*: Mozilla Observatory[^4], NIST 800-52r2[^2]

### DNSSEC  
* DS+DNSKEY+RRSIG present +0.25  
* Chain of trust validated (**AD** flag) +0.25  
* Validated by multiple resolvers +0.25  
* Modern algorithm (13 or 14) **and** key ≥ 256 bit +0.25  
* *Ref*: Ling et al., 2021[^1]

---

## Web Hardening

### Security Headers  
* HSTS 0.20  
* CSP 0.20  
* X-Frame-Options 0.15  
* X-Content-Type-Options 0.15  
* Referrer-Policy 0.15  
* Permissions-Policy 0.15  
* Missing any header → subtract its weight  
* *Ref*: Aerts et al., 2019[^4]; OWASP Top 10

### Cookie Flags  
* All of **Secure** + **HttpOnly** + **SameSite** present → 1.0  
* −0.33 for each flag that is missing  
* *Ref*: OWASP Secure Headers

---

## E-mail Security

### SPF + DMARC  
* SPF + DMARC `policy=reject` = 1.0  
* SPF + DMARC `quarantine` = 0.75  
* SPF only = 0.50  
* None = 0.0  
* *Ref*: RFC 7208, RFC 7489

### DKIM  
* DKIM record present = 1.0, missing = 0.0  
* *Ref*: RFC 6376

### MTA-STS  
* `mode=enforce` = 1.0  
* `mode=testing` = 0.5  
* No policy = 0.0  
* *Ref*: RFC 8460[^6]

### BIMI  
* BIMI TXT record **and** valid SVG = 1.0  
* Record present but invalid SVG = 0.5  
* None = 0.0  
* *Ref*: BIMI Group

---

## Certificate Policy

### CAA  
* CAA restricts CA (no wildcard) = 1.0  
* `issue *` (any CA) = 0.5  
* No CAA = 0.0  
* *Ref*: CA/B Forum[^7]

### Certificate Transparency Monitor  
* Active CT log monitoring present = 1.0  
* None = 0.0  
* *Ref*: Scheitle et al., 2020

---

## DNS Hygiene

### DNS Basic  
* A/AAAA record 0.25  
* ≥ 2 NS records 0.25  
* SOA record 0.25  
* MX record 0.25 (if no MX → 0.10)  
* *Ref*: Fowler et al., 2022[^5]

### DNSSEC Chain  
* Full chain of trust = 1.0  
* Partial = 0.5  
* None = 0.0  
* *Ref*: Ling et al., 2021[^1]

### NSEC3  
* NSEC3 present = 1.0  
* None = 0.0  
* *Ref*: RFC 5155

---

## Impersonation & Trust

### Impersonation  
* All of DMARC alignment, BIMI, and MTA-STS present → 1.0  
* Subtract proportionally for each control that is missing  
* *Ref*: ISO/IEC 27001:2022 Annex A.5[^8]

---

## Accessibility

### WCAG 2.1 AA  
* Fully compliant = 1.0  
* Partial = 0.5  
* Fail = 0.0  
* *Ref*: WCAG 2.1[^9]

---

## Ownership Clarity

### WHOIS  
* Owner/organisation contact present = 1.0  
* Registrar only = 0.5  
* None or privacy-masked WHOIS = 0.0  
* *Ref*: EU GDPR Art. 5[^10]

---

## Sustainability (Optional)

### Eco Index  
* Meets eco criteria = 1.0  
* None = 0.0  
* *Ref*: Oberle 2022

---

> **Design goal:** All formulas rely on binary or easily enumerable criteria to keep manual verification possible (KISS).
> For implementation details, see the corresponding class in `dqix/probes/*` or `dqix/plugins/*`. 