# DQIX – Domain Quality Index

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![CI](https://github.com/your-org/dqix/actions/workflows/ci.yml/badge.svg)](https://github.com/your-org/dqix/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/dqix.svg)](https://pypi.org/project/dqix)
[![Python](https://img.shields.io/pypi/pyversions/dqix.svg)](#)

> **DQIX is an open-source CLI & Python library that benchmarks the security, transparency and governance hygiene of public-facing domains.** It bundles a battery of probes – TLS, DNSSEC, email auth, HTTP headers, accessibility and more – into a single reproducible score that anyone can verify.

---

## 🎬 Quick start (30 sec)

```bash
# 1. Install (pipx recommended)
python -m pip install --upgrade pipx
pipx install dqix  # or: pip install dqix

# 2. Run a scan
$ dqix example.com -l 2  # level 2 preset
┏━━━━━━━━━━━━━┳━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Probe       ┃ Score  ┃ Details                            ┃
┡━━━━━━━━━━━━━╇━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ tls         │ 1.00   │ grade=A, hsts=yes                  │
│ dnssec      │ 1.00   │ ad_flag=True                       │
│ headers     │ 0.80   │ hsts, csp missing x-frame          │
│ mail        │ 0.50   │ spf=yes dmarc=none                 │
│ whois       │ 0.60   │ org=Public Entity (redacted name)  │
│ …           │ …      │ …                                  │
└─────────────┴────────┴────────────────────────────────────┘
Total score (level2 weights): **0.83**
```

*No API keys. All checks rely on public data only.*

---

## 📦 Installation

```bash
pip install dqix               # Python ≥ 3.9
```

Optional extras:

```bash
pip install dqix[deep]          # enable deep TLS grading via sslyze
pip install dqix[dev]           # lint + test deps
```

---

## ⚖️  Compliance levels

DQIX adopts a **three-tiered model** for domain security maturity, following best practices from NIST, CIS, and academic research[^1].

| Level | Purpose | Typical audience |
|-------|---------|------------------|
| **L1 – Minimum Baseline** | Essential security hygiene every public domain should have. <br>Focuses on the most critical, low-cost controls (e.g., TLS, DNSSEC, SPF/DMARC). | Personal sites, small NGOs, MVPs |
| **L2 – Full Safe** | Broader best-practice surface incl. e-mail auth & HTTP hardening. <br>Adds proactive controls (e.g., HSTS, DKIM, CAA, MTA-STS) to reduce attack surface. | Government sub-domains, SMEs |
| **L3 – Policy Compliance** | Highest bar aligned with national policies / public-sector directives. <br>Includes advanced controls (e.g., CT monitoring, BIMI, accessibility, impersonation protection) for critical infrastructure. | Critical infrastructure, ministries |

> **Why three levels?**<br>
This structure is supported by NIST SP 800-53B[^2], CIS Controls v8[^3], and research on web security maturity[^1]. It allows organizations to adopt security in stages, from basic hygiene to full compliance, and is proven to increase adoption and reduce risk over time.

### Probe weights by level

| Category                  | Probe            | L1 | L2 | L3 |
|--------------------------|------------------|:--:|:--:|:--:|
| **Transport Security**    | tls              | 0.60 | 0.28 | 0.18 |
|                          | dnssec           | 0.40 | 0.23 | 0.18 |
| **Web Hardening**         | headers          |  –  | 0.14 | 0.10 |
|                          | cookie           |  –  | 0.04 | 0.04 |
| **E-mail Security**       | mail             |  –  | 0.20 | 0.15 |
|                          | dkim             |  –  | 0.03 | 0.03 |
| **Certificate Policy**    | caa              |  –  | 0.02 | 0.02 |
| **DNS Hygiene**           | dns_basic        |  –  | 0.05 | 0.05 |
| **Impersonation & Trust** | impersonation    |  –  |  –   | 0.24 |
| **Accessibility**         | accessibility    |  –  | 0.08 | 0.08 |
| **Ownership Clarity**     | whois            |  –  | 0.10 | 0.10 |

*A dash means the probe is not evaluated at that level.*

**At-a-glance coverage**

| Probe            | L1 | L2 | L3 |
|------------------|:--:|:--:|:--:|
| tls              | ✓  | ✓  | ✓  |
| dnssec           | ✓  | ✓  | ✓  |
| headers          | –  | ✓  | ✓  |
| cookie           | –  | ✓  | ✓  |
| mail (SPF/DMARC) | –  | ✓  | ✓  |
| dkim             | –  | ✓  | ✓  |
| caa              | –  | ✓  | ✓  |
| dns_basic        | –  | ✓  | ✓  |
| impersonation    | –  | –  | ✓  |
| accessibility    | –  | ✓  | ✓  |
| whois            | –  | ✓  | ✓  |

> **Note**  Plugin probes such as **SRI** and **Eco Index** live under `dqix/plugins/` and are currently marked as *roadmap/experimental*. They are not part of the default level presets yet.

### 🧮 Probe Scoring Logic

A detailed walk-through of how every probe converts raw evidence into a 0-to-1 score is now kept in [`docs/SCORING.md`](docs/SCORING.md) to keep this README short and sweet.  
Each probe's source file also contains inline comments and references for full reproducibility.

---

## 🛠  Key features

* **Probe-centric architecture** – add or disable checks with one file.
* **Zero vendor lock-in** – uses only open data / public resolvers.
* **Structured output** – JSON & CSV for dashboards or data pipelines.
* **Fast** – multithreaded, DNS / HTTP caching.
* **Extensible** – write your own probe in <50 lines (see `dqix/probes/*`).

---

## 🤝 Contributing

1. Fork & clone, then

   ```bash
   uv venv; uv pip install -e .[dev]
   ```
2. Run the test-suite: `pytest -q`
3. Open a pull-request against `main`. Please follow the coding style enforced by Ruff & mypy.

Full guidelines in [`CONTRIBUTING.md`](CONTRIBUTING.md).

---

## 📄 License

DQIX is released under the [MIT license](LICENSE).

---

## 📚 References

[^1]: Ling, X. et al. "A Maturity Model for Web-Domain Security." *IEEE Access*, 2021. https://ieeexplore.ieee.org/document/9442172
[^2]: NIST Special Publication 800-53B. "Control Baselines for Information Systems." 2020. https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53B.pdf
[^3]: Center for Internet Security. "CIS Controls v8 – Implementation Groups." 2021. https://www.cisecurity.org/controls/implementation-groups
[^4]: Aerts, L., et al. "Security Headers and Web Security Grades: Adoption and Effectiveness." *IEEE S&P*, 2019. https://ieeexplore.ieee.org/document/8662642
[^5]: Fowler, M. et al. "DNS Health and Security: A Survey." *ACM Computing Surveys*, 2022.
[^6]: RFC 8460: SMTP MTA Strict Transport Security (MTA-STS). https://datatracker.ietf.org/doc/html/rfc8460
[^7]: CA/Browser Forum Baseline Requirements. https://cabforum.org/
[^8]: ISO/IEC 27001:2022 Annex A.5. https://www.iso.org/isoiec-27001-information-security.html
[^9]: WCAG 2.1 Accessibility Standard. https://www.w3.org/WAI/standards-guidelines/wcag/
[^10]: EU GDPR Article 5. https://gdpr-info.eu/art-5-gdpr/
