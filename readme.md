# DQIX – Domain Quality Index

[![License](https://img.shields.io/github/license/phoneee/domain-quality-index?style=flat-square)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.9%2B-blue.svg?style=flat-square)](https://www.python.org/)
[![Latest Release](https://img.shields.io/github/v/release/phoneee/domain-quality-index?style=flat-square)](https://github.com/phoneee/domain-quality-index/releases)
[![CI](https://img.shields.io/github/actions/workflow/status/phoneee/domain-quality-index/ci.yml?branch=main&label=tests&style=flat-square)](https://github.com/phoneee/domain-quality-index/actions)

> **DQIX** benchmarks the security & governance hygiene of public-service domains.
>
> ⚡ **Fast**   •   🛡️ **Privacy-Conscious**   •   🛠️ **Pluggable Probe Architecture**

---

## Table of Contents
- [DQIX – Domain Quality Index](#dqix--domain-quality-index)
  - [Table of Contents](#table-of-contents)
  - [Overview](#overview)
  - [Features](#features)
  - [How DQIX Works](#how-dqix-works)
  - [Understanding the Probes](#understanding-the-probes)
  - [Compliance Levels \& Scoring](#compliance-levels--scoring)
  - [Package Layout](#package-layout)
  - [Installation](#installation)
  - [Validation \& Scoring Logic](#validation--scoring-logic)
  - [Performance Tips](#performance-tips)
  - [Quick Start](#quick-start)
  - [Usage](#usage)
    - [Command-Line Interface (CLI)](#command-line-interface-cli)
  - [Environment Variables](#environment-variables)
  - [Using DQIX as a Library (Advanced)](#using-dqix-as-a-library-advanced)
  - [Roadmap](#roadmap)
  - [Contributing](#contributing)
  - [License](#license)
  - [References](#references)

---

## Overview

The Domain Quality Index (DQIX) is a command-line tool and Python library designed to assess and score the technical quality and security posture of domain names. It employs a series of "probes" to check various aspects of a domain's configuration, such as TLS/SSL setup, DNSSEC implementation, email security records (SPF, DMARC, DKIM alignment), HTTP security headers, and WHOIS data transparency.

The goal of DQIX is to provide a quick, reliable, and configurable way to benchmark domains, making it useful for:
*   Security auditors assessing organizational hygiene.
*   System administrators verifying configurations.
*   Researchers studying domain security trends.
*   Automated CI/CD pipelines for continuous monitoring.

DQIX is designed to be fast and privacy-conscious. While it primarily aims for local checks, it utilizes external services like the SSL Labs API (with caching preferences) for comprehensive TLS grading and Google's Public DNS-over-HTTPS for reliable DNSSEC validation.

## Features

*   **Comprehensive TLS/SSL Assessment:**
    *   Utilizes the [SSL Labs API](https://www.ssllabs.com/ssltest/) for an A-F grade, preferring cached results for speed.
    *   Optional deep scan via [SSLyze] integration (if installed and enabled) for detailed cipher suite analysis.
    *   Fallback to a local TLS handshake check if API/SSLyze are unavailable or disabled.
    *   Intelligently handles `www` and non-`www` domain variants for web-related probes.
*   **DNSSEC Validation:** Checks for DNSSEC deployment and data authentication using Google Public DNS-over-HTTPS.
*   **Email Security:**
    *   Verifies presence and policy of SPF and DMARC records.
    *   Assesses DMARC alignment with SPF and DKIM (for impersonation risk).
*   **HTTP Security Headers:** Checks for key headers like HSTS (HTTP Strict Transport Security) and CSP (Content Security Policy).
*   **WHOIS Transparency:** Evaluates the clarity of WHOIS registration information, flagging redacted or privacy-protected records.
*   **Modular Probe System:** Easily extendable with new probes for future checks.
*   **Configurable Scoring:** YAML-driven weight presets (Levels 1–3) allow auditors to tune scoring criteria without modifying Python code.
*   **Flexible Usage:**
    *   User-friendly command-line interface.
    *   Can be integrated as a Python library into other tools and scripts.
*   **Efficient & Visual Processing:** Concurrent multi-threaded scanning with a real-time progress bar (powered by `tqdm`) that shows which domain has just been validated.
*   **Multiple Output Formats:** Standard console output, verbose/debug modes, and CSV export.

## How DQIX Works

DQIX operates by running a series of probes against a target domain.

1.  **Probe Execution:** For a given domain and assessment level, DQIX selects the relevant probes and their configured weights from YAML presets.
2.  **Data Collection:** Each probe performs its checks. This might involve:
    *   Making DNS queries (e.g., for TXT, A records via `dns.resolver`).
    *   Establishing TLS connections (local handshake, SSL Labs API, or SSLyze).
    *   Sending HTTP requests (for headers).
    *   Querying WHOIS servers.
    *   Using Google DOH for DNSSEC checks.
3.  **Scoring:**
    *   Each probe returns a raw score between 0.0 (worst) and 1.0 (best) based on its findings.
    *   The overall DQI score is a weighted average of the individual probe scores, scaled to 0-100.
4.  **Reporting:** Results are displayed on the console, including the overall DQI score and, optionally, detailed breakdowns for each probe. Results can also be saved to a CSV file.

## Understanding the Probes

DQIX uses the following probes (defined in `dqix/core/probes.py`) to assess domain quality:

*   **`tls` (TLS/SSL Configuration):**
    *   Primarily uses the SSL Labs API for an A-F grade.
    *   Can optionally perform a deeper scan using SSLyze if `DQIX_TLS_DEEP=1` is set and SSLyze is installed.
    *   Falls back to a local handshake check if the API fails or SSLyze is not used.
    *   Automatically tries `www.` and non-`www` variants of the domain.
*   **`dnssec` (DNSSEC):**
    *   Verifies if DNSSEC is enabled and that DNS records are cryptographically signed and validated by checking the AD (Authenticated Data) bit via Google's DNS-over-HTTPS service.
*   **`headers` (HTTP Security Headers):**
    *   Inspects HTTP response headers from the domain (via HTTPS).
    *   Checks for the presence of `Strict-Transport-Security` (HSTS) and `Content-Security-Policy` (CSP or CSP-Report-Only).
    *   Automatically tries `www.` and non-`www` variants of the domain.
*   **`mail` (Basic Email Security):**
    *   Checks for the presence of an SPF (Sender Policy Framework) record.
    *   Checks for the presence of a DMARC (Domain-based Message Authentication, Reporting, and Conformance) record and its policy (e.g., `none`, `quarantine`, `reject`).
*   **`whois` (WHOIS Transparency):**
    *   Fetches WHOIS registration data.
    *   Scores based on whether the registrant organization information is clearly available or if it's redacted, proxied, or hidden for privacy.
*   **`impersonation` (Advanced Email Security & Alignment):**
    *   A more in-depth check related to email spoofing and impersonation risk.
    *   Scores based on SPF presence, DMARC policy strength (`p=`), DMARC SPF alignment (`aspf=s|r`), DMARC DKIM alignment (`adkim=s|r`), and DMARC enforcement percentage (`pct=`).

## Compliance Levels & Scoring

DQIX offers three predefined compliance levels, each with different probes and weightings, defined in YAML files under `dqix/presets/`. The total DQI score is out of 100. The weights determine how much each probe contributes to the final score.

| Level | Objective                                                     | Example Probes & Weights (from `levelX.yaml`)                                                                 |
|-------|---------------------------------------------------------------|---------------------------------------------------------------------------------------------------------------|
| **1** | *"Must not be broken"* – Basic channel security & DNS integrity. | e.g., `tls` (0.60), `dnssec` (0.40) — *See `level1.yaml` for actual values.*                                   |
| **2** | *"Safe by default"* – Adds HTTP headers & baseline e‑mail security. | e.g., `tls` (0.30), `dnssec` (0.25), `headers` (0.15), `mail` (0.20), `whois` (0.10) — *See `level2.yaml`.* |
| **3** | *"Policy aligned"* – Full impersonation‑risk model.             | `tls` (0.20), `dnssec` (0.20), `headers` (0.10), `mail` (0.15), `whois` (0.10), `impersonation` (0.25) — *As per `level3.yaml`.* |

Each probe's raw score (0.0 to 1.0) is multiplied by its weight for the selected level, and these weighted scores are summed up and scaled to produce the final DQI score.

## Package Layout

```
dqix/
├── cli.py              # Main CLI entry point (python -m dqix.cli ...)
├── core/
│   ├── init.py     # Core utilities, probe registration
│   └── probes.py       # Definitions for all Probe classes (TLS, DNSSEC, etc.)
├── presets/            # YAML files defining weights for level1, level2, level3
└── plugins/            # (Future) Directory for additional, optional probes
```

## Installation

DQIX targets Python ≥ 3.9 and runs on Linux, macOS, and Windows.
It's highly recommended to install DQIX in a virtual environment.

If your project uses `extras_require` in `setup.py` (e.g., `dqix[base]`, `dqix[sslyze]`), adjust the pip install commands accordingly:

`tqdm` is now required for the progress bar. Install the baseline dependencies with:

```bash
pip install dqix tqdm  # or your local clone:  pip install -e . && pip install tqdm
```

If you want **full TLS deep-scan** capabilities you should also install [SSLyze]:

```bash
pip install sslyze
```

## Validation & Scoring Logic

DQIX validates its **weight presets** on startup.  If the weights defined in any of the YAML files do **not** add up to `1.0` (±0.01) a warning is raised and the weights are **auto-normalized** so the overall score still spans 0-100.  This prevents silent mis-configuration when you customise the preset files.

👉 If you see a message such as `weights for level 2 sum to 1.12 (expected 1.0)` check your `dqix/presets/level2.yaml` for typos.

## Performance Tips

1. **SSL Labs API latency** is often the slowest part of a run (it may queue a fresh scan for 1–2 minutes).  To speed things up:
   * Prefer re-runs within ~24 h so the cached SSL Labs results are returned instantly.
   * Export `DQIX_TLS_DEEP=1` and install `sslyze` – for many hosts a local SSLyze scan is faster than waiting for the public API.
2. Increase the **thread pool** with `-j` but stay below the number of outbound connections your network can handle comfortably.
3. Use `--csv` for large batches so you don't need `--verbose`; the CSV will still contain the raw JSON for post-analysis.

---

## Quick Start

1.  **Install DQIX and SSLyze (optional but recommended for full TLS checks):**
2.  **Run a scan:**
    Example output:
    
    To see more details:


## Usage

### Command-Line Interface (CLI)

DQIX is primarily used via its command-line interface.

- `example.com`: The domain that was scanned.
- `DQI-L3=88.5`: The Domain Quality Index score for Level 3 is 88.5 (out of 100).

If you use --verbose or --debug, you'll see more details:


**Targets:**
You can specify one or more domain names. You can also provide file paths, where each file contains a list of domains (one per line, comments with `#` are ignored).

**Key Options (as per `dqix/cli.py`):**

| Flag                             | Default                                  | Description                                                                                                |
|----------------------------------|------------------------------------------|------------------------------------------------------------------------------------------------------------|
| `targets` (positional)         | _N/A_                                    | One or more domain names or file paths (one domain per line).                                              |
| `-l, --level <1\|2\|3>`          | `3`                                      | Assessment level (1=Minimal, 2=Safe, 3=Policy). Defines probe weights.                                   |
| `-j, --threads <int>`            | Auto (min(32, CPU cores + 4))            | Number of concurrent threads for scanning multiple domains.                                                |
| `--csv <path/to/file.csv>`       | _None_                                   | Save results to a CSV file at the specified path.                                                          |
| `-v, --verbose`                  | _Off_                                    | Show detailed scores and raw data for each probe that didn't score perfectly or lost significant points. |
| `--debug`                        | _Off_                                    | Show all probe details, including raw data and potential errors, even for perfect scores. Implies `-v`.    |

**Examples:**

* Scan a single domain with default Level 3:
  - `·` or `⚠`: A flag indicating status. `⚠` suggests an area for improvement or a non-perfect score.
  - `tls`, `dnssec`, etc.: The ID of the probe.
  - `-04.0 pts`: Points lost from this probe's contribution to the total 0-100 DQI score.
  - `score=0.80`: The raw score of this probe (0.0 to 1.0).
  - `weight=0.20`: The weight of this probe for the current level.
  - `raw={...}`: A summary of the raw data collected by the probe. In --debug mode, this can be more extensive and is truncated in verbose mode if too long.

## Environment Variables

- `DQIX_TLS_DEEP`: Controls the SSLyze deep scan behavior for the tls probe.
    - `DQIX_TLS_DEEP=1`: Force enable the SSLyze deep scan (if SSLyze is installed).
    - `DQIX_TLS_DEEP=0`: Force disable the SSLyze deep scan.
    - If not set (default): SSLyze scan is attempted if SSLyze is installed and the SSL Labs API call doesn't yield a grade.

## Using DQIX as a Library (Advanced)

While primarily a CLI tool, DQIX's core components can be used programmatically. This example mirrors the logic in cli.py:
*   Scan multiple domains at Level 2 with verbose output:

*Note: The `PROBES` dictionary in `dqix.core` stores instances. For true stateless library use, instantiating probes per call or ensuring they are designed to be stateless is important.*

## Roadmap

- [ ] **Improved Library Interface:** Offer a more streamlined `Auditor` class or similar for easier programmatic use.
- [ ] **MTA-STS and SMTP TLS-RPT Probes:** Enhance email security checks.
- [ ] **CAA Record Check:** Add a probe for Certification Authority Authorization.
- [ ] **Configuration for External Services:** Allow users to configure timeouts, retries, or even disable specific external API calls (e.g., SSL Labs).
- [ ] **RPKI & DANE Support:** Investigate probes for BGP security and DNS-based Authentication of Named Entities.

## Contributing

Contributions are welcome! Whether it's bug reports, feature requests, documentation improvements, or new probes, please feel free to contribute.

1. Fork the repository (`https://github.com/phoneee/domain-quality-index`).
2. Create your feature branch (git checkout -b feature/my-new-probe).
3. If you have development dependencies (e.g., in `requirements-dev.txt` or as a `dev` extra), install them:
   *   Scan domains from a file `domains.txt` and save results to `results.csv`
4. Make your changes. Add tests for new functionality.
5. Ensure tests pass (e.g., `pytest -q`).
6. Format your code (e.g., using Black, Flake8 - consider pre-commit hooks).
7. Submit a pull request, clearly explaining the what and why of your changes.

*We aim to follow the Contributor Covenant code of conduct.*

## License

This project is licensed under the MIT License – see the `LICENSE` file for details.

## References

- SSLyze GitHub repo (fast TLS scanner)
- Google Public DNS over HTTPS (DoH) Documentation
- SSL Labs API Documentation (used by TLSProbe)
- Relevant RFCs: SPF (RFC7208), DMARC (RFC7489), DKIM (RFC6376), HSTS (RFC6797), CSP.
