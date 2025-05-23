# Domain Quality Index (DQIX) – Project Principles

## Vision

Build an open-source, transparent, and reproducible **Domain Quality Index (DQIX)** that _measures the internet's performance, affordability, and trustworthiness_. Our goal is to provide a vendor-neutral benchmark that empowers governments, public services, researchers, and the wider internet community to understand and improve everyday access to a faster, more affordable, and more reliable web.

## Mission

1. Leverage exclusively open data and open-source tooling to produce a composite score that captures three pillars of digital inclusion: **Performance** (speed, reliability, resiliency), **Affordability** (cost-efficient delivery, lightweight design), and **Trustworthiness** (security, privacy, transparency).
2. Maintain a modular, probe-centric architecture that enables anyone to add, audit, or refine individual checks without touching core logic—promoting community innovation and scientific reproducibility.
3. Provide actionable, privacy-respecting recommendations that help governments, network operators, and website owners lower access costs, increase speed, and strengthen user trust across the public internet.

## Core Principles

| # | Principle | Rationale |
|---|-----------|-----------|
| 1 | **Open by Default** | All code, documentation, and data formats are released under OSI-approved licenses. Proprietary dependencies are avoided unless a permissive alternative is impossible. |
| 2 | **Transparency & Reproducibility** | Every probe publishes its algorithm, weight, and data sources. Anyone should be able to reproduce a score with the same inputs. |
| 3 | **Vendor Neutrality** | Results should not depend on paid APIs or rate-limited SaaS. We benchmark against commercial scores but do not embed them. |
| 4 | **Privacy & Ethics** | No invasive tracking. Scans must respect robots.txt, legal boundaries, and exclude personal data unless explicit consent is given. |
| 5 | **Modularity** | Each probe lives in its own file, follows a common interface, and can be enabled/disabled independently. Utilities are shared in focused packages (`utils/`). |
| 6 | **Community Driven** | New features, weights, and probes are proposed through public discussions. A lightweight governance model decides on strategic direction. |
| 7 | **Accessibility & Internationalization** | CLI output, reports, and documentation follow accessibility best practices and support multiple languages where possible. |
| 8 | **Progressive Enhancement** | Start simple, ship early, iterate. Complexity (e.g., async DNS, distributed crawling) is added only when clearly justified. |
| 9 | **Testability** | Every probe includes unit tests and, where feasible, integration tests with disposable fixtures or public test domains. |
| 10 | **Sustainability** | Favor efficient algorithms, minimal external calls, and cache reuse to reduce energy consumption and API load. |

## Design Goals

1. **Probe-Centric Architecture** — The `probes/` folder contains self-contained checks registered via a decorator. Adding a new probe is a three-step process: create file, inherit `Probe`, call `@register`.
2. **Structured Output** — Scores, raw evidence, and metadata are exported as JSON first-class objects, enabling downstream integrations (dashboards, data warehouses).
3. **CLI First** — A friendly command-line interface (`dqix` executable) offers sensible defaults, verbosity levels, and progress bars.
4. **Extensible Integrations** — Output modules (`output/`) and preset configurations (`presets/`) allow organisations to tailor scoring and reporting.
5. **Stateless Core** — The library itself has no persistent state; caching layers (`storage/`) are pluggable.

## Scope

Included:
- DNS, TLS, HTTP, WHOIS, and email security probes
- Accessibility, privacy, and transparency checks
- Basic report generation (JSON, CSV, HTML)
- Open data only (e.g., public DNS queries, HTTP headers)

Out of Scope (for now):
- Active vulnerability scanning
- Paid backlink databases
- Full crawler-based content indexing

## Non-Goals

- Compete feature-for-feature with commercial SEO suites
- Store or monetise user data
- Replace formal security audits

## Contribution Workflow (High-Level)

1. Fork repository & create a feature branch.
2. Add or modify probes, utilities, or documentation.
3. Include/adjust tests under `tests/` and ensure `make test` passes.
4. Open a Pull Request referencing any relevant issues.
5. A maintainer reviews for style, security, and principle compliance.

Detailed steps live in **CONTRIBUTING.md**.

## Roadmap Pillars (2025)

1. **MVP Score 0.1** — Replicate core aspects of Ahrefs DR using public backlink counts (e.g., Common Crawl, Open PageRank).
2. **Public Dataset Release** — Publish periodic snapshots of DQIX scores for `.go.th` and `.ac.th` domains.
3. **Web Dashboard** — Minimal read-only dashboard powered by static JSON.
4. **Plugin SDK** — Allow third-party probes to register outside core repo.
5. **International Expansion** — Add presets and translations for additional ccTLDs and languages.

---
_Project tagline_: **"Measuring the health of the web, together, in the open."**

_Updated tagline_: **"Measuring internet performance, affordability & trustworthiness — together, in the open."** 