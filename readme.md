# DQIX - Domain Quality Index 🚀

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue)](https://www.python.org)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)
[![Security](https://img.shields.io/badge/Security-A%2B-brightgreen)](SECURITY.md)
[![Coverage](https://img.shields.io/badge/Coverage-85%25-yellow)](tests/)

🔍 **Open-source Internet Measurement and Domain Quality Assessment Platform**

DQIX provides comprehensive, transparent domain security assessment with multi-language support, cutting-edge visualizations, and actionable insights. Unlike traditional tools, DQIX shows that different domains excel in different areas - no single domain dominates all security categories.

## 🌟 **Key Features**

### 🎯 **Transparent Measurements**
- **Multi-dimensional scoring** across TLS, DNS, HTTPS, and Security Headers
- **No built-in bias** - basic sites can excel in specific areas
- **Real-world validation** - tested against top domains worldwide
- **Clear weaknesses** - every domain has improvement areas

### 📊 **Cutting-Edge Visualizations**
- **Interactive dashboards** with real-time updates
- **3D security universe** visualization
- **Storytelling reports** with narrative-driven insights
- **Performance heatmaps** and trend forecasting

### 🌍 **Polyglot Architecture**
- **Python** (`dqix-python/`) - Full-featured reference implementation, installable as `dqix` package
- **Go** (`dqix-go/`) - High-performance concurrent scanning
- **Rust** (`dqix-rust/`) - Memory-safe, zero-cost abstractions
- **Haskell** (`dqix-haskell/`) - Pure functional with formal verification
- **C++** (`dqix-cpp/`) - Maximum performance with modern C++20 features
- **Bash** (`dqix-cli/`) - Universal compatibility and simplicity

See [POLYGLOT_ARCHITECTURE.md](POLYGLOT_ARCHITECTURE.md) for detailed information.

## ✅ **Implementation Status**

All language implementations are feature-complete with:
- ✅ Real network probes (TLS, DNS, HTTPS, Security Headers)
- ✅ 3-level security hierarchy (Critical, Important, Best Practices)
- ✅ Standardized scoring and weights
- ✅ Consistent output formats
- ✅ **NEW**: Performance optimizations with modern language features

See [PROJECT_STATUS.md](PROJECT_STATUS.md) for detailed status information.

## 🚀 **Performance Optimizations (v2.0)**

Each implementation has been optimized for maximum performance:
- **Python**: Async/await with uvloop, type hints, TaskGroup (3.11+)
- **Bash**: GNU Parallel, modern bash 4.4+ features
- **Go**: Bounded concurrency, HTTP/2, Go 1.21+ features
- **Rust**: Tokio async, zero-copy operations, Arc sharing
- **Haskell**: STM work-stealing, parallel strategies, strict evaluation
- **C++**: std::async, RAII, libcurl optimizations, modern C++20 features

See [OPTIMIZATION_REPORT.md](OPTIMIZATION_REPORT.md) for detailed benchmarks.

## 📈 **Performance**

| Implementation | Domains/min | Memory | Startup Time |
|---------------|-------------|---------|--------------|
| Python        | 100         | 40MB    | 200ms       |
| Go            | 400         | 20MB    | 50ms        |
| Rust          | 500         | 10MB    | 30ms        |
| Haskell       | 200         | 30MB    | 100ms       |
| Bash          | 50          | 5MB     | 10ms        |

## 🚀 **Quick Start**

### Installation

#### Python Package (Recommended)
```bash
# Install from PyPI
pip install dqix

# Or install with all features
pip install dqix[full]

# Or install from source
git clone https://github.com/phoneee/dqix
cd dqix
pip install -e .
```

#### Other Language Implementations
```bash
# Build Go implementation
cd dqix-go && go build -o dqix-go ./cmd/dqix/

# Build Rust implementation  
cd dqix-rust && cargo build --release

# Build Haskell implementation
cd dqix-haskell && cabal build

# Bash implementation (no build needed)
chmod +x dqix-cli/dqix-multi
```

### Basic Usage

#### Using Python Implementation (After pip install)
```bash
# Quick domain assessment
dqix scan github.com

# Compact output (70% smaller)
dqix scan github.com --compact

# Compare multiple domains
dqix compare github.com google.com cloudflare.com

# Generate storytelling report
dqix export github.com --format html --storytelling

# Launch interactive dashboard
dqix dashboard --port 8000
```

#### Using Other Language Implementations
```bash
# Go implementation
./dqix-go/dqix-go github.com

# Rust implementation
./dqix-rust/target/release/dqix github.com

# Haskell implementation
./dqix-haskell/dqix scan github.com

# Bash implementation
./dqix-cli/dqix-multi scan github.com
```

## 🔍 **Transparency Example**

Real assessment showing different domains excel in different areas:

```
🌈 DQIX Measurement Results:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

cloudflare.com (CDN Provider)     Overall: 88.5%
  🔐 TLS:      100% ██████████  Perfect implementation
  🌍 DNS:       97% █████████▓  Best-in-class
  🛡️ Headers:   57% █████▓░░░░  Room for improvement
  🌐 HTTPS:    100% ██████████  Excellent

github.com (Developer Platform)   Overall: 84.1%
  🔐 TLS:      100% ██████████  Modern protocols
  🌍 DNS:       82% ████████░░  Good, no IPv6
  🛡️ Headers:   55% █████▒░░░░  Basic protection
  🌐 HTTPS:    100% ██████████  Fast & secure

example.com (Basic Website)       Overall: 65.0%
  🔐 TLS:      100% ██████████  Surprisingly good!
  🌍 DNS:       88% ████████▓░  Well configured
  🛡️ Headers:    3% ░░░░░░░░░░  Needs attention
  🌐 HTTPS:     70% ███████░░░  Functional

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
✅ No single winner - each domain has unique strengths
```

## 🏗️ **Architecture**

DQIX follows Clean Architecture principles with Domain-Driven Design:

```
dqix/
├── domain/         # Core business logic (no dependencies)
├── application/    # Use cases and workflows
├── infrastructure/ # External integrations (probes, storage)
└── interfaces/     # User interfaces (CLI, API, dashboard)
```

### Key Design Principles:
- **Dependency Inversion** - Core doesn't depend on infrastructure
- **Single Responsibility** - Each module has one reason to change
- **Open/Closed** - Extensible without modification
- **Interface Segregation** - Small, focused interfaces
- **Liskov Substitution** - Implementations are interchangeable

## 🔒 **Security Features**

- ✅ **JWT Authentication** for API endpoints
- ✅ **SSL/TLS verification** enabled by default
- ✅ **Rate limiting** to prevent abuse
- ✅ **Input sanitization** for all user inputs
- ✅ **No hardcoded secrets** - environment-based config
- ✅ **CORS protection** with configurable origins
- ✅ **CSRF tokens** for state-changing operations

## 📊 **Assessment Probes**

### Level 1: Foundation Security (Critical)
- **TLS Probe**: SSL/TLS configuration, certificate validation, protocol versions
- **HTTPS Probe**: Accessibility, redirects, HSTS implementation

### Level 2: Infrastructure Security
- **DNS Probe**: DNSSEC, SPF, DMARC, DKIM, CAA records, IPv6 support

### Level 3: Application Security
- **Security Headers**: CSP, X-Frame-Options, X-Content-Type-Options, etc.

## 🎯 **Use Cases**

### Government & Public Sector
- Digital transformation assessment
- Compliance monitoring (NIST, CIS)
- Public service quality measurement

### Enterprise Security
- Domain portfolio assessment
- Security posture monitoring
- Vendor security evaluation

### Research & Academia
- Internet measurement studies
- Security trend analysis
- Educational demonstrations

## 🛠️ **Advanced Features**

### Performance Optimizations
- **Connection pooling** for network efficiency
- **Smart caching** with TTL for probe results
- **Concurrent execution** with adaptive limits
- **Streaming results** for large assessments

### Export Options
```bash
# HTML report with visualizations
dqix export domain.com --format html

# PDF for presentations
dqix export domain.com --format pdf

# JSON for analysis
dqix export domain.com --format json

# CSV for spreadsheets
dqix export domain.com --format csv
```

### Bulk Assessment
```bash
# Assess multiple domains
echo -e "github.com\ngoogle.com\ncloudflare.com" > domains.txt
dqix bulk domains.txt --concurrent 10 --output results.json
```

### Continuous Monitoring
```bash
# Monitor domains with alerts
dqix monitor domains.txt --interval 3600 --alert-threshold 0.7
```

## 📚 **Documentation**

- [Installation Guide](docs/installation.md)
- [API Reference](docs/api.md)
- [Architecture Overview](docs/architecture.md)
- [Security Analysis](SECURITY_ANALYSIS_REPORT.md)
- [Contributing Guide](CONTRIBUTING.md)
- [Polyglot Publishing](POLYGLOT_PUBLISHING_GUIDE.md)

## 🧪 **Testing**

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=dqix --cov-report=html

# Run specific test categories
pytest tests/test_probes.py -v
pytest tests/test_integration.py -v

# Run performance benchmarks
python benchmarks/run_benchmarks.py
```

## 🤝 **Contributing**

We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### Development Setup
```bash
# Clone repository
git clone https://github.com/phoneee/dqix
cd dqix

# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # or `.venv\Scripts\activate` on Windows

# Install development dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Run linters
ruff check .
mypy .
```

## 📈 **Roadmap**

- [x] Core assessment engine
- [x] Multi-language implementations
- [x] Security hardening
- [x] Transparent scoring system
- [x] Storytelling reports
- [ ] Machine learning insights
- [ ] Global measurement network
- [ ] Browser extension
- [ ] Mobile apps

## 📜 **License**

MIT License - see [LICENSE](LICENSE) file.

## 🙏 **Acknowledgments**

- Internet measurement community
- Security researchers worldwide
- Open source contributors
- OWASP for security guidelines

---

**🌟 Measuring the health of the web, transparently, in the open.**

DQIX - Where every domain's unique strengths are recognized and celebrated.