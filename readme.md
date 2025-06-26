# 🔍 DQIX - Domain Quality Index

**Advanced domain assessment and analysis tool with clean architecture**

DQIX is a comprehensive Python library for measuring domain quality, security, and compliance. Built with clean architecture principles, it provides detailed analysis of domains through various probes and generates actionable insights.

## ✨ Features

### 🚀 Enhanced CLI Interface
- **Detailed Analysis**: Comprehensive probe results with scoring and recommendations
- **Multiple Output Formats**: Table, JSON, and chart visualizations
- **Bulk Assessment**: Process multiple domains from files with progress tracking
- **Domain Comparison**: Side-by-side analysis of multiple domains
- **Visualization**: ASCII charts, graphs, and dashboard-style output
- **Export Capabilities**: Save results in JSON, CSV, and detailed reports

### 🔬 Assessment Capabilities
- **TLS/SSL Security**: Certificate validation, protocol analysis, cipher strength
- **DNS Security**: DNSSEC validation, CAA records, DNS configuration
- **Security Headers**: HSTS, CSP, X-Frame-Options, and other security headers
- **Compliance Levels**: Basic, Enhanced, and Critical Infrastructure compliance
- **Scoring System**: 0-100 scoring with detailed breakdown

### 📊 Visualization & Reporting
- **Interactive Charts**: Bar charts, histograms, pie charts, radar charts
- **Performance Matrix**: Cross-domain probe comparison
- **Dashboard Views**: Comprehensive assessment summaries
- **Trend Analysis**: Performance trends across multiple assessments
- **Real-time Progress**: Live progress indicators for bulk operations

## 🛠️ Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/dqix.git
cd dqix

# Install dependencies
pip install -e .

# Or install from PyPI (when available)
pip install dqix
```

## 🚀 Quick Start

### Single Domain Assessment

```bash
# Basic assessment
python -m dqix assess example.com

# Detailed analysis with recommendations
python -m dqix assess example.com --verbose --detailed --recommendations

# Chart visualization
python -m dqix assess example.com --format chart

# Save results
python -m dqix assess example.com --save results.json
```

### Bulk Domain Assessment

```bash
# Assess multiple domains from file
python -m dqix assess-bulk domains.txt

# Detailed bulk analysis with comparison
python -m dqix assess-bulk domains.txt --verbose --compare

# Generate comprehensive report
python -m dqix assess-bulk domains.txt --report bulk_report.json

# Save individual results
python -m dqix assess-bulk domains.txt --save-dir ./results/
```

### Domain Comparison

```bash
# Compare multiple domains
python -m dqix compare google.com github.com stackoverflow.com

# Detailed comparison with verbose output
python -m dqix compare google.com example.com --verbose

# Save comparison results
python -m dqix compare domain1.com domain2.com --save comparison.json
```

### Available Probes

```bash
# List all available probes
python -m dqix list-probes

# Detailed probe information
python -m dqix list-probes --detailed

# Filter by category
python -m dqix list-probes --category security
```

## 📈 Advanced Examples

### Bulk Assessment with Visualization

```python
from examples.advanced_bulk_assessment import BulkAssessmentAnalyzer

# Create analyzer
analyzer = BulkAssessmentAnalyzer()

# Load domains from CSV
domains = analyzer.load_domains_from_csv("domains.csv")

# Assess with progress tracking
results = await analyzer.assess_domains_with_progress(domains)

# Generate comprehensive analysis
analysis = analyzer.analyze_results(results)

# Create visual summary
analyzer.print_visual_summary(analysis)

# Export results
analyzer.export_results(results, analysis)
```

### Visualization Dashboard

```python
from examples.visualization_demo import DomainAssessmentVisualizer

visualizer = DomainAssessmentVisualizer()

# Create various visualizations
bar_chart = visualizer.create_score_bar_chart(results)
matrix = visualizer.create_probe_performance_matrix(results)
dashboard = visualizer.create_comparison_dashboard(results)

print(bar_chart)
print(matrix)
print(dashboard)
```

## 📊 Sample Output

### Enhanced CLI Assessment
```
🔍 Domain Assessment Report
═══════════════════════════════════════════════════════════════════════════════════
Domain: example.com
Timestamp: 2025-01-27 10:30:45
Overall Score: 85.3/100
Compliance Level: Enhanced

████████████████████████████████████████████████████████████████████████████████████ 85.3/100

📊 Probe Analysis Results
┏━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━┳━━━━━━━━━━┳━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Probe              ┃ Category      ┃ Score    ┃ Status     ┃ Details                      ┃
┡━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━╇━━━━━━━━━━╇━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ TLS_Probe          │ Security      │ 90.0     │ ✅ Success │ No issues detected           │
│ DNS_Probe          │ Security      │ 85.5     │ ✅ Success │ No issues detected           │
│ SecurityHeaders    │ Security      │ 80.5     │ ✅ Success │ Missing some headers         │
└────────────────────┴───────────────┴──────────┴────────────┴──────────────────────────────┘

💡 Recommendations:
  🛡️ Implement additional security headers
  🔒 Consider upgrading TLS configuration and certificates
```

### Bulk Assessment Dashboard
```
🖥️ DOMAIN ASSESSMENT DASHBOARD
════════════════════════════════════════════════════════════════════════════════════════════════════
Generated: 2025-01-27 10:35:22
Domains Assessed: 10

📊 SUMMARY STATISTICS
──────────────────────────────────────────────────────
Average Score:     82.45
Highest Score:     95.20
Lowest Score:      65.30
Score Range:       29.90

🏆 TOP PERFORMERS
──────────────────────────────
1. google.com          95.2
2. github.com           88.7
3. cloudflare.com       86.4

⚠️ NEEDS ATTENTION
──────────────────────────────
1. example.org          65.3
2. httpstat.us          72.1
3. httpbin.org          74.8
```

## 🏗️ Architecture

DQIX follows clean architecture principles with clear separation of concerns:

```
dqix/
├── domain/           # Business logic and entities
├── application/      # Use cases and orchestration
├── infrastructure/   # External services and probes
└── interfaces/       # CLI and user interaction
```

### Key Components

- **Domain Layer**: Core business entities and rules
- **Application Layer**: Use cases that orchestrate domain operations
- **Infrastructure Layer**: Probes, repositories, and external services
- **Interface Layer**: CLI commands and user interactions

## 🔧 Configuration

### Probe Configuration

```python
from dqix.domain.entities import ProbeConfig

config = ProbeConfig(
    timeout=30,              # Request timeout in seconds
    retry_count=2,           # Number of retries
    cache_enabled=True,      # Enable result caching
    max_concurrent=10        # Maximum concurrent operations
)
```

### Custom Probes

```python
from dqix.infrastructure.probes.base import BaseProbe
from dqix.domain.entities import ProbeCategory

class CustomProbe(BaseProbe):
    probe_id = "custom_probe"
    category = ProbeCategory.SECURITY
    
    async def execute(self, domain: str, config: ProbeConfig) -> ProbeResult:
        # Your custom probe logic here
        pass
```

## 📋 File Formats

### Domain Lists (TXT)
```
# Comments start with #
google.com
github.com
example.com
```

### Domain Lists (CSV)
```csv
domain,category,description,priority
google.com,tech,Search engine,high
github.com,tech,Code repository,medium
example.com,demo,Example domain,low
```

### Domain Lists (JSON)
```json
{
  "domains": [
    {
      "domain": "google.com",
      "category": "tech",
      "description": "Search engine",
      "priority": "high"
    }
  ]
}
```

## 🧪 Development

### Running Tests

```bash
# Run all tests
make test

# Run with coverage
make test-coverage

# Run specific test
pytest tests/test_cli.py -v
```

### Code Quality

```bash
# Lint code
make lint

# Format code
make format

# Type checking
make type-check

# Security scan
make security-check
```

### Development Setup

```bash
# Install development dependencies
make dev-setup

# Install pre-commit hooks
make install-hooks

# Run quality checks
make quality
```

## 📚 Documentation

### **📖 Complete Documentation**
- **[User Manual](docs/USER_MANUAL.md)** - Comprehensive usage guide with examples
- **[FAQ](docs/FAQ.md)** - Frequently asked questions & troubleshooting
- **[Domain Quality Principles](docs/DOMAIN_QUALITY_INDEX_PRINCIPLES.md)** - Academic standards & measurement criteria

### **🚀 Quick Navigation**
- **[Quick Start Guide](docs/USER_MANUAL.md#quick-start-guide)** - Get started in 5 minutes
- **[Command Reference](docs/USER_MANUAL.md#command-reference)** - Complete CLI documentation
- **[Output Formats](docs/USER_MANUAL.md#output-formats)** - Rich, JSON, CSV, table, stdout
- **[Performance Guide](docs/USER_MANUAL.md#performance-optimization)** - Speed up assessments
- **[Integration Examples](docs/USER_MANUAL.md#integration-guide)** - CI/CD, APIs, monitoring

### **🎯 Common Use Cases**
- **Security Auditing**: `dqix assess domain.com --checklist --recommendations`
- **Bulk Analysis**: `dqix bulk domains.txt --concurrent 20 --format csv`
- **Domain Comparison**: `dqix compare site1.com site2.com --verbose`
- **Automation**: `dqix assess domain.com --format json | jq '.overall_score'`

---

## 🤝 Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### Development Workflow

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Run quality checks: `make quality`
6. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Built with clean architecture principles
- Inspired by domain-driven design
- Uses modern Python async/await patterns
- Rich CLI interface powered by [Typer](https://typer.tiangolo.com/) and [Rich](https://rich.readthedocs.io/)

---

**DQIX**: Measuring domain quality, together, in the open. 🌐✨
