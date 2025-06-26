# DQIX - Domain Quality Index 🚀

🔍 **Open-source Internet Measurement and Domain Quality Assessment Platform**

DQIX is a comprehensive, open-source tool for measuring domain security, performance, and compliance with integration to multiple Internet measurement platforms and OpenData sources.

## ✨ **Enhanced Features**

### 🌐 **Interactive Internet Observability Dashboard**
- **Real-time domain assessment** with interactive visualizations
- **OpenData correlation** from RIPE Atlas, BGP Stream, Cloudflare Radar, Google Transparency
- **Global Internet health monitoring** inspired by [IODA](https://ioda.inetintel.cc.gatech.edu/) and [IHR](https://ihr.iijlab.net/ihr/en-us)
- **Threat intelligence integration** for security correlation
- **Historical trend analysis** with time-series data

### 📄 **Internet Measurement Reports**
- **Print-ready HTML reports** optimized for professional documentation
- **Multi-format export**: HTML, PDF, PNG, JSON, CSV
- **Professional templates** for government and enterprise use
- **Comprehensive analysis** with OpenData correlation

## 🚀 **Quick Start**

### Installation
```bash
# Basic installation
pip install -e .

# With dashboard dependencies
pip install flask plotly pandas dash dash-bootstrap-components

# With export dependencies  
pip install matplotlib weasyprint
```

### Basic Usage
```bash
# Quick domain assessment
python -m dqix assess github.com

# Launch Interactive Dashboard
python -m dqix dashboard

# Generate Internet Measurement Report
python -m dqix export github.com --format html --print

# Compare multiple domains
python -m dqix compare google.com github.com cloudflare.com
```

## 🌐 **Internet Observability Dashboard**

Launch the interactive dashboard for comprehensive Internet measurement:

```bash
python -m dqix dashboard --port 5000
```

**Features:**
- **🔍 Domain Assessment**: Real-time security and performance analysis
- **🌍 Global Internet Health**: Worldwide connectivity monitoring  
- **🛡️ Threat Intelligence**: Security correlation and alerts
- **📊 OpenData Correlation**: Multi-source data integration
- **🕒 Historical Analysis**: Trend analysis and pattern recognition

**OpenData Sources:**
- **RIPE Atlas**: Global Internet measurement network
- **BGP Stream**: BGP routing data and events  
- **Cloudflare Radar**: Internet traffic and attack insights
- **Google Transparency**: Safe browsing and malware data

## 📄 **Export & Reporting**

Generate professional Internet Measurement Reports:

```bash
# HTML report with print optimization
python -m dqix export example.com --format html --print

# PDF report for presentations  
python -m dqix export example.com --format pdf --comprehensive

# JSON data for analysis
python -m dqix export example.com --format json --comprehensive
```

**Report Features:**
- Professional design with responsive CSS
- Print-optimized formatting
- Security score visualization
- Detailed probe analysis
- Improvement recommendations
- OpenData correlation results

## 🔬 **Assessment Probes**

DQIX includes security-focused probes prioritized by importance:

### **Level 1: Foundation Security (Critical)**
- **TLS Probe**: SSL/TLS configuration and certificate validation
- **HTTPS Probe**: HTTPS accessibility and redirect analysis

### **Level 2: Infrastructure Security**  
- **DNS Probe**: DNS records, SPF, DMARC, DNSSEC validation

### **Level 3: Application Security**
- **Security Headers Probe**: HTTP security headers analysis

View available probes:
```bash
python -m dqix probes --detailed
```

## 🌍 **Multi-Language Architecture**

DQIX supports multiple implementation languages for different use cases:

```bash
# Python implementation (current)
python -m dqix assess example.com

# Future: Go implementation (high performance)
dqix-go assess example.com  

# Future: Rust implementation (memory safety)
dqix-rust assess example.com

# Multi-language coordinator
dqix-multi --language all example.com
```

## 🔧 **API Integration**

When dashboard is running, access RESTful API:

```bash
# Assess domain via API
curl http://localhost:5000/api/assess/example.com

# Start monitoring
curl -X POST -H "Content-Type: application/json" \
  -d '{"domains": ["example.com"], "interval": 3600}' \
  http://localhost:5000/api/monitor/start
```

## 📊 **Bulk Assessment**

Assess multiple domains efficiently:

```bash
# Create domains file
echo -e "google.com\ngithub.com\ncloudflare.com" > domains.txt

# Bulk assessment
python -m dqix bulk domains.txt --format csv --concurrent 10

# Generate bulk reports
python -m dqix bulk domains.txt --format html --print
```

## 🎯 **Use Cases**

### **Government & Public Sector**
- **Digital transformation assessment**
- **Cybersecurity compliance monitoring**  
- **Public service quality measurement**
- **Critical infrastructure monitoring**

### **Enterprise Security**
- **Domain portfolio assessment**
- **Security posture monitoring**
- **Compliance reporting**
- **Threat intelligence correlation**

### **Research & Academia**
- **Internet measurement research**
- **OpenData analysis**
- **Global connectivity studies**
- **Security trend analysis**

## 🔍 **Examples**

### Interactive Dashboard
```bash
# Start dashboard with auto-open
python -m dqix dashboard --port 8080 --auto-open

# Debug mode for development
python -m dqix dashboard --debug --no-auto-open
```

### Professional Reports
```bash
# Government domain assessment
python -m dqix export mof.go.th --format html --print --comprehensive

# University security analysis  
python -m dqix export ku.ac.th --format pdf --template report

# Financial institution audit
python -m dqix export scb.co.th --format html --print --comprehensive
```

### OpenData Correlation
```bash
# Assess with comprehensive correlation
python -m dqix assess example.com --comprehensive --recommendations

# Compare with correlation data
python -m dqix compare site1.com site2.com --checklist --verbose
```

## 🏗️ **Architecture**

DQIX follows Clean Architecture principles:

- **Domain Layer**: Core business logic and entities
- **Application Layer**: Use cases and orchestration
- **Infrastructure Layer**: External services and I/O  
- **Interface Layer**: CLI, Dashboard, API

## 📚 **Documentation**

```bash
# Show examples
python -m dqix examples

# View documentation
python -m dqix docs

# Comprehensive manual
python -m dqix man
```

## 🤝 **Contributing**

DQIX is open-source and welcomes contributions:

1. Fork the repository
2. Create feature branch
3. Add tests and documentation
4. Submit pull request

## 📜 **License**

Open source under MIT License - see [LICENSE](LICENSE) file.

---

**🌟 Measuring the health of the web, together, in the open.**

DQIX combines domain quality assessment with Internet observability, providing comprehensive insights through OpenData correlation and interactive visualization for better Internet health understanding.
