# DQIX User Manual

*Version 1.0 - June 2025*

## Table of Contents

1. [Quick Start Guide](#quick-start-guide)
2. [Installation](#installation)
3. [Command Reference](#command-reference)
4. [Output Formats](#output-formats)
5. [Measurement Criteria](#measurement-criteria)
6. [Performance Optimization](#performance-optimization)
7. [Integration Guide](#integration-guide)
8. [Examples & Use Cases](#examples--use-cases)

---

## Quick Start Guide

### **Basic Usage**
```bash
# Install DQIX
pip install dqix

# Assess a single domain
dqix assess example.com

# Get detailed analysis
dqix assess example.com --checklist --verbose --recommendations

# Compare domains
dqix compare google.com cloudflare.com github.com

# Bulk assessment
echo -e "google.com\ncloudflare.com\ngithub.com" > domains.txt
dqix bulk domains.txt --format csv
```

### **Key Features**
- 🔍 **Single Domain Assessment** - Comprehensive security analysis
- 📊 **Domain Comparison** - Side-by-side evaluation
- 📈 **Bulk Processing** - Large-scale assessment with concurrency
- 📋 **Detailed Checklists** - Comprehensive measurement breakdown
- 🎯 **Multiple Output Formats** - Rich, JSON, CSV, table, stdout
- ⚡ **High Performance** - Fast mode and concurrent execution

---

## Installation

### **Standard Installation**
```bash
pip install dqix
```

### **Development Installation**
```bash
git clone https://github.com/phoneee/dqix
cd dqix
pip install -e .
```

### **Docker Installation**
```dockerfile
FROM python:3.11-slim
RUN pip install dqix
ENTRYPOINT ["dqix"]
```

### **Requirements**
- Python 3.9 or higher
- Internet connectivity for domain testing
- 2GB RAM minimum (4GB recommended for bulk processing)

---

## Command Reference

### **1. Domain Assessment**

```bash
dqix assess <domain> [OPTIONS]
```

**Options:**
- `-v, --verbose` - Show detailed analysis
- `-t, --technical` - Include technical details  
- `--checklist` - Show measurement checklists
- `-r, --recommendations` - Show improvement recommendations
- `-f, --format {rich,json,table,csv,stdout}` - Output format
- `-s, --save` - Save results to file
- `--save-dir DIR` - Directory to save results
- `--timeout SECONDS` - Request timeout (default: 10)
- `-c, --comprehensive` - Run comprehensive analysis
- `--fast` - High-performance mode

**Examples:**
```bash
# Basic assessment
dqix assess example.com

# Full analysis with checklists
dqix assess example.com --checklist --verbose --recommendations

# JSON output for automation
dqix assess example.com --format json

# Fast assessment with CSV output
dqix assess example.com --fast --format csv

# Save detailed results
dqix assess example.com --save --save-dir ./security-reports
```

### **2. Domain Comparison**

```bash
dqix compare <domain1> <domain2> [domain3...] [OPTIONS]
```

**Options:**
- `-v, --verbose` - Show detailed comparison
- `--checklist` - Show measurement checklists
- `-f, --format {rich,json,table}` - Output format
- `-s, --save` - Save comparison results
- `--timeout SECONDS` - Request timeout

**Examples:**
```bash
# Compare security postures
dqix compare google.com microsoft.com apple.com

# Detailed comparison with checklists
dqix compare site1.com site2.com --checklist --verbose

# JSON output for analysis
dqix compare site1.com site2.com --format json --save
```

### **3. Bulk Assessment**

```bash
dqix bulk <file> [OPTIONS]
```

**Options:**
- `-f, --format {rich,json,csv}` - Output format
- `--save-dir DIR` - Directory to save results
- `-c, --concurrent NUM` - Concurrent assessments (default: 5)
- `--timeout SECONDS` - Request timeout
- `--summary/--no-summary` - Show summary statistics

**Supported File Formats:**
- **TXT**: One domain per line
- **CSV**: Domains in first column
- **JSON**: Array of domains or `{"domains": [...]}`

**Examples:**
```bash
# Assess domains from text file
dqix bulk domains.txt

# High-performance bulk assessment
dqix bulk domains.txt --concurrent 20 --format csv

# Bulk with summary statistics
dqix bulk domains.csv --summary --save-dir ./bulk-results
```

### **4. Probe Management**

```bash
dqix probes [OPTIONS]
```

**Options:**
- `-d, --detailed` - Show detailed probe information
- `-c, --category {security,performance,compliance}` - Filter by category

**Examples:**
```bash
# List all available probes
dqix probes

# Detailed probe information
dqix probes --detailed

# Security probes only
dqix probes --category security
```

---

## Output Formats

### **1. Rich Format (Default)**
Beautiful terminal output with colors, progress bars, and structured panels.

```bash
dqix assess example.com
```

**Features:**
- Color-coded scores and status indicators
- Progress bars for bulk operations
- Structured panels for different sections
- ASCII charts and visualizations
- Comprehensive error handling

### **2. JSON Format**
Machine-readable structured data for automation and integration.

```bash
dqix assess example.com --format json
```

**Schema:**
```json
{
  "domain": "example.com",
  "overall_score": 0.75,
  "compliance_level": "advanced",
  "timestamp": "2025-06-26T12:00:00",
  "probe_results": [
    {
      "probe_id": "tls",
      "score": 0.85,
      "category": "security",
      "technical_details": {...}
    }
  ],
  "category_scores": {
    "security": 0.80
  }
}
```

### **3. CSV Format**
Comma-separated values for spreadsheet analysis.

```bash
dqix assess example.com --format csv
```

**Output:**
```csv
domain,overall_score,compliance_level,probe_id,probe_score,probe_category
example.com,0.75,advanced,tls,0.85,security
example.com,0.75,advanced,dns,0.70,security
example.com,0.75,advanced,security_headers,0.65,security
```

### **4. Table Format**
Simple table for terminal display.

```bash
dqix assess example.com --format table
```

### **5. Stdout Format**
Tab-separated format for Unix pipes.

```bash
dqix assess example.com --format stdout
```

**Output:**
```
example.com	0.750	advanced
```

---

## Measurement Criteria

### **TLS Security (35% Weight)**

#### **Protocol Analysis**
- **TLS 1.3**: 10/10 points - Modern, secure protocol
- **TLS 1.2**: 8/10 points - Acceptable with proper configuration
- **TLS 1.1/1.0**: 0/10 points - Deprecated protocols
- **No TLS**: 0/10 points - Unencrypted communication

#### **Cipher Suite Evaluation**
- **Perfect Forward Secrecy**: ECDHE/DHE key exchange
- **Modern Encryption**: AES-GCM, ChaCha20-Poly1305
- **Strong Hash Functions**: SHA-256 or better
- **Weak Cipher Detection**: RC4, 3DES, NULL ciphers

#### **Certificate Validation**
- **Chain of Trust**: Valid CA signature path
- **Domain Validation**: Certificate matches requested domain
- **Expiration Status**: Valid time period
- **Key Strength**: RSA ≥2048 bits, ECC ≥256 bits

### **DNS Infrastructure (30% Weight)**

#### **Basic DNS Health**
- **IPv4/IPv6 Support**: A and AAAA record availability
- **Nameserver Redundancy**: Multiple authoritative servers
- **Response Performance**: Sub-second resolution times

#### **Email Security**
- **SPF Records**: Sender Policy Framework configuration
  - `-all` (strict): 4/4 points
  - `~all` (soft): 2/4 points
  - Missing: 0/4 points
  
- **DMARC Policy**: Domain-based Message Authentication
  - `p=reject`: 4/4 points
  - `p=quarantine`: 2/4 points
  - `p=none` or missing: 0/4 points

- **DKIM Support**: DomainKeys Identified Mail selectors

#### **Advanced Security Features**
- **DNSSEC**: DNS Security Extensions validation
- **CAA Records**: Certificate Authority Authorization

### **HTTP Security Headers (35% Weight)**

#### **Critical Headers**
- **HSTS**: HTTP Strict Transport Security
  - Long max-age + includeSubDomains + preload: 8/8 points
  - Basic implementation: 4/8 points
  
- **CSP**: Content Security Policy
  - Restrictive policy without unsafe directives: 8/8 points
  - Basic policy: 3/8 points
  
- **X-Frame-Options**: Clickjacking protection
  - DENY: 4/4 points
  - SAMEORIGIN: 3/4 points

#### **Important Headers**
- **X-Content-Type-Options**: MIME sniffing prevention
- **Referrer-Policy**: Referrer information control
- **Permissions-Policy**: Browser feature restrictions

#### **Information Disclosure Assessment**
- **Server Headers**: Technology stack disclosure (-2 points)
- **X-Powered-By**: Framework disclosure (-2 points)

---

## Performance Optimization

### **High-Performance Mode**
```bash
dqix assess example.com --fast
```

**Benefits:**
- Removes progress tracking overhead
- Optimized network operations
- Minimal terminal output
- Direct result display

### **Concurrent Processing**
```bash
dqix bulk domains.txt --concurrent 20
```

**Guidelines:**
- **Local testing**: 5-10 concurrent connections
- **Server deployment**: 20-50 concurrent connections
- **Network considerations**: Monitor bandwidth usage
- **Rate limiting**: Respect target server limits

### **Timeout Optimization**
```bash
# Fast failures for quick scanning
dqix assess example.com --timeout 5

# Extended timeout for slow networks
dqix assess example.com --timeout 30
```

### **Memory Management**
- **Bulk processing**: Results are streamed to avoid memory buildup
- **Large datasets**: Use file outputs instead of terminal display
- **Resource cleanup**: Automatic cleanup of network connections

---

## Integration Guide

### **Python API Usage**
```python
import asyncio
from dqix.application.use_cases import DomainAssessmentUseCase
from dqix.infrastructure.factory import create_infrastructure

async def assess_domain(domain_name):
    infrastructure = create_infrastructure()
    use_case = DomainAssessmentUseCase(infrastructure)
    result = await use_case.assess_domain(domain_name, timeout=10)
    return result

# Example usage
result = asyncio.run(assess_domain("example.com"))
print(f"Score: {result['overall_score']}")
```

### **CI/CD Integration**

#### **GitHub Actions**
```yaml
name: Domain Security Assessment
on: [push, pull_request]

jobs:
  security-assessment:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Setup Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.11'
      
      - name: Install DQIX
        run: pip install dqix
      
      - name: Assess Domain Security
        run: |
          dqix assess ${{ github.event.repository.name }} \
            --format json \
            --save \
            --save-dir ./security-reports
      
      - name: Upload Results
        uses: actions/upload-artifact@v3
        with:
          name: security-assessment
          path: ./security-reports/
```

#### **Jenkins Pipeline**
```groovy
pipeline {
    agent any
    stages {
        stage('Domain Security Assessment') {
            steps {
                sh 'pip install dqix'
                sh '''
                    dqix bulk domains.txt \
                        --format csv \
                        --save-dir ./reports \
                        --concurrent 10
                '''
                archiveArtifacts artifacts: 'reports/**/*'
            }
        }
    }
}
```

### **Database Integration**
```bash
# Export to database via JSON
dqix assess example.com --format json | \
  jq '.probe_results[] | {domain: .domain, probe: .probe_id, score: .score}' | \
  psql -d database -c "COPY assessment_results FROM STDIN WITH CSV HEADER"
```

### **Monitoring Integration**
```python
# Custom monitoring integration
import json
import subprocess

def monitor_domain_security(domain):
    result = subprocess.run(
        ['dqix', 'assess', domain, '--format', 'json'],
        capture_output=True, text=True
    )
    
    data = json.loads(result.stdout)
    score = data['overall_score']
    
    # Send to monitoring system
    if score < 0.7:
        send_alert(f"Domain {domain} security score below threshold: {score}")
    
    return data
```

---

## Examples & Use Cases

### **1. Security Auditing**
```bash
# Comprehensive security assessment
dqix assess company.com \
  --checklist \
  --verbose \
  --recommendations \
  --save \
  --save-dir ./audit-2025

# Compare with competitors
dqix compare company.com competitor1.com competitor2.com \
  --checklist \
  --format json \
  --save
```

### **2. Compliance Monitoring**
```bash
# Regular compliance checks
dqix bulk compliance-domains.txt \
  --format csv \
  --concurrent 15 \
  --save-dir ./compliance-reports

# Generate compliance report
dqix assess internal-app.company.com \
  --comprehensive \
  --checklist \
  --format json > compliance-report.json
```

### **3. Migration Validation**
```bash
# Before migration
dqix assess old-domain.com --save --save-dir ./pre-migration

# After migration  
dqix assess new-domain.com --save --save-dir ./post-migration

# Compare results
dqix compare old-domain.com new-domain.com --verbose
```

### **4. Security Research**
```bash
# Large-scale analysis
dqix bulk top-1000-domains.txt \
  --concurrent 50 \
  --format csv \
  --save-dir ./research-data

# Statistical analysis
dqix bulk government-domains.txt \
  --format json \
  --save-dir ./gov-analysis \
  --summary
```

### **5. DevOps Integration**
```bash
# Pre-deployment check
dqix assess staging.app.com --fast --format stdout | \
  awk '{if($2 < 0.8) exit 1}' || echo "Security check failed"

# Post-deployment validation
dqix assess prod.app.com \
  --checklist \
  --recommendations \
  --save \
  --save-dir ./deployment-validation
```

### **6. Continuous Monitoring**
```bash
#!/bin/bash
# Weekly security monitoring script

DOMAINS="app.com api.app.com admin.app.com"
DATE=$(date +%Y-%m-%d)

for domain in $DOMAINS; do
  echo "Assessing $domain..."
  dqix assess $domain \
    --format json \
    --save \
    --save-dir "./monitoring/$DATE"
done

# Generate summary report
dqix bulk <(echo "$DOMAINS" | tr ' ' '\n') \
  --format csv \
  --save-dir "./monitoring/$DATE"
```

---

## Performance Benchmarks

### **Single Domain Assessment**
- **Standard mode**: ~2-5 seconds per domain
- **Fast mode**: ~1-3 seconds per domain
- **Comprehensive mode**: ~5-10 seconds per domain

### **Bulk Assessment Performance**
- **5 concurrent**: ~100 domains/minute
- **20 concurrent**: ~300 domains/minute  
- **50 concurrent**: ~500 domains/minute (server-grade hardware)

### **Memory Usage**
- **Single assessment**: ~50MB RAM
- **Bulk assessment**: ~100-200MB RAM (streaming results)
- **Large datasets (1000+ domains)**: ~300-500MB RAM

---

## Best Practices

### **1. Security Assessment**
- Use `--checklist` for detailed security analysis
- Include `--recommendations` for actionable improvements
- Save results with `--save` for historical tracking
- Use `--comprehensive` for critical infrastructure

### **2. Performance Optimization**
- Start with low concurrency (5) and increase gradually
- Use `--fast` mode for quick checks
- Adjust `--timeout` based on network conditions
- Monitor target server response times

### **3. Data Management**
- Use JSON format for programmatic processing
- Use CSV format for spreadsheet analysis
- Organize results by date and purpose
- Implement result archival for historical analysis

### **4. Automation Integration**
- Use `stdout` format for Unix pipes
- Implement error handling for failed assessments
- Set up automated alerts for low scores
- Create dashboard integration for ongoing monitoring

---

*Last Updated: June 2025*  
*For support and updates, visit: [GitHub Repository](https://github.com/phoneee/dqix)* 