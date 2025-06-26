# DQIX - Frequently Asked Questions (FAQ)

## 📋 General Questions

### **Q: What is Domain Quality Index (DQIX)?**
**A:** DQIX is an open-source library that measures domain security, accessibility, and governance compliance using academic standards and transparent methodologies. It provides a vendor-neutral alternative to commercial domain scoring tools.

### **Q: How does DQIX scoring compare to commercial tools like Ahrefs DR or Moz DA?**
**A:** DQIX focuses on security and compliance rather than SEO metrics. Our scoring is based on measurable technical criteria (TLS security, DNS configuration, HTTP headers) rather than backlink analysis. Results are reproducible and transparent.

### **Q: What data sources does DQIX use?**
**A:** DQIX uses only open data:
- Direct protocol testing (TLS, DNS, HTTP)
- Public DNS records
- Certificate transparency logs
- Open web standards compliance
- No proprietary databases or paid APIs

---

## 🔧 Installation & Setup

### **Q: How do I install DQIX?**
**A:** Install using pip:
```bash
pip install dqix
```

For development:
```bash
git clone https://github.com/dqix/dqix
cd dqix
pip install -e .
```

### **Q: What are the system requirements?**
**A:** 
- Python 3.9 or higher
- 2GB RAM minimum (4GB recommended for bulk processing)
- Internet connectivity for domain testing
- Optional: Docker for containerized deployment

### **Q: I'm getting SSL/TLS certificate errors. How do I fix this?**
**A:** Common solutions:
1. Check your system's certificate store: `python -m certifi`
2. Update certificates: `pip install --upgrade certifi`
3. Check corporate firewall/proxy settings
4. Use `--timeout` option for slow networks

---

## 📊 Usage & Commands

### **Q: How do I assess a single domain?**
**A:** Basic assessment:
```bash
dqix assess example.com
```

Detailed analysis with checklists:
```bash
dqix assess example.com --checklist --verbose --recommendations
```

### **Q: How do I compare multiple domains?**
**A:** 
```bash
dqix compare google.com cloudflare.com github.com --checklist
```

### **Q: How do I assess domains in bulk?**
**A:** Create a file with domains (one per line) and run:
```bash
dqix bulk domains.txt --format csv --concurrent 10
```

Supported file formats: TXT, CSV, JSON

### **Q: What output formats are available?**
**A:** 
- `rich` (default) - Beautiful terminal output with colors
- `json` - Machine-readable structured data
- `table` - Simple table format
- `csv` - Comma-separated values for spreadsheets
- `stdout` - Tab-separated for Unix pipes

### **Q: How do I save results to files?**
**A:** Use the `--save` flag:
```bash
dqix assess example.com --save --save-dir ./results
```

---

## 🔍 Measurement Details

### **Q: What does the overall score represent?**
**A:** The overall score (0.0-1.0) is a weighted average:
- TLS Security: 35%
- DNS Infrastructure: 30%  
- HTTP Security Headers: 35%

Each component is scored against academic standards and best practices.

### **Q: What are the compliance levels?**
**A:**
- **Excellent (90-100)**: Industry-leading security
- **Advanced (80-89)**: Strong security posture
- **Standard (60-79)**: Basic security measures
- **Basic (40-59)**: Significant improvements needed
- **Poor (0-39)**: Critical vulnerabilities

### **Q: Why did my domain score low on DNS?**
**A:** Common reasons:
- Missing SPF/DMARC email security records
- No DNSSEC implementation
- Missing CAA (Certificate Authority Authorization) records
- Single point of failure (only one nameserver)

### **Q: What are the most important security headers?**
**A:** Critical headers for high scores:
1. **HSTS** - Prevents SSL stripping attacks
2. **CSP** - Prevents XSS and injection attacks
3. **X-Frame-Options** - Prevents clickjacking
4. **X-Content-Type-Options** - Prevents MIME sniffing

### **Q: Why doesn't my high-security site score well?**
**A:** DQIX measures specific technical implementations. A site might be secure but lack:
- Proper HTTP security headers
- DNSSEC validation
- Email authentication records
- Modern TLS configuration

---

## ⚡ Performance & Optimization

### **Q: How can I speed up assessments?**
**A:** Use performance options:
```bash
# Fast mode (no progress tracking)
dqix assess example.com --fast

# Bulk with high concurrency
dqix bulk domains.txt --concurrent 20

# Reduce timeout for faster failures
dqix assess example.com --timeout 5
```

### **Q: How many domains can I assess simultaneously?**
**A:** Recommended concurrency levels:
- Local testing: 5-10 concurrent
- Server deployment: 20-50 concurrent
- Respect rate limits and target infrastructure

### **Q: My assessments are timing out. What should I do?**
**A:** 
1. Increase timeout: `--timeout 30`
2. Check network connectivity
3. Try different DNS servers
4. Verify domains are accessible

---

## 🛠️ Troubleshooting

### **Q: I get "ModuleNotFoundError" when running DQIX.**
**A:** Common solutions:
1. Ensure proper installation: `pip install dqix`
2. Check Python path: `python -c "import dqix; print(dqix.__file__)"`
3. Use virtual environment: `python -m venv venv && source venv/bin/activate`

### **Q: Bulk assessment fails with some domains.**
**A:** This is normal. DQIX handles errors gracefully:
- Check the error messages in output
- Verify domain spelling and availability
- Some domains may block automated scanning
- Use `--summary` to see success/failure statistics

### **Q: DNS resolution fails for local domains.**
**A:** For internal/local domains:
1. Ensure DNS server can resolve the domain
2. Check network connectivity
3. Consider using public DNS (8.8.8.8) for testing
4. Some corporate networks block external DNS queries

### **Q: TLS probe returns "local_handshake" error.**
**A:** This indicates TLS negotiation failed:
1. Domain may not support HTTPS
2. Certificate might be invalid/expired
3. Network/firewall issues
4. Try with `--timeout` increase

---

## 🔧 Advanced Configuration

### **Q: Can I customize scoring weights?**
**A:** Currently, scoring weights are fixed based on academic research. Custom weights may be added in future versions. You can:
1. Fork the repository and modify scoring logic
2. Create custom probe implementations
3. Use JSON output for custom analysis

### **Q: How do I add custom probes?**
**A:** Create a new probe class:
```python
from dqix.infrastructure.probes.base import BaseProbe

class CustomProbe(BaseProbe):
    probe_id = "custom"
    category = ProbeCategory.SECURITY
    
    async def run(self, domain: str) -> Tuple[float, Dict[str, Any]]:
        # Your custom logic here
        return score, details
```

### **Q: Can I run DQIX in Docker?**
**A:** Yes, example Dockerfile:
```dockerfile
FROM python:3.11-slim
RUN pip install dqix
ENTRYPOINT ["dqix"]
```

Build and run:
```bash
docker build -t dqix .
docker run dqix assess example.com
```

---

## 📈 Integration & APIs

### **Q: Can I use DQIX programmatically?**
**A:** Yes, example Python usage:
```python
import asyncio
from dqix.application.use_cases import DomainAssessmentUseCase
from dqix.infrastructure.factory import create_infrastructure

async def assess_domain():
    infrastructure = create_infrastructure()
    use_case = DomainAssessmentUseCase(infrastructure)
    result = await use_case.assess_domain("example.com")
    return result

result = asyncio.run(assess_domain())
```

### **Q: How do I integrate DQIX into CI/CD pipelines?**
**A:** Example GitHub Actions:
```yaml
- name: Domain Security Assessment
  run: |
    pip install dqix
    dqix assess ${{ github.event.repository.name }} --format json > security_report.json
```

### **Q: Can I export results to databases?**
**A:** Use JSON output and custom scripts:
```bash
dqix assess example.com --format json | jq '.' | your-database-import-script
```

---

## 📚 Academic & Research Use

### **Q: Can I cite DQIX in academic papers?**
**A:** Yes, suggested citation:
```
Domain Quality Index (DQIX) Principles & Measurement Criteria, Version 1.0 (2025).
Available at: https://github.com/dqix/dqix
```

### **Q: What academic standards does DQIX follow?**
**A:** DQIX is based on:
- NIST Cybersecurity Framework
- OWASP security guidelines
- RFC standards for internet protocols
- W3C web accessibility standards
- ISO 27001 security management principles

### **Q: How can I validate DQIX results?**
**A:** DQIX results are reproducible:
1. All algorithms are open source
2. Same inputs produce identical outputs
3. Cross-verify with manual testing
4. Compare with other security tools

---

## 🤝 Contributing & Community

### **Q: How can I contribute to DQIX?**
**A:** See [CONTRIBUTING.md](CONTRIBUTING.md) for details:
1. Fork the repository
2. Create feature branch
3. Add tests for new functionality
4. Submit pull request

### **Q: How do I report bugs or request features?**
**A:** Use GitHub Issues:
- Bug reports: Include domain, command used, error output
- Feature requests: Describe use case and requirements
- Security issues: Email maintainers privately first

### **Q: Is there a community forum or chat?**
**A:** 
- GitHub Discussions for general questions
- Issues for bug reports and features
- Email for security concerns

---

## 📋 Common Error Messages

### **"Domain not found" or "NXDOMAIN"**
- Domain doesn't exist in DNS
- Check spelling and domain extension
- Verify domain registration status

### **"Connection timeout"**
- Network connectivity issues
- Increase `--timeout` value
- Check firewall/proxy settings

### **"Certificate verification failed"**
- Invalid or expired SSL certificate
- Self-signed certificates not trusted
- Clock synchronization issues

### **"Permission denied"**
- Network restrictions
- Corporate firewall blocking
- Rate limiting by target server

### **"Too many concurrent requests"**
- Reduce `--concurrent` value
- Respect target server limits
- Add delays between requests

---

*Last Updated: June 2025*  
*For additional support, visit: [GitHub Issues](https://github.com/dqix/dqix/issues)* 