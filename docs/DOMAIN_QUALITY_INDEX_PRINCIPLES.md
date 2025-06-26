# Domain Quality Index (DQIX) - Principles & Measurement Criteria

## Vision Statement
*"Measuring the health of the web, together, in the open."*

The Domain Quality Index provides a comprehensive, transparent, and reproducible measurement of domain security, accessibility, and governance compliance using exclusively open data and academic standards.

---

## Core Measurement Principles

### 1. **Academic Standards Compliance**
Based on internationally recognized frameworks:
- **NIST Cybersecurity Framework** - Risk management and security controls
- **OWASP Top 10** - Web application security risks
- **RFC Standards** - Internet engineering protocols (TLS, DNS, HTTP)
- **W3C Web Standards** - Accessibility and web best practices
- **ISO 27001** - Information security management principles

### 2. **Open Transparency**
- All measurement algorithms are public and auditable
- Scoring criteria based on published security research
- No proprietary or black-box scoring methods
- Reproducible results using open data sources

### 3. **Evidence-Based Assessment**
- Measurements derived from actual technical implementation
- Quantifiable security and compliance indicators
- Peer-reviewed security research foundations
- Real-world attack vector considerations

---

## Measurement Categories

## 🔐 **TLS Security Assessment (35% Weight)**

### **Protocol Security (10 points)**
- **TLS 1.3**: 10 points - Modern, secure protocol
- **TLS 1.2**: 8 points - Acceptable with proper configuration  
- **TLS 1.1/1.0**: 0 points - Deprecated, vulnerable protocols
- **No TLS**: 0 points - Unencrypted communication

### **Cipher Suite Security (8 points)**
- **Perfect Forward Secrecy**: +3 points - ECDHE/DHE key exchange
- **Modern Encryption**: +3 points - AES-GCM, ChaCha20-Poly1305
- **Strong Hash**: +2 points - SHA-256 or better
- **Weak Ciphers**: -5 points - RC4, 3DES, NULL ciphers

### **Certificate Validation (12 points)**
- **Trusted CA**: 4 points - Valid certificate authority
- **Domain Match**: 3 points - Certificate matches domain
- **Validity Period**: 2 points - Not expired, reasonable lifetime
- **Key Strength**: 3 points - RSA ≥2048 bits or ECC ≥256 bits

### **Advanced Features (5 points)**
- **OCSP Stapling**: +1 point - Certificate revocation checking
- **Certificate Transparency**: +1 point - CT log inclusion
- **HPKP/Expect-CT**: +1 point - Certificate pinning (when present)
- **Multiple Validation**: +2 points - Extended/Organization validation

**Sources**: [RFC 8446 (TLS 1.3)](https://tools.ietf.org/html/rfc8446), [Mozilla SSL Configuration](https://wiki.mozilla.org/Security/Server_Side_TLS)

---

## 🌐 **DNS Security & Infrastructure (30% Weight)**

### **Basic DNS Health (8 points)**
- **IPv4 Availability**: 2 points - A records present
- **IPv6 Support**: 2 points - AAAA records present  
- **Redundant Nameservers**: 2 points - ≥2 authoritative nameservers
- **Response Performance**: 2 points - Sub-second DNS resolution

### **Email Security (12 points)**
- **SPF Record**: 4 points - Sender Policy Framework configured
  - `-all` (strict): 4 points
  - `~all` (soft): 2 points  
  - No SPF: 0 points
- **DMARC Policy**: 4 points - Domain-based Message Authentication
  - `p=reject`: 4 points
  - `p=quarantine`: 2 points
  - `p=none` or missing: 0 points
- **DKIM Support**: 4 points - DomainKeys Identified Mail
  - Active selectors: 4 points
  - Configured but inactive: 2 points

### **Advanced Security (10 points)**
- **DNSSEC**: 6 points - DNS Security Extensions
  - Fully validated chain: 6 points
  - Partially configured: 3 points
  - Not configured: 0 points
- **CAA Records**: 4 points - Certificate Authority Authorization
  - Restrictive policy: 4 points
  - Permissive policy: 2 points
  - No CAA: 0 points

**Sources**: [RFC 7208 (SPF)](https://tools.ietf.org/html/rfc7208), [RFC 7489 (DMARC)](https://tools.ietf.org/html/rfc7489), [RFC 4033 (DNSSEC)](https://tools.ietf.org/html/rfc4033)

---

## 🔒 **HTTP Security Headers (35% Weight)**

### **Critical Headers (20 points)**
- **HSTS (HTTP Strict Transport Security)**: 8 points
  - `max-age≥31536000` + `includeSubDomains` + `preload`: 8 points
  - `max-age≥31536000` + `includeSubDomains`: 6 points
  - `max-age≥2592000`: 4 points
  - Shorter or missing: 0 points

- **Content Security Policy (CSP)**: 8 points
  - Restrictive policy without unsafe directives: 8 points
  - Moderate policy with minimal unsafe: 5 points
  - Basic policy or report-only: 3 points
  - Missing: 0 points

- **X-Frame-Options**: 4 points
  - `DENY`: 4 points
  - `SAMEORIGIN`: 3 points
  - `ALLOW-FROM` (deprecated): 1 point
  - Missing: 0 points

### **Important Headers (10 points)**
- **X-Content-Type-Options**: 3 points - `nosniff` prevents MIME sniffing
- **Referrer-Policy**: 3 points - Controls referrer information leakage
- **Permissions-Policy**: 2 points - Controls browser feature access
- **X-XSS-Protection**: 2 points - Legacy XSS protection (modern browsers use CSP)

### **Information Disclosure (-5 points)**
- **Server Header**: -2 points - Reveals server technology
- **X-Powered-By**: -2 points - Reveals framework/language
- **X-AspNet-Version**: -1 point - Reveals specific versions

**Sources**: [OWASP Secure Headers](https://owasp.org/www-project-secure-headers/), [Mozilla Web Security Guidelines](https://infosec.mozilla.org/guidelines/web_security)

---

## Compliance Level Classification

### **Excellent (90-100 points)**
- Industry-leading security implementation
- Suitable for high-security environments
- Meets or exceeds all major security frameworks

### **Advanced (80-89 points)**  
- Strong security posture with minor gaps
- Suitable for most enterprise environments
- Compliant with major security standards

### **Standard (60-79 points)**
- Basic security measures implemented
- Some security gaps requiring attention
- Meets minimum security requirements

### **Basic (40-59 points)**
- Significant security improvements needed
- High risk of security incidents
- Below recommended security baselines

### **Poor (0-39 points)**
- Critical security vulnerabilities present
- Immediate remediation required
- High risk of compromise

---

## Measurement Methodology

### **Data Collection**
1. **Direct Protocol Testing** - Active probing of TLS, DNS, HTTP
2. **Public Record Analysis** - DNS records, certificate transparency logs
3. **Standards Compliance Check** - RFC and W3C guideline adherence
4. **Security Best Practice Validation** - OWASP and NIST framework alignment

### **Scoring Algorithm**
```
Overall Score = (TLS Score × 0.35) + (DNS Score × 0.30) + (Headers Score × 0.35)

Where each component score is:
Component Score = (Achieved Points / Maximum Points) × 100
```

### **Quality Assurance**
- **Reproducibility** - Same inputs produce identical results
- **Transparency** - All criteria publicly documented
- **Validation** - Results verified against known standards
- **Continuous Improvement** - Regular updates based on security research

---

## Academic References

### **Security Frameworks**
- NIST Cybersecurity Framework v1.1 (2018)
- OWASP Application Security Verification Standard (ASVS) v4.0
- ISO/IEC 27001:2013 Information Security Management

### **Protocol Standards**  
- RFC 8446: The Transport Layer Security (TLS) Protocol Version 1.3
- RFC 7208: Sender Policy Framework (SPF) 
- RFC 7489: Domain-based Message Authentication, Reporting, and Conformance (DMARC)
- RFC 4033: DNS Security Introduction and Requirements

### **Web Security Standards**
- W3C Content Security Policy Level 3
- IETF HTTP Strict Transport Security (RFC 6797)
- Mozilla Web Security Guidelines

### **Research Publications**
- "Analysis of the HTTPS Certificate Ecosystem" (IMC 2013)
- "The Security Impact of HTTPS Interception" (NDSS 2017)  
- "Measuring and Analyzing the Real-World Security of the Internet's Most Popular Websites" (WWW 2016)

---

## Implementation Notes

### **Measurement Frequency**
- **Real-time Assessment** - On-demand domain evaluation
- **Bulk Processing** - Large-scale comparative analysis
- **Monitoring Mode** - Periodic re-evaluation for tracking

### **Performance Considerations**
- **Concurrent Execution** - Parallel probe processing
- **Timeout Management** - Reasonable limits for network operations
- **Resource Efficiency** - Minimal computational overhead
- **Rate Limiting** - Respectful of target infrastructure

### **Extensibility**
- **Modular Design** - Easy addition of new measurement criteria
- **Configuration Driven** - Adjustable scoring weights and thresholds
- **Plugin Architecture** - Third-party measurement extensions
- **Version Management** - Backward compatibility for historical data

---

*Last Updated: June 2025*  
*Version: 1.0*

**Citation Format:**
```
Domain Quality Index (DQIX) Principles & Measurement Criteria, Version 1.0 (2025).
Available at: https://github.com/dqix/dqix
``` 