# DQIX Architecture Recommendations

## Executive Summary

Based on rigorous academic analysis, the DQIX system requires architectural improvements to become a credible domain quality measurement system. This document provides actionable recommendations with academic justification.

## 1. Immediate Actions (Priority 1)

### 1.1 Remove Redundant Components

**What to Remove:**
- `ProbeResult` class in `core/probes.py` (unused)
- `impersonation` probe (duplicates SPF/DKIM/DMARC)
- `NSEC` probe (DNSSEC implementation detail)
- Certificate Transparency probe (mandatory, not differentiating)

**Justification:** Occam's Razor - entities should not be multiplied without necessity

### 1.2 Fix Architectural Issues

**Replace Global State:**
```python
# Current (BAD)
VERBOSE_LEVEL = 0  # Global variable

# Recommended (GOOD)
@dataclass
class ProbeConfig:
    verbosity: int = 0
    timeout: int = 10
```

**Justification:** Fowler (2002) - Avoid global state for testability

### 1.3 Consolidate Email Security

**Current:** Separate SPF (15%), DKIM (3%), DMARC, Impersonation (24%)

**Recommended:** Single `email_security` probe (20%)
- Prevents double-counting
- Reflects interdependencies (DMARC requires SPF/DKIM)
- Reference: M³AAWG Best Practices

## 2. Critical Additions (Priority 2)

### 2.1 IPv6 Support Probe

```python
@register
class IPv6Probe(Probe):
    """
    Measure IPv6 readiness.
    
    Reference: Google IPv6 Statistics (40%+ adoption)
    """
    id = "ipv6"
    weight = 0.05
    
    def run(self, domain):
        # Check for AAAA records
        # Test IPv6 connectivity
        # Verify feature parity with IPv4
```

### 2.2 Performance Metrics

```python
@register
class PerformanceProbe(Probe):
    """
    Measure domain performance.
    
    Reference: Google Core Web Vitals
    """
    id = "performance"
    weight = 0.10
    
    def run(self, domain):
        # DNS response time (<100ms good)
        # HTTP response time (<200ms good)
        # Geographic distribution
```

## 3. Scoring Model Improvements

### 3.1 Implement Baseline Requirements

```python
scoring_model = BaselineScoringModel(
    baseline_probes=['tls', 'dnssec'],
    threshold=0.5
)

# Domain cannot score >50% without basic security
```

**Justification:** Security is not additive - missing TLS is critical regardless of other features

### 3.2 Adjust Weights Based on Research

```yaml
# level3_improved.yaml
tls:            0.25  # Critical (Felt et al. 2017)
dnssec:         0.20  # Critical (Chung et al. 2017)
email_security: 0.20  # Combined SPF/DKIM/DMARC
headers:        0.15  # Important (OWASP)
dns_basic:      0.10  # Infrastructure
ipv6:           0.05  # Future-ready
performance:    0.05  # User experience
```

## 4. Measurement Validity

### 4.1 TLS Scoring

**Current Issues:**
- Binary pass/fail doesn't reflect gradations
- SSL Labs grades are opaque

**Recommended Scoring:**
```python
def score_tls(tls_version, cipher_strength, cert_validity):
    base_score = 0.0
    
    # Protocol version (40% of score)
    if tls_version >= "1.3":
        base_score += 0.4
    elif tls_version >= "1.2":
        base_score += 0.3
    else:
        return 0.0  # Fail immediately
    
    # Cipher strength (30% of score)
    if cipher_strength >= 256:
        base_score += 0.3
    elif cipher_strength >= 128:
        base_score += 0.2
    
    # Certificate validity (30% of score)
    if cert_validity > 30:  # days
        base_score += 0.3
    elif cert_validity > 7:
        base_score += 0.15
    
    return base_score
```

### 4.2 DNSSEC Scoring

**Reference:** Scheitle et al. (2018) "A Long Way to the Top"

```python
def score_dnssec(chain_valid, algorithm, key_size):
    if not chain_valid:
        return 0.0
    
    score = 0.5  # Base for valid chain
    
    # Modern crypto (ECDSA P-256 or RSA-2048+)
    if algorithm in [13, 14] or (algorithm == 8 and key_size >= 2048):
        score += 0.3
    
    # Multiple validators confirmed
    if validated_by_multiple_resolvers:
        score += 0.2
    
    return score
```

## 5. Implementation Timeline

### Phase 1 (Week 1-2)
1. Remove redundant components
2. Fix global state issues
3. Consolidate email probes

### Phase 2 (Week 3-4)
1. Add IPv6 probe
2. Add performance probe
3. Implement baseline scoring

### Phase 3 (Week 5-6)
1. Adjust weights based on data
2. Validate measurements
3. Document methodology

## 6. Validation Methodology

### 6.1 Ground Truth Dataset

Create validation set from:
- Alexa Top 1000 (popular sites)
- Tranco List (research-oriented)
- Government domains (.gov)
- Known-bad domains (phishing lists)

### 6.2 Correlation Analysis

Validate that DQIX scores correlate with:
- Security incidents (lower scores = more incidents)
- User trust surveys
- Browser security warnings
- Industry certifications (ISO 27001, etc.)

### 6.3 Academic Review

Submit methodology to:
- Internet Measurement Conference (IMC)
- USENIX Security Symposium
- Network and Distributed System Security (NDSS)

## 7. Ethical Considerations

### 7.1 Transparency
- Publish all algorithms and weights
- Provide detailed scoring breakdowns
- Allow appeals/corrections

### 7.2 Privacy
- No personal data collection
- Respect robots.txt
- Rate-limit scans

### 7.3 Responsible Disclosure
- Notify domains of critical issues before publishing
- Provide remediation guidance
- Grace period for fixes

## 8. References

1. **Architecture & Design**
   - Fowler, M. (2002). "Patterns of Enterprise Application Architecture"
   - Martin, R. (2003). "Agile Software Development, Principles, Patterns, and Practices"

2. **Domain Security**
   - Felt et al. (2017). "Measuring HTTPS Adoption on the Web." USENIX Security
   - Chung et al. (2017). "Understanding the Role of Registrars in DNSSEC." IMC
   - Scheitle et al. (2018). "A Long Way to the Top: Significance of DNSSEC." IMC

3. **Measurement Methodology**
   - Le Pochat et al. (2019). "Tranco: A Research-Oriented Top Sites Ranking." WWW
   - Durumeric et al. (2014). "The Matter of Heartbleed." IMC

4. **Standards**
   - RFC 1035: Domain Names - Implementation
   - RFC 7208: Sender Policy Framework
   - RFC 7489: Domain-based Message Authentication

## Conclusion

The DQIX system has potential to become a valuable domain quality measurement tool. By implementing these evidence-based recommendations, it can provide accurate, actionable insights that improve internet security and reliability. The key is focusing on measurable, validated metrics that correlate with real-world outcomes. 