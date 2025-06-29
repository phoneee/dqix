# DQIX Cross-Language Validation Report

Generated: Sun Jun 29 12:50:52 +07 2025

## Summary

✅ **All implementations passed consistency validation**

## Test Configuration

### Test Domains
- example.com
- google.com
- github.com
- badssl.com

### Expected Probe Weights
- tls: 0.35 (35.0%)
- dns: 0.25 (25.0%)
- https: 0.2 (20.0%)
- security_headers: 0.2 (20.0%)

### Score Thresholds
- excellent: ≥0.8 (80.0%)
- good: ≥0.6 (60.0%)
- fair: ≥0.4 (40.0%)

## Recommendations

1. Ensure all implementations use consistent probe weights
2. Standardize score calculation algorithms
3. Implement JSON output for all languages
4. Create shared test fixtures for validation
