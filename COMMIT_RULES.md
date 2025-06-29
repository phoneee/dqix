# DQIX Commit Rules and Feature Requirements

## Overview

This document defines the commit rules and feature requirements for the DQIX Internet Observability Platform. All implementations must pass these requirements before commits are accepted.

## Core Feature Requirements

### 1. Domain Validation ✅
All implementations MUST validate domains according to these rules:
- Domain must not be empty
- Domain must contain at least one dot
- Domain length must not exceed 253 characters
- Domain must follow valid DNS naming conventions
- Proper error messages for invalid domains

**Test Cases:**
```bash
# Valid domains
✓ github.com
✓ sub.domain.example.com
✓ test-domain.com

# Invalid domains
✗ "" (empty)
✗ no-dot
✗ invalid..domain
✗ -start.com
✗ end-.com
```

### 2. Probe Implementations ✅

All implementations MUST implement these four probes:

#### TLS Probe (Weight: 35%)
- Check TLS/SSL connectivity
- Detect protocol version (TLS 1.3, 1.2, 1.1)
- Verify certificate validity
- Score based on security level

#### DNS Probe (Weight: 25%)
- Verify DNS resolution
- Check for IPv6 (AAAA records)
- Check for MX records
- Check for TXT records (SPF)
- Additional checks for DNSSEC, DMARC, etc.

#### HTTPS Probe (Weight: 20%)
- Verify HTTPS accessibility
- Check for HSTS header
- Verify HTTP to HTTPS redirect
- Measure response time

#### Security Headers Probe (Weight: 20%)
- Check Content-Security-Policy
- Check X-Frame-Options
- Check X-Content-Type-Options
- Check Referrer-Policy
- Count and score based on presence

### 3. Scoring Algorithm ✅

All implementations MUST use the same weighted scoring:
```
Overall Score = (TLS × 0.35) + (DNS × 0.25) + (HTTPS × 0.20) + (Headers × 0.20)
```

Grade boundaries:
- A+: 95-100%
- A: 90-94%
- A-: 85-89%
- B+: 80-84%
- B: 75-79%
- B-: 70-74%
- C+: 65-69%
- C: 60-64%
- C-: 55-59%
- D: 50-54%
- F: 0-49%

### 4. Output Formats ✅

#### Console Output
- Clear visual representation
- Color-coded scores (green: good, yellow: warning, red: poor)
- Progress bars for scores
- Recommendations based on findings

#### JSON Output
Required structure:
```json
{
  "domain": "example.com",
  "overall_score": 85,
  "grade": "A-",
  "timestamp": "2024-01-01T00:00:00Z",
  "engine": "Language DQIX v2.0.0",
  "probe_results": [
    {
      "probe_id": "tls",
      "score": 100,
      "category": "security",
      "details": "Valid certificate, TLSv1.3"
    }
  ]
}
```

### 5. CLI Commands ✅

All implementations MUST support:
- `scan <domain>` - Primary domain assessment
- `validate <domain>` - Security validation checklist
- `test` - Run self-tests
- `demo [domain]` - Interactive demonstration
- `help` - Show usage information
- `version` - Show version information

### 6. Error Handling ✅

- Graceful handling of network failures
- Timeout management (30s default)
- Clear error messages
- No crashes on invalid input
- Partial results on probe failures

## Pre-Commit Checks

The following checks run automatically before commits:

1. **Code Quality**
   - Python: Black, isort, flake8, mypy
   - Bash: shellcheck
   - All: trailing whitespace, file size

2. **Security**
   - Bandit for Python security issues
   - No hardcoded secrets or credentials

3. **Feature Tests**
   - Domain validation tests
   - Probe execution verification
   - Score calculation accuracy
   - Output format validation

4. **Import/Execution Tests**
   - Python package imports successfully
   - Bash script is executable
   - All CLIs respond to basic commands

## Commit Process

1. **Before Committing:**
   ```bash
   # Run feature verification
   ./scripts/verify-features.sh
   
   # Run specific language tests
   python -m pytest tests/test_feature_parity.py
   
   # Check implementations manually
   dqix scan example.com --json
   ./dqix-cli/dqix-multi scan example.com --json
   ```

2. **Commit Message Format:**
   ```
   <type>: <subject>
   
   <body>
   
   Feature checklist:
   [x] Domain validation implemented and tested
   [x] All 4 probes functional
   [x] Scoring algorithm correct
   [x] JSON output format consistent
   [x] Error handling for network failures
   [x] CLI commands working
   [x] Tests passing
   ```

3. **Types:**
   - `feat`: New feature
   - `fix`: Bug fix
   - `docs`: Documentation
   - `test`: Tests
   - `chore`: Maintenance

## Testing Requirements

### Unit Tests
- Domain validation edge cases
- Score calculation accuracy
- Grade boundary verification
- Error handling scenarios

### Integration Tests
- Real domain scanning
- Network timeout handling
- JSON parsing validation
- CLI command execution

### Performance Tests
- Scan completion within 30s
- Memory usage reasonable
- Concurrent scan support

## Language-Specific Requirements

### Python
- Type hints on all functions
- Docstrings for public APIs
- 100% test coverage for core logic
- Clean architecture compliance

### Bash
- POSIX compliance where possible
- Bash 3.2 compatibility (macOS)
- Clear error messages
- Proper exit codes

### Go
- Proper error handling
- Context usage for cancellation
- Concurrent probe execution
- Interface-based design

### Rust
- Safe code by default
- Proper error types
- Zero-copy where possible
- Async/await for I/O

### Haskell
- Pure functions where possible
- Proper monad usage
- Type safety throughout
- QuickCheck properties

## Continuous Improvement

1. **Regular Reviews**
   - Weekly feature parity checks
   - Performance benchmarking
   - Security scanning
   - Dependency updates

2. **Documentation**
   - Keep README current
   - Update examples
   - Document breaking changes
   - Maintain changelog

3. **Community**
   - Respond to issues
   - Review pull requests
   - Update based on feedback
   - Share learnings

## Enforcement

These rules are enforced through:
1. Pre-commit hooks (local development)
2. CI/CD pipeline (GitHub Actions)
3. Manual review (pull requests)
4. Automated testing (feature parity suite)

Non-compliant commits will be rejected automatically.

---

For questions or clarifications, see the main [README](README.md) or open an issue.