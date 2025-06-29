# DQIX Haskell Implementation

**Functional Domain Quality Index Assessment** - A modern, type-safe implementation aligned with the polyglot DQIX architecture.

## 🎯 Features

- **Real Network Assessment**: Performs actual TLS, DNS, HTTPS, and security header testing
- **Functional Programming**: Leverages Haskell's type safety and immutability
- **Concurrent Execution**: Uses `async` for parallel probe execution
- **JSON Output**: Machine-readable output for integration
- **Cross-Platform**: Works on macOS, Linux, and Windows
- **Shared Configuration**: Aligned with `shared-config.yaml` standards

## 🚀 Quick Start

### Build

```bash
# Install dependencies and build
cabal build

# Or use the optimized version
cabal build dqix-optimized
```

### Usage

```bash
# Standard assessment
./dist-newstyle/build/.../dqix scan example.com

# JSON output for integration
./dist-newstyle/build/.../dqix scan example.com --json

# Run tests
./dist-newstyle/build/.../dqix test

# Demo mode
./dist-newstyle/build/.../dqix demo
```

## 📊 Sample Output

```
🔍 DQIX Internet Observability Platform
Analyzing: example.com

Overall Score: 83% B
[█████████████████████████████████░░░░░░░]

Security Assessment (3-Level Hierarchy):

🚨 CRITICAL SECURITY
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  🛡️ Security Headers      60% [████████████░░░░░░░░] ⚠️  GOOD
  🔐 TLS/SSL Security      80% [████████████████░░░░] ✅ EXCELLENT

⚠️  IMPORTANT CONFIGURATION  
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  🌍 DNS Security         100% [████████████████████] ✅ EXCELLENT
  🌐 HTTPS Configuration  100% [████████████████████] ✅ EXCELLENT
```

## 🏗️ Architecture

### Core Types

```haskell
data ProbeResult = ProbeResult
    { probeId :: Text
    , name :: Text  
    , score :: Double
    , weight :: Double
    , category :: Text
    , status :: Text
    , message :: Text
    , details :: ProbeDetails
    , timestamp :: UTCTime
    }

data AssessmentResult = AssessmentResult
    { domain :: Text
    , overallScore :: Double
    , grade :: Text
    , complianceLevel :: Text
    , probeResults :: [ProbeResult]
    , assessmentTimestamp :: UTCTime
    , assessmentExecutionTime :: Double
    , metadata :: Metadata
    }
```

### Probe Implementation

Each probe is implemented as a pure function that performs real network testing:

- **TLS Probe**: Tests HTTPS connectivity and certificate validity
- **DNS Probe**: Checks SPF, DMARC, and DNS resolution 
- **HTTPS Probe**: Validates HTTPS configuration and redirects
- **Security Headers Probe**: Analyzes HTTP security headers

### Scoring System

Aligned with `shared-config.yaml`:

```haskell
tlsWeight = 1.5        -- Critical Security
headersWeight = 1.5    -- Critical Security  
httpsWeight = 1.2      -- Important Configuration
dnsWeight = 1.2        -- Important Configuration
totalWeight = 5.4
```

## 🧪 Testing

The implementation includes comprehensive tests:

```bash
# Run all tests
./dist-newstyle/build/.../dqix test

# Tests cover:
# - Domain validation
# - Probe level classification  
# - Grade calculation
# - Weighted scoring configuration
```

## 📦 Dependencies

**Core Dependencies:**
- `aeson` - JSON serialization
- `async` - Concurrent execution
- `dns` - DNS resolution
- `http-simple` - HTTP client
- `text` - Efficient text handling
- `time` - Timestamp handling

**Build Tools:**
- GHC 9.6+ 
- Cabal 3.0+

## 🔄 Integration with Polyglot Architecture

This Haskell implementation maintains feature parity with:

- **Go Implementation**: Same probe logic and scoring
- **Rust Implementation**: Equivalent safety guarantees
- **Python Implementation**: Compatible JSON output
- **Bash Implementation**: Identical CLI interface

### Cross-Language Validation

```bash
# All implementations should produce similar scores (±5% variance)
./dqix-go/dqix scan example.com --json > go-result.json
./dqix-haskell/dist-newstyle/.../dqix scan example.com --json > haskell-result.json
./dqix-rust/target/release/dqix scan example.com --json > rust-result.json

# Compare overall scores across implementations
```

## 🎛️ Configuration

Weights and thresholds are hardcoded to match `shared-config.yaml`:

```haskell
-- Probe weights (from shared-config.yaml)
tlsWeight, dnsWeight, httpsWeight, headersWeight :: Double
tlsWeight = 1.5
dnsWeight = 1.2  
httpsWeight = 1.2
headersWeight = 1.5
totalWeight = 5.4
```

## 🐛 Troubleshooting

### Common Issues

1. **Build Errors**: Ensure GHC 9.6+ and required dependencies
2. **Network Timeouts**: Default timeout is 30s per probe
3. **DNS Resolution**: Requires working DNS resolver

### Debug Mode

```bash
# Verbose output for debugging
cabal run dqix -- scan example.com --verbose
```

## 🤝 Contributing

This implementation follows the DQIX polyglot architecture:

1. **Maintain Feature Parity**: All probes must exist in all languages
2. **Consistent Scoring**: Use shared-config.yaml weights
3. **Type Safety**: Leverage Haskell's type system for correctness
4. **Functional Style**: Pure functions where possible

## 📄 License

MIT License - Same as parent DQIX project

---

**Part of the DQIX Internet Observability Platform** - A polyglot domain security assessment toolkit.