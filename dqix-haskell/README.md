# DQIX Internet Observability Platform - Haskell Implementation

🔍 **Pure Functional Programming with Test-Driven Development**

## Overview

This is the Haskell implementation of DQIX (Domain Quality Index), an Internet Observability Platform that provides comprehensive analysis of domain security, performance, and compliance using pure functional programming principles.

## Features

### ✨ Functional Programming Excellence
- **Pure Functions** - All core logic implemented without side effects
- **Algebraic Data Types** - Type-safe domain modeling
- **Monadic Error Handling** - Using `Either` for robust error handling
- **Higher-Order Functions** - Function composition throughout
- **Immutable Data Structures** - No in-place modifications

### 🧪 Test-Driven Development
- **Unit Tests** with HUnit
- **Property-Based Testing** with QuickCheck
- **Comprehensive Test Coverage** for all pure functions
- **Mock Data Generation** for testing
- **Functional Test Suite** execution

### 🔍 Internet Observability Probes
- **TLS/SSL Security Analysis** - Protocol versions, cipher strength, certificates
- **DNS Infrastructure Assessment** - DNSSEC, IPv6, SPF/DMARC records
- **HTTPS Implementation Review** - Accessibility, redirects, HSTS
- **Security Headers Validation** - CSP, frame options, content type

### 📊 Scoring & Compliance
- **Weighted Scoring Algorithm** - TLS (35%), DNS (25%), HTTPS (20%), Headers (20%)
- **Compliance Levels** - Excellent, Advanced, Standard, Basic, Poor
- **Security Grades** - A+ to F rating system
- **Detailed Assessment Reports** - Technical insights and recommendations

## Installation

### Prerequisites
- GHC 8.10+ or Stack
- Cabal 3.0+

### Build from Source
```bash
# Clone the repository
git clone https://github.com/dqix/dqix.git
cd dqix/dqix-haskell

# Install dependencies
cabal update
cabal install --only-dependencies

# Build the project
cabal build

# Install executable
cabal install
```

### Using Stack (Alternative)
```bash
# Build with Stack
stack build

# Install
stack install
```

## Usage

### Basic Commands

```bash
# Comprehensive domain analysis
dqix scan github.com

# Security validation checklist
dqix validate github.com

# Test with known good domains
dqix test

# Interactive demonstration
dqix demo github.com

# Run functional tests
dqix run-tests

# Show version information
dqix version
```

### Example Output

```
🔍 DQIX Internet Observability Platform
Analyzing: github.com

🌐 github.com
Internet Health Score: 92.1%
Grade: A | Compliance: Advanced

🔐 TLS/SSL Security: ✅ 95.2%
🌐 HTTPS Implementation: ✅ 92.8%
🌍 DNS Infrastructure: ✅ 89.1%
🛡️ Security Headers: ⚠️ 87.5%
```

## Architecture

### Pure Functional Design

```haskell
-- Domain modeling with algebraic data types
data Domain = Domain String deriving (Show, Eq)

data ProbeResult = ProbeResult
    { probeId :: String
    , probeDomain :: Domain
    , probeStatus :: ProbeStatus
    , probeScore :: Double
    , probeMessage :: String
    , probeDetails :: [(String, String)]
    } deriving (Show, Eq)

-- Functional error handling
type DqixResult a = Either String a

-- Pure scoring functions
calculateTlsScore :: [(String, String)] -> DqixResult Double
calculateDnsScore :: [(String, String)] -> DqixResult Double
calculateHttpsScore :: [(String, String)] -> DqixResult Double
```

### Higher-Order Functions

```haskell
-- Function composition
pipe :: [a -> a] -> a -> a
pipe = foldr (.) id

compose :: (b -> c) -> (a -> b) -> a -> c
compose = (.)

-- List processing
mapResults :: (a -> b) -> [a] -> [b]
filterResults :: (a -> Bool) -> [a] -> [a]
foldResults :: (b -> a -> b) -> b -> [a] -> b
```

### Monadic Assessment Composition

```haskell
composeAssessment :: Domain -> [ProbeResult] -> Double -> DqixResult AssessmentResult
composeAssessment domain probeResults timestamp = do
    overallScore <- calculateOverallScore probeResults
    complianceLevel <- determineComplianceLevel overallScore
    return $ AssessmentResult domain probeResults overallScore complianceLevel timestamp
```

## Testing

### Run All Tests
```bash
# Full test suite
cabal test

# Quick property tests
make test-quick

# Individual function tests
make test-functions
```

### Test Coverage
- ✅ Domain validation (empty, invalid, valid domains)
- ✅ TLS scoring (protocol versions, certificates, ciphers)
- ✅ DNS scoring (IPv4/IPv6, DNSSEC, email security)
- ✅ HTTPS scoring (accessibility, redirects, HSTS)
- ✅ Security headers scoring (CSP, frame options)
- ✅ Overall score calculation with weights
- ✅ Compliance level determination
- ✅ Assessment composition
- ✅ Higher-order function behavior
- ✅ Pure function determinism

### Property-Based Testing

```haskell
-- Domain validation round-trip property
prop_ValidDomainRoundTrip :: String -> Property
prop_ValidDomainRoundTrip domainName = 
    not (null domainName) && ('.' `elem` domainName) && length domainName <= 253 ==>
    case validateDomain domainName of
        Right (Domain result) -> result == domainName
        Left _ -> False

-- Score range validation
prop_ScoreInRange :: Double -> Property
prop_ScoreInRange score = 
    score >= 0.0 && score <= 1.0 ==>
    case determineComplianceLevel score of
        Right level -> level `elem` [Excellent, Advanced, Standard, Basic, Poor]
        Left _ -> False
```

## Development

### Setup Development Environment
```bash
make setup    # Install dependencies and dev tools
make repl     # Start GHCi REPL
make format   # Format code with stylish-haskell
make lint     # Lint code with hlint
make docs     # Generate documentation
```

### Continuous Integration
```bash
make ci       # Run full CI pipeline
```

### Performance Profiling
```bash
make profile  # Profile performance with GHC profiler
```

## Functional Programming Principles

### 1. Pure Functions
All core business logic is implemented as pure functions:
- No side effects
- Deterministic behavior
- Referential transparency
- Easy to test and reason about

### 2. Immutable Data
All data structures are immutable:
- No in-place modifications
- Thread-safe by design
- Predictable behavior
- Easier debugging

### 3. Type Safety
Strong static typing with algebraic data types:
- Compile-time error detection
- Self-documenting code
- Impossible states made impossible
- Refactoring safety

### 4. Monadic Error Handling
Using `Either` monad for error handling:
- Explicit error types
- Composable error handling
- No exceptions in pure code
- Railway-oriented programming

### 5. Higher-Order Functions
Functions as first-class citizens:
- Function composition
- Code reusability
- Declarative style
- Powerful abstractions

## Benchmarks

```bash
make benchmark  # Run performance benchmarks
```

Expected performance characteristics:
- Domain validation: ~1μs
- Probe scoring: ~10μs per probe
- Overall assessment: ~100μs
- Mock data generation: ~50μs

## Contributing

1. Fork the repository
2. Create a feature branch
3. Write tests first (TDD approach)
4. Implement functionality
5. Ensure all tests pass
6. Format and lint code
7. Submit pull request

### Code Style
- Follow standard Haskell conventions
- Use `stylish-haskell` for formatting
- Address all `hlint` warnings
- Write comprehensive tests
- Document public functions

## License

MIT License - see LICENSE file for details

## Related Implementations

- [Python Implementation](../dqix/) - Object-oriented with dataclasses
- [Go Implementation](../dqix-go/) - Concurrent with goroutines
- [Rust Implementation](../dqix-rust/) - Systems programming with ownership
- [Bash Implementation](../dqix-cli/) - Shell scripting with functions

## References

- [Haskell Functional Programming](https://nithinbekal.com/posts/haskell-quicksort/)
- [QuickSort in Functional Style](https://www.netidee.at/automated-software-verification-first-order-theorem-provers/functional-version-quicksort)
- [Property-Based Testing with QuickCheck](https://hackage.haskell.org/package/QuickCheck)
- [Domain-Driven Design in Haskell](https://leanpub.com/domain-modeling-made-functional)

---

**"Measuring the health of the Internet, together, in the open."** 🌐 