# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

DQIX (Domain Quality Index) is a comprehensive internet observability platform that provides transparent domain security assessments. It implements a unique **polyglot architecture** with the same domain assessment functionality across 6+ different programming languages, plus a modern WebAssembly frontend.

### Core Architecture

The project follows **Clean Architecture** with **Domain-Driven Design** principles:

```
dqix/                    # Root project with Python main implementation
├── dqix-python/         # Python reference implementation (pip installable as 'dqix')
├── dqix-go/            # Go implementation (high performance)  
├── dqix-rust/          # Rust implementation (memory safe)
├── dqix-haskell/       # Haskell implementation (functional)
├── dqix-cpp/           # C++ implementation (maximum performance)
├── dqix-cli/           # Bash implementation (unified CLI)
└── dqix-wasm/          # WebAssembly frontend (Tauri + SolidJS)
```

Each language implementation maintains **feature parity** while leveraging language-specific strengths.

## Development Commands

### **IMPORTANT: Cleanup Commands (Use Before Testing/Committing)**

```bash
# Full development cleanup (run before testing) - ESSENTIAL!
./scripts/clean-dev.sh

# Pre-commit cleanup with validation (run before committing) - REQUIRED!
./scripts/pre-commit-clean.sh

# Setup git hooks for automatic cleanup (run once per clone) - RECOMMENDED!
./scripts/setup-git-hooks.sh
```

⚠️ **Always run cleanup before testing or committing to avoid build artifacts and maintain repository hygiene.**

### Primary Development (uses uv package manager)

```bash
# Setup development environment
make dev-setup

# Install development dependencies
make install-dev

# Run all quality checks (lint, format, type-check, security, test)
make quality

# Run tests
make test                 # All tests
make test-unit           # Unit tests only  
make test-integration    # Integration tests only
make test-cov            # With coverage report

# Code quality
make lint                # Run linting
make lint-fix            # Auto-fix linting issues
make format              # Format code with Ruff
make type-check          # MyPy type checking
make security            # Security checks with bandit + safety

# Build and publish
make build               # Build Python package
make publish-test        # Publish to TestPyPI
make publish             # Publish to PyPI (production)
```

### Cross-Language Building

```bash
# Build individual language implementations
make build-go            # Go implementation
make build-rust          # Rust implementation  
make build-all           # All implementations

# Language-specific commands
cd dqix-go && go build -o dqix ./cmd/dqix/
cd dqix-rust && cargo build --release
cd dqix-haskell && cabal build
cd dqix-cpp && mkdir build && cd build && cmake .. && make

# WASM frontend
cd dqix-wasm && ./build-all.sh
```

### Testing Strategy

```bash
# Run specific test files
pytest tests/test_probes.py -v
pytest tests/test_integration.py -v

# Run tests by marker
pytest -m "unit"         # Unit tests only
pytest -m "integration"  # Integration tests only

# Run cross-language validation
python tests/cross_language_validation.py

# Benchmark all implementations
make benchmark
python benchmarks/run_benchmarks.py
```

## Key Architecture Concepts

### Domain Assessment Engine

All implementations share the same **3-level security hierarchy**:

1. **Critical Security** (TLS, Security Headers) - 55% weight
2. **Important Configuration** (HTTPS, DNS) - 45% weight  
3. **Best Practices** (Additional probes) - Variable weight

### Probe System

Each implementation includes **4 core probes**:
- **TLS Probe**: SSL/TLS configuration, certificates, protocol versions
- **DNS Probe**: DNSSEC, SPF, DMARC, DKIM records
- **HTTPS Probe**: Accessibility, redirects, HSTS
- **Security Headers**: CSP, X-Frame-Options, etc.

### Unified CLI Interface

The bash implementation in `dqix-cli/dqix` consolidates **5 previous separate scripts** into a single interface:

```bash
./dqix-cli/dqix scan example.com                    # Standard mode
./dqix-cli/dqix scan example.com --educational      # Educational explanations  
./dqix-cli/dqix scan example.com --comprehensive    # SSL Labs-style analysis
./dqix-cli/dqix scan example.com --parallel         # GNU parallel execution
./dqix-cli/dqix scan example.com --performance      # Speed optimized
./dqix-cli/dqix batch domain1.com domain2.com       # Batch processing
```

### WASM Frontend

The `dqix-wasm/` directory contains a **multi-engine WebAssembly frontend**:
- **5 WASM engines**: Rust/Leptos, Go/TinyGo, C++/Emscripten, Python/Pyodide, Haskell/Asterius
- **Unified frontend**: Tauri + SolidJS with real-time engine switching
- **Performance comparison**: Live benchmarking across all engines

## Configuration and Dependencies

### Python Main Implementation
- **Package manager**: uv (modern pip replacement)
- **Testing**: pytest with coverage
- **Linting**: Ruff (replaces flake8, black, isort)
- **Type checking**: MyPy
- **Security**: bandit + safety

### Cross-Language Dependencies
- **Go**: Go 1.21+ with modern features
- **Rust**: Tokio async runtime, latest stable
- **Haskell**: GHC 9.x with Cabal
- **C++**: C++20 standard with CMake
- **Bash**: GNU Bash 4.4+ with parallel support

## Important Files and Patterns

### Configuration Files
- `pyproject.toml` - Python package configuration
- `shared-config.yaml` - **NEW**: Unified configuration for all implementations (eliminates code duplication)
- `TEST_DOMAINS.yaml` - **NEW**: Consolidated test domains for cross-language testing
- `Makefile` - Development commands and workflows
- `.gitmessage` - Conventional commit message template

### Key Implementation Files
- `dqix-python/` - Reference implementation with full feature set
- `dqix-cli/dqix` - Unified bash CLI (replaces 5 separate scripts)
- `dqix-wasm/frontend-tauri/src/lib/wasm-engines.ts` - WASM engine manager

### Cross-Language Validation
- `tests/cross_language_validation.py` - Ensures feature parity
- `benchmarks/` - Performance comparison across languages
- `CROSS_LANGUAGE_TEST_SPECIFICATION.yaml` - Test specification

## Development Workflow

### Standard Development (Single Language)
1. **Make changes** in the appropriate language directory
2. **Run quality checks**: `make quality`
3. **Test changes**: `make test` or language-specific tests
4. **Cross-language validation**: Run validation scripts if core logic changed
5. **Benchmark**: Use `make benchmark` if performance-related changes

### Polyglot Feature Development (Affects All Languages)

**Critical**: When developing features that affect all language implementations, follow this strict sequence:

#### Phase 1: Specification & Configuration
1. **Update `shared-config.yaml`** - Add new parameters, weights, thresholds
2. **Update `CROSS_LANGUAGE_TEST_SPECIFICATION.yaml`** - Define expected behavior
3. **Update `TEST_DOMAINS.yaml`** - Add test cases if needed
4. **Document the feature** - Clear specification of logic and scoring

#### Phase 2: Reference Implementation
5. **Implement in Python first** (`dqix-python/`) - This is the reference implementation
6. **Validate logic thoroughly** - Ensure correct behavior and scoring
7. **Create comprehensive tests** - Unit and integration tests
8. **Update language-neutral tests** - Add to `tests/specs/universal-test-spec.yaml`

#### Phase 3: Cross-Language Propagation
9. **Implement in Go** (`dqix-go/`) - High-performance implementation
10. **Implement in Rust** (`dqix-rust/`) - Memory-safe implementation  
11. **Implement in Bash** (`dqix-cli/`) - CLI implementation
12. **Implement in Haskell** (`dqix-haskell/`) - Functional implementation
13. **Implement in C++** (`dqix-cpp/`) - Performance-critical implementation

#### Phase 4: Validation & Integration
14. **Run cross-language validation**: `python tests/runners/run-cross-language-validation.py`
15. **Check consistency**: Ensure ±5% score variance across implementations
16. **Update WASM frontend** - If needed for `dqix-wasm/`
17. **Run full benchmark suite**: `make benchmark`
18. **Update documentation** - All affected READMEs and guides

#### Phase 5: Quality Assurance
19. **Test edge cases** - Invalid domains, network failures, timeouts
20. **Security review** - Ensure no vulnerabilities introduced
21. **Performance validation** - No significant regressions
22. **Final cross-language test** - All implementations must pass

### ⚠️ Critical Rules for Polyglot Development

- **Never implement in only one language** - Feature parity is mandatory
- **Always start with shared configuration** - Avoid hardcoded values
- **Use the same scoring logic** - No implementation-specific algorithms
- **Validate consistency religiously** - Cross-language validation is required
- **Document breaking changes** - Update version numbers appropriately
- **Test real network scenarios** - Not just unit tests

## Special Considerations

### Polyglot Development
- **Feature parity**: All implementations must provide equivalent functionality
- **Consistent output**: JSON output format is standardized across languages
- **Performance characteristics**: Each language optimized for its strengths

### Security Focus
- All network requests use proper SSL/TLS verification
- Input validation on all domain inputs
- No hardcoded secrets or credentials
- Security scanning integrated into CI/CD

### WebAssembly Complexity  
- WASM builds require specific toolchains per language
- Browser compatibility considerations for different WASM engines
- Performance profiling across multiple runtime environments

This codebase uniquely maintains the same assessment logic across 6+ different programming languages while providing modern tooling and WebAssembly frontend capabilities.

## Universal Testing Principles

### Test-Driven Polyglot Development

The DQIX project follows **Universal Test Specification** principles to ensure consistency across all language implementations:

#### Core Testing Philosophy
1. **Language Neutrality**: Tests must work equally across all implementations without language-specific bias
2. **Pivot/Control Testing**: Each implementation must pass identical functional tests to ensure feature parity
3. **Behavioral Consistency**: All implementations should produce equivalent results for the same inputs (±5% variance allowed)
4. **Interface Standardization**: Common command patterns across all languages (`scan`, `--help`, `--json`)

#### Universal Test Requirements

Every language implementation MUST support:

```bash
# Core Required Tests (Must Pass ≥80%)
./implementation --help              # Help command
./implementation scan example.com    # Basic domain scan

# Optional Tests (Recommended)
./implementation demo                # Demo/test mode
./implementation scan domain --json  # JSON output format
```

#### Quality Gates

**Before Release:**
- All language implementations pass Universal Test Specification
- Cross-language score variance ≤5% for same domain
- Performance benchmarks within acceptable ranges
- External configuration consistency via `shared-config.yaml`

**Continuous Integration:**
- Automated testing across all 6 languages (Python, Go, Rust, Haskell, C++, Bash)
- Regression detection for behavioral changes
- Performance monitoring and alerting

#### Reference Implementation

**Bash CLI** (`dqix-cli/dqix`) serves as the **reference implementation** because:
- Most universally available (bash is everywhere)
- Simplest to debug and understand
- Clearest logic flow for validation
- Easiest to trace execution steps

#### Test Execution Standards

```bash
# Universal test runner
./test_all_implementations_simple.sh                    # Test all languages
./test_all_implementations_simple.sh --languages go rust # Test specific languages

# Individual language validation
./dqix-cli/dqix scan example.com                        # Reference implementation
./dqix-go/dqix scan example.com                         # Go implementation
./dqix-rust/target/release/dqix scan example.com        # Rust implementation
```

#### Module Issue Resolution Process

1. **Identify**: Use Universal Test Specification to detect issues
2. **Prioritize**: Fix core required tests first, optional tests second
3. **Standardize**: Ensure all implementations use `shared-config.yaml`
4. **Validate**: Run cross-language validation before considering fixed
5. **Document**: Update implementation-specific notes in this file

This systematic approach ensures that despite having 6+ different programming languages, the DQIX platform provides consistent, reliable domain assessment capabilities regardless of which implementation users choose.