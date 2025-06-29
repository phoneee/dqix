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

1. **Make changes** in the appropriate language directory
2. **Run quality checks**: `make quality`
3. **Test changes**: `make test` or language-specific tests
4. **Cross-language validation**: Run validation scripts if core logic changed
5. **Benchmark**: Use `make benchmark` if performance-related changes

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