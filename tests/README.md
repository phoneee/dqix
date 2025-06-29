# DQIX Language-Neutral Testing Framework

This directory contains a **language-neutral testing framework** that addresses the issue of Python-centric testing in a polyglot architecture.

## Problem Solved

The original `tests/` directory was Python-centric, violating the polyglot principle:
- ❌ Used pytest and Python-specific modules
- ❌ Tests only worked with Python implementation  
- ❌ Other languages couldn't reuse tests
- ❌ Broke the unified `shared-config.yaml` approach

## New Architecture

```
tests/
├── specs/                          # Language-neutral specifications
│   └── universal-test-spec.yaml    # Universal test definitions
├── runners/                        # Language-specific test runners
│   ├── universal-test-runner.py    # Main test orchestrator
│   ├── run-bash-tests.sh          # Bash CLI test runner
│   ├── run-go-tests.sh            # Go implementation tests
│   └── run-cross-language-validation.py  # Cross-language consistency
└── README.md                       # This file
```

## Key Features

### 1. Universal Test Specification (`specs/universal-test-spec.yaml`)
- **Language-neutral test definitions**
- **Expected behaviors and constraints**
- **Consistent scoring and validation rules**
- **Performance benchmarks**
- **Cross-language consistency requirements**

### 2. Language-Specific Runners (`runners/`)
- **Bash**: Tests all CLI variants (unified, educational, performance, parallel)
- **Go**: Native Go testing with build validation
- **Python**: uv-based testing with dependency management
- **Rust**: Cargo-based testing and benchmarks
- **Haskell**: Cabal-based functional testing

### 3. Cross-Language Validation
- **Consistency checking**: Ensures similar scores across implementations
- **Output format validation**: JSON and human-readable consistency
- **Performance comparison**: Execution time and resource usage
- **Error handling verification**: Graceful failure testing

## Usage

### Run All Tests
```bash
# Test all available languages
python tests/runners/universal-test-runner.py

# Test specific languages
python tests/runners/universal-test-runner.py --languages go bash

# Save detailed report
python tests/runners/universal-test-runner.py --output test-report.json
```

### Language-Specific Testing
```bash
# Test bash implementations
./tests/runners/run-bash-tests.sh

# Test Go implementation  
./tests/runners/run-go-tests.sh

# Cross-language validation
python tests/runners/run-cross-language-validation.py
```

### Validation Commands
```bash
# Validate consistency across implementations
python tests/runners/run-cross-language-validation.py \\
  --languages go bash python \\
  --domains example.com google.com github.com

# Generate detailed validation report
python tests/runners/run-cross-language-validation.py \\
  --output validation-report.json
```

## Test Categories

1. **Core Functionality**: Basic domain assessment
2. **Probe Accuracy**: Individual probe consistency  
3. **Output Format**: JSON and CLI output validation
4. **Performance**: Execution time and resource usage
5. **Error Handling**: Graceful failure and edge cases

## Consistency Requirements

- **Score Variance**: ≤5% difference between implementations
- **Probe Count**: Same number of probes across languages
- **Output Schema**: Consistent JSON structure
- **Execution Time**: ≤30 seconds per domain assessment

## Integration with Shared Config

The testing framework leverages `shared-config.yaml`:
- **Test domains**: Uses consolidated test domain lists
- **Scoring thresholds**: Validates against shared scoring rules
- **Probe definitions**: Ensures probe consistency
- **Output formatting**: Matches shared display standards

## Benefits

✅ **Language Neutral**: Tests work across all implementations  
✅ **Consistent Validation**: Same rules for all languages  
✅ **Extensible**: Easy to add new languages  
✅ **Comprehensive**: Covers functionality, performance, and consistency  
✅ **Automated**: Can run in CI/CD pipelines  
✅ **Unified**: Integrates with shared configuration

## Example Output

```
🚀 DQIX Universal Test Suite
Languages: go, bash, python
Domains: example.com, google.com, github.com
============================================================

🐹 Testing go implementation...
  📍 example.com... ✅ Score: 0.82
  📍 google.com... ✅ Score: 0.95
  📍 github.com... ✅ Score: 0.91

🐚 Testing bash implementation...
  📍 example.com... ✅ Score: 0.80
  📍 google.com... ✅ Score: 0.93
  📍 github.com... ✅ Score: 0.89

============================================================
📊 TEST SUMMARY
============================================================
go        |  3/ 3 tests |  100.0% success | Avg score: 0.89
bash      |  3/ 3 tests |  100.0% success | Avg score: 0.87

Consistency: 3/3 validations passed
✅ Cross-language validation PASSED
```

This framework ensures **true polyglot testing** while maintaining the consistency and quality standards required for a production-ready domain assessment platform.