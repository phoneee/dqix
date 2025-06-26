# DQIX Polyglot Publishing Guide

## 🎯 Strategy: Monorepo with Independent Publishing

### Why Monorepo?
1. **Shared Specifications**: All languages implement same DSL
2. **Unified Testing**: Cross-language integration tests
3. **Consistent Versioning**: Coordinated releases
4. **Benchmark Comparisons**: Easy performance testing
5. **Single Source of Truth**: One place for all implementations

### 📦 Publishing Strategy

#### 1. Python → PyPI
```bash
cd python/
# Update version in pyproject.toml
poetry build
poetry publish
# or
python -m build
twine upload dist/*
```

**Package Name**: `dqix`
**Import**: `from dqix import scan_domain`

#### 2. Rust → Crates.io
```bash
cd rust/
cargo publish
```

**Crate Name**: `dqix`
**Binary**: `dqix-rust`

#### 3. Go → pkg.go.dev
```bash
cd go/
go mod tidy
git tag go/v1.0.0
git push --tags
```

**Module**: `github.com/yourusername/dqix/go`
**Binary**: `dqix-go`

#### 4. Haskell → Hackage
```bash
cd haskell/
cabal sdist
cabal upload dist-newstyle/sdist/dqix-*.tar.gz
```

**Package**: `dqix`
**Binary**: `dqix-haskell`

#### 5. Bash → GitHub Releases
```bash
# Create release artifact
tar -czf dqix-bash-v1.0.0.tar.gz bash/
# Upload to GitHub releases
```

## 🔧 Monorepo Setup

### Root Configuration

**`.gitignore`**:
```gitignore
# Python
python/dist/
python/*.egg-info/
python/.venv/
__pycache__/

# Rust
rust/target/
rust/Cargo.lock

# Go
go/bin/
go/vendor/

# Haskell
haskell/dist-newstyle/
haskell/.stack-work/

# Benchmarks
benchmarks/results/*.json
benchmarks/results/*.html
```

**`Makefile`** (root):
```makefile
.PHONY: all test benchmark publish

all: build-all test-all

build-all:
	@echo "Building all implementations..."
	$(MAKE) -C python build
	$(MAKE) -C rust build
	$(MAKE) -C go build
	$(MAKE) -C haskell build
	$(MAKE) -C bash build

test-all:
	@echo "Testing all implementations..."
	$(MAKE) -C python test
	$(MAKE) -C rust test
	$(MAKE) -C go test
	$(MAKE) -C haskell test
	$(MAKE) -C bash test

benchmark:
	@echo "Running cross-language benchmarks..."
	python benchmarks/run_benchmarks.py

publish-python:
	cd python && poetry publish

publish-rust:
	cd rust && cargo publish

publish-go:
	@echo "Tag with: git tag go/v$(VERSION)"
	@echo "Then: git push --tags"
```

## 📊 Benchmark Framework

**`benchmarks/run_benchmarks.py`**:
```python
#!/usr/bin/env python3
"""Cross-language DQIX benchmark suite."""

import subprocess
import time
import json
import statistics
from pathlib import Path
from typing import Dict, List, Any

class DQIXBenchmark:
    """Benchmark all DQIX implementations."""
    
    IMPLEMENTATIONS = {
        "python": "python -m dqix scan {domain}",
        "rust": "../rust/target/release/dqix scan {domain}",
        "go": "../go/bin/dqix scan {domain}",
        "haskell": "../haskell/dist-newstyle/build/*/dqix/build/dqix/dqix scan {domain}",
        "bash": "../bash/dqix.sh scan {domain}"
    }
    
    TEST_DOMAINS = [
        "github.com",
        "google.com",
        "cloudflare.com",
        "example.com",
        "stackoverflow.com"
    ]
    
    def run_benchmark(self, impl: str, command: str, domain: str) -> Dict[str, Any]:
        """Run single benchmark."""
        times = []
        memory = []
        
        for _ in range(5):  # 5 runs per domain
            start = time.time()
            
            # Run command
            result = subprocess.run(
                command.format(domain=domain),
                shell=True,
                capture_output=True,
                text=True
            )
            
            elapsed = time.time() - start
            times.append(elapsed)
            
            # TODO: Add memory profiling
            
        return {
            "implementation": impl,
            "domain": domain,
            "avg_time": statistics.mean(times),
            "min_time": min(times),
            "max_time": max(times),
            "std_dev": statistics.stdev(times) if len(times) > 1 else 0,
            "runs": len(times)
        }
    
    def run_all_benchmarks(self):
        """Run benchmarks for all implementations."""
        results = []
        
        for impl, command in self.IMPLEMENTATIONS.items():
            print(f"\nBenchmarking {impl}...")
            
            for domain in self.TEST_DOMAINS:
                try:
                    result = self.run_benchmark(impl, command, domain)
                    results.append(result)
                    print(f"  ✓ {domain}: {result['avg_time']:.2f}s")
                except Exception as e:
                    print(f"  ✗ {domain}: {e}")
        
        # Save results
        with open("benchmarks/results/benchmark_results.json", "w") as f:
            json.dump(results, f, indent=2)
        
        # Generate report
        self.generate_report(results)
    
    def generate_report(self, results: List[Dict[str, Any]]):
        """Generate benchmark report."""
        # Group by implementation
        by_impl = {}
        for r in results:
            impl = r["implementation"]
            if impl not in by_impl:
                by_impl[impl] = []
            by_impl[impl].append(r)
        
        print("\n" + "="*60)
        print("DQIX PERFORMANCE BENCHMARK RESULTS")
        print("="*60)
        
        for impl, impl_results in by_impl.items():
            avg_time = statistics.mean([r["avg_time"] for r in impl_results])
            print(f"\n{impl.upper()}:")
            print(f"  Average time: {avg_time:.2f}s")
            print(f"  Domains tested: {len(impl_results)}")

if __name__ == "__main__":
    benchmark = DQIXBenchmark()
    benchmark.run_all_benchmarks()
```

## 🔄 Ensuring Functional Parity

### Shared Test Suite

**`spec/test_cases.yaml`**:
```yaml
test_cases:
  - name: "Basic domain scan"
    command: "scan"
    args: ["github.com"]
    expected:
      score_min: 0.7
      probes: ["tls", "dns", "https", "security_headers"]
      
  - name: "JSON output"
    command: "scan"
    args: ["github.com", "--output", "json"]
    expected:
      format: "json"
      fields: ["domain", "overall_score", "probe_results"]
      
  - name: "Domain comparison"
    command: "compare"
    args: ["github.com", "google.com"]
    expected:
      domains_count: 2
      output_type: "table"
```

### Language-Specific Paradigms

#### Python (Object-Oriented + Async)
```python
# Pythonic implementation
class DQIXScanner:
    async def scan_domain(self, domain: str) -> AssessmentResult:
        """Async/await pattern."""
        probes = await asyncio.gather(*[
            probe.check(domain) for probe in self.probes
        ])
        return AssessmentResult(domain, probes)
```

#### Rust (Memory Safety + Performance)
```rust
// Zero-cost abstractions
pub async fn scan_domain(domain: &str) -> Result<Assessment> {
    let probes = tokio::join!(
        tls_probe(domain),
        dns_probe(domain),
        https_probe(domain),
        headers_probe(domain)
    );
    Ok(Assessment::new(domain, probes))
}
```

#### Go (Concurrency + Simplicity)
```go
// Goroutines and channels
func ScanDomain(domain string) (*Assessment, error) {
    results := make(chan ProbeResult, 4)
    
    go tlsProbe(domain, results)
    go dnsProbe(domain, results)
    go httpsProbe(domain, results)
    go headersProbe(domain, results)
    
    return collectResults(domain, results)
}
```

#### Haskell (Pure Functional)
```haskell
-- Pure functions and monads
scanDomain :: Domain -> IO Assessment
scanDomain domain = do
    results <- mapConcurrently ($ domain) probes
    pure $ Assessment domain results
  where
    probes = [tlsProbe, dnsProbe, httpsProbe, headersProbe]
```

#### Bash (Unix Philosophy)
```bash
# Pipelines and composition
scan_domain() {
    local domain=$1
    
    tls_score=$(check_tls "$domain")
    dns_score=$(check_dns "$domain")
    https_score=$(check_https "$domain")
    headers_score=$(check_headers "$domain")
    
    calculate_overall_score "$tls_score" "$dns_score" "$https_score" "$headers_score"
}
```

## 📝 Publishing Checklist

### Pre-Publishing
- [ ] All tests passing in all languages
- [ ] Version numbers synchronized
- [ ] Changelogs updated
- [ ] Documentation current
- [ ] Benchmarks run and documented

### Python (PyPI)
- [ ] Update `pyproject.toml` version
- [ ] Run `poetry build`
- [ ] Test with `pip install dist/*.whl`
- [ ] Publish with `poetry publish`

### Rust (Crates.io)
- [ ] Update `Cargo.toml` version
- [ ] Run `cargo test`
- [ ] Run `cargo publish --dry-run`
- [ ] Publish with `cargo publish`

### Go (pkg.go.dev)
- [ ] Update version in `go.mod`
- [ ] Run `go test ./...`
- [ ] Tag with `git tag go/vX.Y.Z`
- [ ] Push tags

### Haskell (Hackage)
- [ ] Update `.cabal` file version
- [ ] Run `cabal test`
- [ ] Build sdist with `cabal sdist`
- [ ] Upload to Hackage

### Bash
- [ ] Update version in script header
- [ ] Run shellcheck
- [ ] Create release tarball
- [ ] Upload to GitHub releases

## 🎯 Benefits of This Approach

1. **Single Source of Truth**: All implementations in one place
2. **Coordinated Releases**: Version consistency across languages
3. **Shared Infrastructure**: Common test cases, benchmarks, docs
4. **Easy Comparison**: Benchmark and compare implementations
5. **Community Friendly**: Contributors can work on any language
6. **CI/CD Integration**: One pipeline for all languages

## 🚀 Next Steps

1. Set up CI/CD for automated testing
2. Create release automation scripts
3. Set up benchmark visualization
4. Create language-specific READMEs
5. Set up package registries accounts

This monorepo approach gives you the best of both worlds: unified development with independent publishing!