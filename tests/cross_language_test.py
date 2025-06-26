#!/usr/bin/env python3
"""
DQIX Cross-Language Testing Framework
====================================

Tests consistency and performance across Python, Go, and Rust implementations.
Validates that all three implementations produce consistent results and
maintains performance standards.
"""

import asyncio
import json
import subprocess
import sys
import time
from dataclasses import dataclass
from typing import Any, Optional


@dataclass
class TestResult:
    """Test result for a single implementation"""
    implementation: str
    domain: str
    score: float
    level: str
    duration: float
    success: bool
    error: str = ""
    details: Optional[dict[str, Any]] = None

@dataclass
class BenchmarkResult:
    """Benchmark comparison results"""
    domain: str
    python_time: float
    go_time: float
    rust_time: float
    consistency_score: float
    score_variance: float

class CrossLanguageTester:
    """Cross-language testing and validation framework"""

    def __init__(self):
        self.test_domains = [
            "example.com",
            "google.com",
            "github.com",
            "cloudflare.com",
            "mozilla.org"
        ]
        self.implementations = {
            "python": {
                "command": ["dqix"],
                "available": self._check_python_availability()
            },
            "go": {
                "command": ["dqix-go"],
                "available": self._check_go_availability()
            },
            "rust": {
                "command": ["dqix-rust"],
                "available": self._check_rust_availability()
            }
        }

    def _check_python_availability(self) -> bool:
        """Check if Python implementation is available"""
        try:
            result = subprocess.run(["dqix", "--help"],
                                  capture_output=True, text=True, timeout=10)
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False

    def _check_go_availability(self) -> bool:
        """Check if Go implementation is available"""
        try:
            result = subprocess.run(["dqix-go", "version"],
                                  capture_output=True, text=True, timeout=10)
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False

    def _check_rust_availability(self) -> bool:
        """Check if Rust implementation is available"""
        try:
            result = subprocess.run(["dqix-rust", "version"],
                                  capture_output=True, text=True, timeout=10)
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False

    async def run_assessment(self, implementation: str, domain: str) -> TestResult:
        """Run assessment for a specific implementation and domain"""
        if not self.implementations[implementation]["available"]:
            return TestResult(
                implementation=implementation,
                domain=domain,
                score=0.0,
                level="F",
                duration=0.0,
                success=False,
                error=f"{implementation} implementation not available"
            )

        start_time = time.time()

        try:
            # Prepare command
            cmd = self.implementations[implementation]["command"] + [
                domain,
                "--output", "json"
            ]

            # Run assessment
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await asyncio.wait_for(
                process.communicate(), timeout=60
            )

            duration = time.time() - start_time

            if process.returncode != 0:
                return TestResult(
                    implementation=implementation,
                    domain=domain,
                    score=0.0,
                    level="F",
                    duration=duration,
                    success=False,
                    error=stderr.decode() if stderr else "Unknown error"
                )

            # Parse JSON output
            result_data = json.loads(stdout.decode())

            return TestResult(
                implementation=implementation,
                domain=domain,
                score=result_data.get("score", 0.0),
                level=result_data.get("level", "F"),
                duration=duration,
                success=True,
                details=result_data
            )

        except asyncio.TimeoutError:
            return TestResult(
                implementation=implementation,
                domain=domain,
                score=0.0,
                level="F",
                duration=time.time() - start_time,
                success=False,
                error="Timeout after 60 seconds"
            )
        except json.JSONDecodeError as e:
            return TestResult(
                implementation=implementation,
                domain=domain,
                score=0.0,
                level="F",
                duration=time.time() - start_time,
                success=False,
                error=f"JSON decode error: {e}"
            )
        except Exception as e:
            return TestResult(
                implementation=implementation,
                domain=domain,
                score=0.0,
                level="F",
                duration=time.time() - start_time,
                success=False,
                error=f"Unexpected error: {e}"
            )

    async def test_consistency(self, domain: str) -> dict[str, TestResult]:
        """Test consistency across all implementations for a domain"""
        print(f"🔍 Testing consistency for domain: {domain}")

        tasks = []
        for impl in self.implementations.keys():
            if self.implementations[impl]["available"]:
                tasks.append(self.run_assessment(impl, domain))

        results = await asyncio.gather(*tasks)

        # Create results dictionary
        result_dict = {}
        for result in results:
            result_dict[result.implementation] = result
            status = "✅" if result.success else "❌"
            print(f"  {status} {result.implementation}: {result.score:.4f} ({result.level}) - {result.duration:.2f}s")

            if not result.success:
                print(f"    Error: {result.error}")

        return result_dict

    def analyze_consistency(self, results: dict[str, TestResult]) -> tuple[float, float]:
        """Analyze consistency of results across implementations"""
        successful_results = [r for r in results.values() if r.success]

        if len(successful_results) < 2:
            return 0.0, 0.0

        scores = [r.score for r in successful_results]

        # Calculate variance
        mean_score = sum(scores) / len(scores)
        variance = sum((s - mean_score) ** 2 for s in scores) / len(scores)

        # Calculate consistency score (1.0 = perfect consistency)
        consistency = max(0.0, 1.0 - (variance * 10))  # Scale variance for readability

        return consistency, variance

    async def run_benchmark(self, domain: str) -> BenchmarkResult:
        """Run performance benchmark for all implementations"""
        print(f"🚀 Benchmarking domain: {domain}")

        results = await self.test_consistency(domain)

        # Extract timings
        python_time = results.get("python", TestResult("python", domain, 0, "F", 999, False)).duration
        go_time = results.get("go", TestResult("go", domain, 0, "F", 999, False)).duration
        rust_time = results.get("rust", TestResult("rust", domain, 0, "F", 999, False)).duration

        # Calculate consistency
        consistency, variance = self.analyze_consistency(results)

        return BenchmarkResult(
            domain=domain,
            python_time=python_time,
            go_time=go_time,
            rust_time=rust_time,
            consistency_score=consistency,
            score_variance=variance
        )

    async def run_full_test_suite(self) -> None:
        """Run complete cross-language test suite"""
        print("🌐 DQIX Cross-Language Testing Framework")
        print("=" * 50)

        # Check available implementations
        available_impls = [k for k, v in self.implementations.items() if v["available"]]
        print(f"\n📋 Available implementations: {', '.join(available_impls)}")

        if len(available_impls) < 2:
            print("❌ Error: At least 2 implementations required for cross-language testing")
            return

        print(f"🎯 Testing {len(self.test_domains)} domains")
        print()

        # Run consistency tests
        all_results = {}
        for domain in self.test_domains:
            all_results[domain] = await self.test_consistency(domain)
            print()

        # Run benchmarks
        print("📊 Performance Benchmarks:")
        print("-" * 30)

        benchmark_results = []
        for domain in self.test_domains:
            benchmark = await self.run_benchmark(domain)
            benchmark_results.append(benchmark)

            print(f"Domain: {domain}")
            print(f"  Python: {benchmark.python_time:.3f}s")
            print(f"  Go:     {benchmark.go_time:.3f}s")
            print(f"  Rust:   {benchmark.rust_time:.3f}s")
            print(f"  Consistency: {benchmark.consistency_score:.3f}")
            print(f"  Variance: {benchmark.score_variance:.6f}")
            print()

        # Summary statistics
        self.print_summary(benchmark_results, all_results)

    def print_summary(self, benchmarks: list[BenchmarkResult],
                     all_results: dict[str, dict[str, TestResult]]) -> None:
        """Print comprehensive test summary"""
        print("📈 Summary Statistics:")
        print("=" * 30)

        # Performance statistics
        avg_python = sum(b.python_time for b in benchmarks) / len(benchmarks)
        avg_go = sum(b.go_time for b in benchmarks) / len(benchmarks)
        avg_rust = sum(b.rust_time for b in benchmarks) / len(benchmarks)

        print("Average Performance:")
        print(f"  Python: {avg_python:.3f}s")
        print(f"  Go:     {avg_go:.3f}s")
        print(f"  Rust:   {avg_rust:.3f}s")

        # Performance ratios
        if avg_python > 0:
            go_speedup = avg_python / avg_go if avg_go > 0 else 0
            rust_speedup = avg_python / avg_rust if avg_rust > 0 else 0
            print("\nSpeedup vs Python:")
            print(f"  Go:   {go_speedup:.2f}x")
            print(f"  Rust: {rust_speedup:.2f}x")

        # Consistency statistics
        avg_consistency = sum(b.consistency_score for b in benchmarks) / len(benchmarks)
        avg_variance = sum(b.score_variance for b in benchmarks) / len(benchmarks)

        print("\nConsistency:")
        print(f"  Average consistency score: {avg_consistency:.3f}")
        print(f"  Average score variance: {avg_variance:.6f}")

        # Success rates
        for impl in self.implementations.keys():
            if self.implementations[impl]["available"]:
                successes = sum(1 for results in all_results.values()
                              if impl in results and results[impl].success)
                rate = successes / len(self.test_domains) * 100
                print(f"  {impl.capitalize()} success rate: {rate:.1f}%")

    async def generate_report(self, output_file: str = "cross_language_test_report.json") -> None:
        """Generate detailed JSON report"""
        print(f"📄 Generating detailed report: {output_file}")

        # Run tests and collect all data
        test_data = {
            "metadata": {
                "framework": "DQIX Cross-Language Testing",
                "version": "1.2.0",
                "timestamp": time.time(),
                "implementations": {
                    k: v["available"] for k, v in self.implementations.items()
                }
            },
            "domains": self.test_domains,
            "results": {},
            "benchmarks": []
        }

        # Collect detailed results
        for domain in self.test_domains:
            results = await self.test_consistency(domain)
            test_data["results"][domain] = {
                impl: {
                    "score": result.score,
                    "level": result.level,
                    "duration": result.duration,
                    "success": result.success,
                    "error": result.error
                }
                for impl, result in results.items()
            }

            benchmark = await self.run_benchmark(domain)
            test_data["benchmarks"].append({
                "domain": benchmark.domain,
                "python_time": benchmark.python_time,
                "go_time": benchmark.go_time,
                "rust_time": benchmark.rust_time,
                "consistency_score": benchmark.consistency_score,
                "score_variance": benchmark.score_variance
            })

        # Write report
        with open(output_file, 'w') as f:
            json.dump(test_data, f, indent=2)

        print(f"✅ Report saved to: {output_file}")

async def main():
    """Main entry point for cross-language testing"""
    tester = CrossLanguageTester()

    if len(sys.argv) > 1:
        command = sys.argv[1]

        if command == "consistency":
            domain = sys.argv[2] if len(sys.argv) > 2 else "example.com"
            await tester.test_consistency(domain)
        elif command == "benchmark":
            domain = sys.argv[2] if len(sys.argv) > 2 else "example.com"
            await tester.run_benchmark(domain)
        elif command == "report":
            await tester.generate_report()
        else:
            print("Usage: python cross_language_test.py [consistency|benchmark|report] [domain]")
    else:
        await tester.run_full_test_suite()

if __name__ == "__main__":
    asyncio.run(main())
