#!/usr/bin/env python3
"""
DQIX Polyglot Benchmarking Suite

Comprehensive benchmarking system for comparing DQIX implementations
across Python, Go, and Rust programming languages.
"""

import argparse
import json
import os
import statistics
import subprocess
import time
from datetime import datetime

import psutil


class LanguageBenchmark:
    """Base class for language-specific benchmarks"""

    def __init__(self, language: str, binary_path: str):
        self.language = language
        self.binary_path = binary_path
        self.results = {}

    def check_availability(self) -> bool:
        """Check if the language implementation is available"""
        try:
            result = subprocess.run([self.binary_path, "--version"],
                                  capture_output=True, text=True, timeout=10)
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False

    def benchmark_single_domain(self, domain: str) -> dict:
        """Benchmark single domain assessment"""
        start_time = time.time()
        process = psutil.Popen([self.binary_path, "assess", domain, "--format", "json"],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        # Monitor resource usage
        memory_usage = []
        cpu_usage = []

        while process.is_running():
            try:
                memory_usage.append(process.memory_info().rss / 1024 / 1024)  # MB
                cpu_usage.append(process.cpu_percent())
                time.sleep(0.1)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                break

        stdout, stderr = process.communicate()
        end_time = time.time()

        return {
            "domain": domain,
            "execution_time": end_time - start_time,
            "memory_peak": max(memory_usage) if memory_usage else 0,
            "memory_avg": statistics.mean(memory_usage) if memory_usage else 0,
            "cpu_avg": statistics.mean(cpu_usage) if cpu_usage else 0,
            "success": process.returncode == 0,
            "output_size": len(stdout) if stdout else 0,
            "error": stderr.decode() if stderr else None
        }

    def benchmark_bulk_domains(self, domains: list[str]) -> dict:
        """Benchmark bulk domain assessment"""
        start_time = time.time()

        # Create temporary file with domains
        temp_file = f"/tmp/dqix_benchmark_domains_{int(time.time())}.txt"
        with open(temp_file, 'w') as f:
            f.write('\n'.join(domains))

        try:
            process = psutil.Popen([self.binary_path, "bulk", temp_file, "--format", "json"],
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE)

            # Monitor resource usage
            memory_usage = []
            cpu_usage = []

            while process.is_running():
                try:
                    memory_usage.append(process.memory_info().rss / 1024 / 1024)  # MB
                    cpu_usage.append(process.cpu_percent())
                    time.sleep(0.1)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    break

            stdout, stderr = process.communicate()
            end_time = time.time()

            return {
                "domain_count": len(domains),
                "execution_time": end_time - start_time,
                "memory_peak": max(memory_usage) if memory_usage else 0,
                "memory_avg": statistics.mean(memory_usage) if memory_usage else 0,
                "cpu_avg": statistics.mean(cpu_usage) if cpu_usage else 0,
                "success": process.returncode == 0,
                "throughput": len(domains) / (end_time - start_time) if end_time > start_time else 0,
                "error": stderr.decode() if stderr else None
            }
        finally:
            if os.path.exists(temp_file):
                os.remove(temp_file)

    def benchmark_startup_time(self) -> float:
        """Measure cold start time"""
        times = []
        for _ in range(5):  # Average of 5 runs
            start = time.time()
            result = subprocess.run([self.binary_path, "--help"],
                                  capture_output=True, timeout=10)
            end = time.time()
            if result.returncode == 0:
                times.append(end - start)

        return statistics.mean(times) if times else float('inf')

class PythonBenchmark(LanguageBenchmark):
    def __init__(self):
        super().__init__("python", "dqix")

class GoBenchmark(LanguageBenchmark):
    def __init__(self):
        # Try different possible paths for Go binary
        possible_paths = ["dqix", "dqix-go/dqix", "./dqix-go/dqix"]
        binary_path = "dqix"  # Default

        for path in possible_paths:
            try:
                result = subprocess.run([path, "--version"], capture_output=True, timeout=5)
                if result.returncode == 0:
                    binary_path = path
                    break
            except (subprocess.TimeoutExpired, FileNotFoundError):
                continue

        super().__init__("go", binary_path)

class RustBenchmark(LanguageBenchmark):
    def __init__(self):
        # Try different possible paths for Rust binary
        possible_paths = ["dqix", "dqix-rust/target/release/dqix", "./dqix-rust/target/release/dqix"]
        binary_path = "dqix"  # Default

        for path in possible_paths:
            try:
                result = subprocess.run([path, "--version"], capture_output=True, timeout=5)
                if result.returncode == 0:
                    binary_path = path
                    break
            except (subprocess.TimeoutExpired, FileNotFoundError):
                continue

        super().__init__("rust", binary_path)

class BenchmarkRunner:
    """Main benchmark runner coordinating all language implementations"""

    def __init__(self):
        self.benchmarks = {
            "python": PythonBenchmark(),
            "go": GoBenchmark(),
            "rust": RustBenchmark()
        }
        self.results = {}
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    def get_test_domains(self, count: int = 10) -> list[str]:
        """Get list of test domains"""
        default_domains = [
            "example.com",
            "google.com",
            "github.com",
            "stackoverflow.com",
            "mozilla.org",
            "cloudflare.com",
            "microsoft.com",
            "amazon.com",
            "wikipedia.org",
            "reddit.com"
        ]
        return default_domains[:count]

    def run_language_benchmarks(self, language: str, domains: list[str]) -> dict:
        """Run all benchmarks for a specific language"""
        if language not in self.benchmarks:
            raise ValueError(f"Unsupported language: {language}")

        benchmark = self.benchmarks[language]

        if not benchmark.check_availability():
            return {
                "language": language,
                "available": False,
                "error": f"{language} implementation not found or not working"
            }

        print(f"Running {language} benchmarks...")

        results = {
            "language": language,
            "available": True,
            "timestamp": self.timestamp,
            "startup_time": benchmark.benchmark_startup_time(),
            "single_domain": {},
            "bulk_assessment": {}
        }

        # Single domain benchmarks
        print("  Single domain assessments...")
        for domain in domains[:3]:  # Test first 3 domains individually
            try:
                result = benchmark.benchmark_single_domain(domain)
                results["single_domain"][domain] = result
                print(f"    {domain}: {result['execution_time']:.2f}s")
            except Exception as e:
                results["single_domain"][domain] = {"error": str(e)}

        # Bulk assessment benchmarks
        print("  Bulk assessments...")
        for count in [5, 10]:
            try:
                test_domains = domains[:count]
                result = benchmark.benchmark_bulk_domains(test_domains)
                results["bulk_assessment"][f"{count}_domains"] = result
                print(f"    {count} domains: {result['execution_time']:.2f}s ({result['throughput']:.2f} domains/s)")
            except Exception as e:
                results["bulk_assessment"][f"{count}_domains"] = {"error": str(e)}

        return results

    def run_all_benchmarks(self, languages: list[str], domains: list[str]) -> dict:
        """Run benchmarks for all specified languages"""
        all_results = {
            "timestamp": self.timestamp,
            "system_info": {
                "platform": os.uname().sysname,
                "cpu_count": os.cpu_count(),
                "memory_gb": psutil.virtual_memory().total / (1024**3)
            },
            "languages": {}
        }

        for language in languages:
            try:
                results = self.run_language_benchmarks(language, domains)
                all_results["languages"][language] = results
            except Exception as e:
                all_results["languages"][language] = {
                    "language": language,
                    "available": False,
                    "error": str(e)
                }

        return all_results

    def save_results(self, results: dict, output_dir: str = "benchmarks/results"):
        """Save benchmark results to files"""
        os.makedirs(output_dir, exist_ok=True)

        # Save complete results
        filename = f"{output_dir}/benchmark_results_{self.timestamp}.json"
        with open(filename, 'w') as f:
            json.dump(results, f, indent=2)

        print(f"Results saved to: {filename}")

        # Generate summary report
        self.generate_summary_report(results, output_dir)

    def generate_summary_report(self, results: dict, output_dir: str):
        """Generate a human-readable summary report"""
        report_file = f"{output_dir}/summary_{self.timestamp}.md"

        with open(report_file, 'w') as f:
            f.write("# DQIX Polyglot Benchmark Report\n\n")
            f.write(f"**Timestamp**: {results['timestamp']}\n")
            f.write(f"**System**: {results['system_info']['platform']} ")
            f.write(f"({results['system_info']['cpu_count']} cores, ")
            f.write(f"{results['system_info']['memory_gb']:.1f}GB RAM)\n\n")

            f.write("## Language Availability\n\n")
            for lang, data in results['languages'].items():
                status = "✅ Available" if data.get('available', False) else "❌ Not Available"
                f.write(f"- **{lang.title()}**: {status}\n")
                if not data.get('available', False):
                    f.write(f"  - Error: {data.get('error', 'Unknown error')}\n")

            f.write("\n## Performance Comparison\n\n")
            f.write("| Language | Startup Time | Single Domain Avg | Bulk Throughput |\n")
            f.write("|----------|--------------|-------------------|------------------|\n")

            for lang, data in results['languages'].items():
                if not data.get('available', False):
                    continue

                startup = f"{data.get('startup_time', 0):.3f}s"

                # Calculate average single domain time
                single_times = []
                for domain_result in data.get('single_domain', {}).values():
                    if isinstance(domain_result, dict) and 'execution_time' in domain_result:
                        single_times.append(domain_result['execution_time'])

                single_avg = f"{statistics.mean(single_times):.2f}s" if single_times else "N/A"

                # Get best bulk throughput
                bulk_throughputs = []
                for bulk_result in data.get('bulk_assessment', {}).values():
                    if isinstance(bulk_result, dict) and 'throughput' in bulk_result:
                        bulk_throughputs.append(bulk_result['throughput'])

                bulk_best = f"{max(bulk_throughputs):.2f} domains/s" if bulk_throughputs else "N/A"

                f.write(f"| {lang.title()} | {startup} | {single_avg} | {bulk_best} |\n")

        print(f"Summary report saved to: {report_file}")

def main():
    parser = argparse.ArgumentParser(description="DQIX Polyglot Benchmarking Suite")
    parser.add_argument("--language", choices=["python", "go", "rust", "all"],
                       default="all", help="Language to benchmark")
    parser.add_argument("--domains", type=str, help="File with list of domains to test")
    parser.add_argument("--count", type=int, default=10, help="Number of domains to test")
    parser.add_argument("--output", type=str, default="benchmarks/results",
                       help="Output directory for results")

    args = parser.parse_args()

    # Get test domains
    if args.domains and os.path.exists(args.domains):
        with open(args.domains) as f:
            domains = [line.strip() for line in f if line.strip()]
    else:
        runner = BenchmarkRunner()
        domains = runner.get_test_domains(args.count)

    # Determine languages to test
    if args.language == "all":
        languages = ["python", "go", "rust"]
    else:
        languages = [args.language]

    # Run benchmarks
    runner = BenchmarkRunner()
    print(f"Starting DQIX polyglot benchmarks for: {', '.join(languages)}")
    print(f"Testing {len(domains)} domains: {', '.join(domains[:5])}{'...' if len(domains) > 5 else ''}")

    results = runner.run_all_benchmarks(languages, domains)
    runner.save_results(results, args.output)

    print("\nBenchmarking complete!")

if __name__ == "__main__":
    main()
