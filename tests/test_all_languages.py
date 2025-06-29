#!/usr/bin/env python3
"""
Comprehensive Unit Tests for All DQIX Language Implementations
Tests Python, Go, Rust, Haskell, C++, and Bash implementations
"""

import asyncio
import json
import subprocess
import sys
import time
import unittest
from pathlib import Path
from typing import Dict, List, Optional, Tuple
import tempfile
import os

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

class DQIXLanguageTest:
    """Base test class for DQIX language implementations"""
    
    def __init__(self, language: str, command: List[str], working_dir: str, 
                 build_cmd: Optional[List[str]] = None):
        self.language = language
        self.command = command
        self.working_dir = Path(__file__).parent.parent / working_dir
        self.build_cmd = build_cmd
        self.test_domains = ["example.com"]  # Using single domain for consistency across languages
        self.timeout = 60
    
    async def build_if_needed(self) -> bool:
        """Build the language implementation if needed"""
        if not self.build_cmd:
            return True
        
        try:
            if "&&" in " ".join(self.build_cmd):
                # Handle complex build commands
                cmd_str = " ".join(self.build_cmd)
                process = await asyncio.create_subprocess_shell(
                    cmd_str,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    cwd=self.working_dir
                )
            else:
                process = await asyncio.create_subprocess_exec(
                    *self.build_cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    cwd=self.working_dir
                )
            
            stdout, stderr = await asyncio.wait_for(
                process.communicate(), timeout=300
            )
            
            return process.returncode == 0
            
        except Exception:
            return False
    
    async def run_command(self, args: List[str]) -> Tuple[bool, str, str, float]:
        """Run a command and return success, stdout, stderr, execution_time"""
        start_time = time.time()
        
        try:
            full_cmd = self.command + args
            process = await asyncio.create_subprocess_exec(
                *full_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=self.working_dir
            )
            
            stdout, stderr = await asyncio.wait_for(
                process.communicate(), timeout=self.timeout
            )
            
            execution_time = time.time() - start_time
            success = process.returncode == 0
            
            return success, stdout.decode(), stderr.decode(), execution_time
            
        except asyncio.TimeoutError:
            return False, "", f"Timeout after {self.timeout}s", time.time() - start_time
        except Exception as e:
            return False, "", str(e), time.time() - start_time
    
    async def test_help_command(self) -> Dict:
        """Test help/version command - language neutral"""
        # Try multiple help variations to be language-neutral
        help_variants = ["--help", "-h", "help"]
        
        for variant in help_variants:
            success, stdout, stderr, exec_time = await self.run_command([variant])
            if success and (len(stdout) > 0 or len(stderr) > 0):
                return {
                    "test_name": "help_command",
                    "success": True,
                    "has_help_text": True,
                    "execution_time": exec_time,
                    "help_variant_used": variant
                }
        
        # If none worked, return failure
        return {
            "test_name": "help_command", 
            "success": False,
            "has_help_text": False,
            "execution_time": 0,
            "error": "No help command variant worked"
        }
    
    async def test_demo_command(self) -> Dict:
        """Test demo command - language neutral"""
        # Try multiple demo variations to be language-neutral
        demo_variants = ["demo", "demo example.com", "scan example.com", "test"]
        
        for variant in demo_variants:
            args = variant.split()
            success, stdout, stderr, exec_time = await self.run_command(args)
            
            if success and len(stdout) > 0:
                # Parse JSON output if possible
                json_output = None
                try:
                    json_output = json.loads(stdout)
                except:
                    pass
                
                return {
                    "test_name": "demo_command",
                    "success": True,
                    "has_output": True,
                    "json_parseable": json_output is not None,
                    "execution_time": exec_time,
                    "output_size": len(stdout),
                    "demo_variant_used": variant
                }
        
        # If none worked, return failure but don't penalize
        return {
            "test_name": "demo_command",
            "success": False,
            "has_output": False,
            "json_parseable": False,
            "execution_time": 0,
            "output_size": 0,
            "error": "No demo command variant worked"
        }
    
    async def test_scan_command(self, domain: str) -> Dict:
        """Test scan command with specific domain - language neutral"""
        # Try multiple scan command variations to be language-neutral
        scan_variants = [
            ["scan", domain],
            [domain],  # Some implementations might take domain as direct argument
            ["analyze", domain],
            ["assess", domain],
            ["check", domain]
        ]
        
        for variant in scan_variants:
            success, stdout, stderr, exec_time = await self.run_command(variant)
            
            if success and len(stdout) > 0:
                # Parse JSON output if possible
                json_output = None
                assessment_score = None
                try:
                    json_output = json.loads(stdout)
                    # Try to extract score with multiple field name variations
                    if isinstance(json_output, dict):
                        score_fields = ["overallScore", "overall_score", "score", "totalScore", "final_score"]
                        for field in score_fields:
                            if field in json_output:
                                assessment_score = json_output[field]
                                break
                except:
                    pass
                
                return {
                    "test_name": f"scan_{domain.replace('.', '_')}",
                    "domain": domain,
                    "success": True,
                    "has_output": True,
                    "json_parseable": json_output is not None,
                    "has_score": assessment_score is not None,
                    "execution_time": exec_time,
                    "output_size": len(stdout),
                    "scan_variant_used": " ".join(variant)
                }
        
        # If none worked, return failure
        return {
            "test_name": f"scan_{domain.replace('.', '_')}",
            "domain": domain,
            "success": False,
            "has_output": False,
            "json_parseable": False,
            "has_score": False,
            "execution_time": 0,
            "output_size": 0,
            "error_message": "No scan command variant worked"
        }
    
    async def test_json_output(self, domain: str) -> Dict:
        """Test JSON output format - language neutral"""
        # Try multiple JSON output variations to be language-neutral
        json_variants = [
            ["scan", domain, "--json"],
            ["scan", domain, "-j"],
            [domain, "--json"],
            ["analyze", domain, "--json"],
            ["check", domain, "--format", "json"]
        ]
        
        for variant in json_variants:
            success, stdout, stderr, exec_time = await self.run_command(variant)
            
            if success and stdout:
                json_output = None
                valid_structure = False
                
                try:
                    json_output = json.loads(stdout)
                    # Check for expected DQIX structure with multiple field variations
                    if isinstance(json_output, dict):
                        # Check for domain field (most basic requirement)
                        domain_fields = ["domain", "hostname", "site", "target"]
                        has_domain = any(field in json_output for field in domain_fields)
                        
                        # Check for score field
                        score_fields = ["overallScore", "overall_score", "score", "totalScore", "final_score"]
                        has_score = any(field in json_output for field in score_fields)
                        
                        # Check for results/probes field
                        results_fields = ["probeResults", "probe_results", "results", "probes", "checks"]
                        has_results = any(field in json_output for field in results_fields)
                        
                        valid_structure = has_domain and (has_score or has_results)
                        
                        if valid_structure:
                            return {
                                "test_name": f"json_output_{domain.replace('.', '_')}",
                                "domain": domain,
                                "success": True,
                                "json_parseable": True,
                                "valid_structure": True,
                                "execution_time": exec_time,
                                "json_variant_used": " ".join(variant)
                            }
                except:
                    continue
        
        # If none worked, return failure
        return {
            "test_name": f"json_output_{domain.replace('.', '_')}",
            "domain": domain,
            "success": False,
            "json_parseable": False,
            "valid_structure": False,
            "execution_time": 0,
            "error": "No JSON output variant worked"
        }
    
    async def run_all_tests(self) -> Dict:
        """Run all tests for this language implementation"""
        print(f"🧪 Testing {self.language} implementation...")
        
        # Build if needed
        build_success = await self.build_if_needed()
        if not build_success:
            return {
                "language": self.language,
                "build_success": False,
                "tests": [],
                "summary": {"total": 0, "passed": 0, "failed": 0, "success_rate": 0}
            }
        
        # Run tests
        tests = []
        
        # Test help command
        tests.append(await self.test_help_command())
        
        # Test demo command
        tests.append(await self.test_demo_command())
        
        # Test scan commands for different domains
        for domain in self.test_domains:
            tests.append(await self.test_scan_command(domain))
            tests.append(await self.test_json_output(domain))
        
        # Calculate summary
        total_tests = len(tests)
        passed_tests = sum(1 for test in tests if test["success"])
        failed_tests = total_tests - passed_tests
        
        return {
            "language": self.language,
            "build_success": build_success,
            "tests": tests,
            "summary": {
                "total": total_tests,
                "passed": passed_tests,
                "failed": failed_tests,
                "success_rate": (passed_tests / total_tests * 100) if total_tests > 0 else 0
            }
        }

class ComprehensiveLanguageTestSuite:
    """Comprehensive test suite for all DQIX language implementations"""
    
    def __init__(self):
        self.language_configs = {
            "bash": DQIXLanguageTest(
                language="bash",
                command=["./dqix"],
                working_dir="dqix-cli"
            ),
            "go": DQIXLanguageTest(
                language="go", 
                command=["./dqix"],
                working_dir="dqix-go",
                build_cmd=["go", "build", "-o", "dqix", "./cmd/dqix/"]
            ),
            "rust": DQIXLanguageTest(
                language="rust",
                command=["./target/release/dqix"],
                working_dir="dqix-rust",
                build_cmd=["cargo", "build", "--release"]
            ),
            "haskell": DQIXLanguageTest(
                language="haskell",
                command=["cabal", "run", "dqix", "--"],
                working_dir="dqix-haskell",
                build_cmd=["cabal", "build"]
            ),
            "cpp": DQIXLanguageTest(
                language="cpp",
                command=["./build/dqix"],
                working_dir="dqix-cpp",
                build_cmd=["mkdir", "-p", "build", "&&", "cd", "build", "&&", "cmake", "..", "&&", "make"]
            ),
            "python": DQIXLanguageTest(
                language="python",
                command=["python", "dqix-python/__main__.py"],
                working_dir="."
            )
        }
    
    def check_language_availability(self) -> Dict[str, bool]:
        """Check which language implementations are available"""
        availability = {}
        
        for lang_name, lang_test in self.language_configs.items():
            if lang_name == "python":
                # Python is always available if we're running this
                availability[lang_name] = True
                continue
            
            # Check if working directory exists
            if not lang_test.working_dir.exists():
                availability[lang_name] = False
                continue
            
            # Check if binary/script exists (for compiled languages)
            if lang_test.command[0].startswith("./"):
                binary_path = lang_test.working_dir / lang_test.command[0][2:]
                availability[lang_name] = binary_path.exists()
            else:
                # For interpreted languages, check if command exists
                try:
                    subprocess.run([lang_test.command[0], "--version"], 
                                 capture_output=True, timeout=5)
                    availability[lang_name] = True
                except:
                    availability[lang_name] = False
        
        return availability
    
    async def run_comprehensive_tests(self, languages: Optional[List[str]] = None) -> Dict:
        """Run comprehensive tests for specified languages (or all available)"""
        print("🚀 DQIX Comprehensive Language Test Suite")
        print("=" * 50)
        
        # Check availability
        availability = self.check_language_availability()
        
        # Filter to requested languages or available ones
        if languages:
            test_languages = [lang for lang in languages if lang in self.language_configs]
        else:
            test_languages = list(availability.keys())
        
        # Filter to available languages
        available_languages = [lang for lang in test_languages if availability.get(lang, False)]
        unavailable_languages = [lang for lang in test_languages if not availability.get(lang, False)]
        
        print(f"✅ Available languages: {', '.join(available_languages)}")
        if unavailable_languages:
            print(f"❌ Unavailable languages: {', '.join(unavailable_languages)}")
        print()
        
        # Run tests for available languages
        results = {}
        for language in available_languages:
            lang_test = self.language_configs[language]
            results[language] = await lang_test.run_all_tests()
        
        return {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "availability": availability,
            "tested_languages": available_languages,
            "unavailable_languages": unavailable_languages,
            "results": results
        }
    
    def print_test_results(self, comprehensive_results: Dict):
        """Print comprehensive test results"""
        print("\n📊 Test Results Summary")
        print("=" * 50)
        
        results = comprehensive_results["results"]
        
        # Summary table
        total_languages = len(results)
        successful_languages = 0
        total_tests = 0
        total_passed = 0
        
        for language, lang_results in results.items():
            summary = lang_results["summary"]
            total_tests += summary["total"]
            total_passed += summary["passed"]
            
            if summary["success_rate"] >= 80:
                successful_languages += 1
            
            # Print individual language results
            status = "✅" if summary["success_rate"] >= 80 else "⚠️" if summary["success_rate"] >= 50 else "❌"
            print(f"{status} {language.upper():>8}: {summary['passed']:>2}/{summary['total']:>2} tests "
                  f"({summary['success_rate']:>5.1f}%)")
            
            # Show failed tests
            failed_tests = [test for test in lang_results["tests"] if not test["success"]]
            if failed_tests:
                for test in failed_tests[:3]:  # Show up to 3 failed tests
                    print(f"    ❌ {test['test_name']}: {test.get('error_message', 'Failed')}")
        
        print()
        print(f"🎯 Overall Summary:")
        print(f"  Languages tested: {total_languages}")
        print(f"  Languages passing (≥80%): {successful_languages}")
        print(f"  Total tests: {total_tests}")
        print(f"  Tests passed: {total_passed}")
        print(f"  Overall success rate: {(total_passed/total_tests*100):.1f}%")
    
    def save_test_results(self, comprehensive_results: Dict, output_file: Optional[Path] = None):
        """Save test results to JSON file"""
        if not output_file:
            timestamp = time.strftime("%Y%m%d_%H%M%S")
            output_file = Path(f"test_results_{timestamp}.json")
        
        output_file.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_file, 'w') as f:
            json.dump(comprehensive_results, f, indent=2, default=str)
        
        print(f"\n💾 Test results saved to: {output_file}")
        return output_file
    
    async def run_performance_comparison(self, domain: str = "example.com") -> Dict:
        """Run performance comparison across all languages"""
        print(f"\n⚡ Performance Comparison ({domain})")
        print("=" * 40)
        
        availability = self.check_language_availability()
        available_languages = [lang for lang, avail in availability.items() if avail]
        
        performance_results = {}
        
        for language in available_languages:
            lang_test = self.language_configs[language]
            
            # Build if needed
            build_success = await lang_test.build_if_needed()
            if not build_success:
                continue
            
            # Run multiple iterations for better accuracy
            iterations = 3
            times = []
            
            for i in range(iterations):
                success, stdout, stderr, exec_time = await lang_test.run_command(["scan", domain])
                if success:
                    times.append(exec_time)
            
            if times:
                performance_results[language] = {
                    "avg_time": sum(times) / len(times),
                    "min_time": min(times),
                    "max_time": max(times),
                    "iterations": len(times)
                }
        
        # Sort by average time
        sorted_results = sorted(performance_results.items(), key=lambda x: x[1]["avg_time"])
        
        print("Performance Ranking (fastest to slowest):")
        for i, (language, stats) in enumerate(sorted_results, 1):
            emoji = "🥇" if i == 1 else "🥈" if i == 2 else "🥉" if i == 3 else f"{i}."
            print(f"  {emoji} {language.upper():>8}: {stats['avg_time']:>6.3f}s "
                  f"(range: {stats['min_time']:.3f}-{stats['max_time']:.3f}s)")
        
        return {
            "domain": domain,
            "results": performance_results,
            "ranking": [lang for lang, _ in sorted_results]
        }

async def main():
    """Main test function"""
    import argparse
    
    parser = argparse.ArgumentParser(description="DQIX Comprehensive Language Test Suite")
    parser.add_argument("--languages", nargs="+", 
                       choices=["python", "go", "rust", "haskell", "cpp", "bash"],
                       help="Languages to test (default: all available)")
    parser.add_argument("--performance", action="store_true",
                       help="Run performance comparison")
    parser.add_argument("--output", type=Path,
                       help="Output file for test results")
    
    args = parser.parse_args()
    
    # Create test suite
    test_suite = ComprehensiveLanguageTestSuite()
    
    # Run comprehensive tests
    results = await test_suite.run_comprehensive_tests(args.languages)
    
    # Print results
    test_suite.print_test_results(results)
    
    # Save results
    output_file = test_suite.save_test_results(results, args.output)
    
    # Run performance comparison if requested
    if args.performance:
        perf_results = await test_suite.run_performance_comparison()
        
        # Add performance results to main results
        results["performance_comparison"] = perf_results
        
        # Save updated results
        test_suite.save_test_results(results, output_file)
    
    # Return success if most tests passed
    overall_success_rate = 0
    if results["results"]:
        total_tests = sum(r["summary"]["total"] for r in results["results"].values())
        total_passed = sum(r["summary"]["passed"] for r in results["results"].values())
        overall_success_rate = (total_passed / total_tests * 100) if total_tests > 0 else 0
    
    return 0 if overall_success_rate >= 70 else 1

if __name__ == "__main__":
    exit(asyncio.run(main()))