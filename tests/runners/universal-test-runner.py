#!/usr/bin/env python3
"""
DQIX Universal Test Runner
Language-neutral test execution and validation framework
"""

import asyncio
import json
import subprocess
import time
import yaml
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

@dataclass
class TestResult:
    """Language-neutral test result."""
    language: str
    domain: str
    success: bool
    score: Optional[float]
    grade: Optional[str]
    execution_time: float
    output: str
    error: Optional[str]
    probe_count: int

@dataclass
class ValidationResult:
    """Validation result for cross-language consistency."""
    passed: bool
    message: str
    actual_value: Any
    expected_value: Any

class UniversalTestRunner:
    """Language-neutral test runner for DQIX implementations."""
    
    def __init__(self, spec_file: str = "tests/specs/universal-test-spec.yaml"):
        self.spec_file = Path(spec_file)
        self.spec = self._load_spec()
        self.results: Dict[str, List[TestResult]] = {}
        
    def _load_spec(self) -> Dict[str, Any]:
        """Load the universal test specification."""
        with open(self.spec_file, 'r') as f:
            return yaml.safe_load(f)
    
    def _get_test_command(self, language: str, domain: str) -> List[str]:
        """Get the test command for a specific language."""
        commands = self.spec['test_commands'][language]
        base_cmd = commands['test'].split()
        
        # Language-specific command construction
        if language == 'python':
            return ['uv', 'run', 'python', '-m', 'dqix-python', domain]
        elif language == 'go':
            return ['./dqix-go/dqix', 'scan', domain]
        elif language == 'rust':
            return ['./dqix-rust/target/release/dqix', domain]
        elif language == 'haskell':
            return ['./dqix-haskell/dqix', domain]
        elif language == 'bash':
            return ['./dqix-cli/dqix-multi', 'scan', domain]
        else:
            raise ValueError(f"Unsupported language: {language}")
    
    def _run_single_test(self, language: str, domain: str, timeout: int = 30) -> TestResult:
        """Run a single test for a language-domain combination."""
        start_time = time.time()
        
        try:
            cmd = self._get_test_command(language, domain)
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=Path.cwd()
            )
            
            execution_time = time.time() - start_time
            
            if result.returncode == 0:
                # Try to parse JSON output
                output_data = self._parse_output(result.stdout)
                score = output_data.get('overall_score') if output_data else None
                grade = output_data.get('grade') if output_data else None
                probe_count = len(output_data.get('probe_results', [])) if output_data else 0
                
                return TestResult(
                    language=language,
                    domain=domain,
                    success=True,
                    score=score,
                    grade=grade,
                    execution_time=execution_time,
                    output=result.stdout,
                    error=None,
                    probe_count=probe_count
                )
            else:
                return TestResult(
                    language=language,
                    domain=domain,
                    success=False,
                    score=None,
                    grade=None,
                    execution_time=execution_time,
                    output=result.stdout,
                    error=result.stderr,
                    probe_count=0
                )
                
        except subprocess.TimeoutExpired:
            return TestResult(
                language=language,
                domain=domain,
                success=False,
                score=None,
                grade=None,
                execution_time=timeout,
                output="",
                error="Test timed out",
                probe_count=0
            )
        except Exception as e:
            return TestResult(
                language=language,
                domain=domain,
                success=False,
                score=None,
                grade=None,
                execution_time=time.time() - start_time,
                output="",
                error=str(e),
                probe_count=0
            )
    
    def _parse_output(self, output: str) -> Optional[Dict[str, Any]]:
        """Try to parse JSON from command output."""
        lines = output.strip().split('\n')
        
        for line in lines:
            try:
                # Try to parse as JSON
                if line.strip().startswith('{'):
                    return json.loads(line.strip())
            except json.JSONDecodeError:
                continue
        
        return None
    
    def run_language_tests(self, language: str, domains: List[str]) -> List[TestResult]:
        """Run all tests for a specific language."""
        print(f"🧪 Testing {language} implementation...")
        results = []
        
        for domain in domains:
            print(f"  📍 {domain}...", end=' ')
            result = self._run_single_test(language, domain)
            results.append(result)
            
            if result.success:
                print(f"✅ Score: {result.score:.2f}" if result.score else "✅")
            else:
                print(f"❌ {result.error}")
        
        self.results[language] = results
        return results
    
    def validate_consistency(self) -> List[ValidationResult]:
        """Validate consistency across language implementations."""
        validations = []
        
        # Get all tested domains
        all_domains = set()
        for results in self.results.values():
            for result in results:
                if result.success:
                    all_domains.add(result.domain)
        
        for domain in all_domains:
            domain_results = {}
            for lang, results in self.results.items():
                for result in results:
                    if result.domain == domain and result.success:
                        domain_results[lang] = result
            
            if len(domain_results) < 2:
                continue
                
            # Validate score consistency
            scores = [r.score for r in domain_results.values() if r.score is not None]
            if len(scores) >= 2:
                max_diff = max(scores) - min(scores)
                max_allowed = self.spec['consistency_requirements']['score_variance']['max_difference']
                
                validations.append(ValidationResult(
                    passed=max_diff <= max_allowed,
                    message=f"Score consistency for {domain}",
                    actual_value=max_diff,
                    expected_value=f"<= {max_allowed}"
                ))
            
            # Validate probe count consistency
            probe_counts = [r.probe_count for r in domain_results.values()]
            if len(set(probe_counts)) > 1:
                validations.append(ValidationResult(
                    passed=False,
                    message=f"Probe count inconsistency for {domain}",
                    actual_value=probe_counts,
                    expected_value="All implementations should have same probe count"
                ))
        
        return validations
    
    def generate_report(self) -> Dict[str, Any]:
        """Generate comprehensive test report."""
        report = {
            "metadata": {
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "spec_version": self.spec['metadata']['version'],
                "languages_tested": list(self.results.keys())
            },
            "summary": {},
            "detailed_results": self.results,
            "consistency_validation": []
        }
        
        # Generate summary
        for language, results in self.results.items():
            total_tests = len(results)
            successful_tests = len([r for r in results if r.success])
            avg_score = sum(r.score for r in results if r.score is not None) / max(1, len([r for r in results if r.score is not None]))
            avg_time = sum(r.execution_time for r in results) / max(1, total_tests)
            
            report["summary"][language] = {
                "total_tests": total_tests,
                "successful_tests": successful_tests,
                "success_rate": successful_tests / total_tests if total_tests > 0 else 0,
                "average_score": avg_score,
                "average_execution_time": avg_time
            }
        
        # Add consistency validation
        report["consistency_validation"] = [
            {
                "test": v.message,
                "passed": v.passed,
                "actual": v.actual_value,
                "expected": v.expected_value
            }
            for v in self.validate_consistency()
        ]
        
        return report
    
    def run_all_tests(self, languages: Optional[List[str]] = None) -> Dict[str, Any]:
        """Run tests for all specified languages."""
        if languages is None:
            languages = list(self.spec['test_commands'].keys())
        
        # Get test domains
        test_domains = []
        for domain_spec in self.spec['test_domains']['basic_functionality']:
            test_domains.append(domain_spec['domain'])
        
        print(f"🚀 DQIX Universal Test Suite")
        print(f"Languages: {', '.join(languages)}")
        print(f"Domains: {', '.join(test_domains)}")
        print("=" * 60)
        
        # Run tests for each language
        for language in languages:
            try:
                self.run_language_tests(language, test_domains)
            except Exception as e:
                print(f"❌ Failed to test {language}: {e}")
                self.results[language] = []
        
        # Generate and return report
        report = self.generate_report()
        
        print("\n" + "=" * 60)
        print("📊 TEST SUMMARY")
        print("=" * 60)
        
        for language, summary in report["summary"].items():
            success_rate = summary["success_rate"] * 100
            print(f"{language:10} | {summary['successful_tests']:2}/{summary['total_tests']:2} tests | "
                  f"{success_rate:5.1f}% success | Avg score: {summary['average_score']:.2f}")
        
        consistency_passed = sum(1 for v in report["consistency_validation"] if v["passed"])
        consistency_total = len(report["consistency_validation"])
        print(f"\nConsistency: {consistency_passed}/{consistency_total} validations passed")
        
        return report

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="DQIX Universal Test Runner")
    parser.add_argument("--languages", nargs="+", 
                       choices=["python", "go", "rust", "haskell", "bash"],
                       help="Languages to test")
    parser.add_argument("--spec", default="tests/specs/universal-test-spec.yaml",
                       help="Path to test specification file")
    parser.add_argument("--output", help="Output file for test report (JSON)")
    
    args = parser.parse_args()
    
    runner = UniversalTestRunner(args.spec)
    report = runner.run_all_tests(args.languages)
    
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(report, f, indent=2)
        print(f"\n📄 Report saved to: {args.output}")