#!/usr/bin/env python3
"""
Cross-Language Validation Suite
Ensures consistency across all DQIX implementations
"""

import json
import subprocess
import time
import yaml
from pathlib import Path
from typing import Dict, List, Any, Optional
from dataclasses import dataclass

@dataclass
class ImplementationResult:
    """Result from a single implementation."""
    language: str
    domain: str
    score: Optional[float]
    grade: Optional[str]
    probe_count: int
    execution_time: float
    success: bool
    raw_output: str
    error: Optional[str]

class CrossLanguageValidator:
    """Validates consistency across language implementations."""
    
    def __init__(self):
        self.results: Dict[str, Dict[str, ImplementationResult]] = {}
        self.load_config()
    
    def load_config(self):
        """Load shared configuration."""
        with open('shared-config.yaml', 'r') as f:
            self.config = yaml.safe_load(f)
    
    def run_implementation(self, language: str, domain: str) -> ImplementationResult:
        """Run a single implementation and return structured result."""
        start_time = time.time()
        
        commands = {
            'python': ['uv', 'run', 'python', '-m', 'dqix-python', domain],
            'go': ['./dqix-go/dqix', 'scan', domain, '--json'],
            'rust': ['./dqix-rust/target/release/dqix', '--json', domain],
            'haskell': ['./dqix-haskell/dqix', domain],
            'bash': ['./dqix-cli/dqix-multi', 'scan', domain, '--json']
        }
        
        if language not in commands:
            return ImplementationResult(
                language=language,
                domain=domain,
                score=None,
                grade=None,
                probe_count=0,
                execution_time=0,
                success=False,
                raw_output="",
                error=f"Unknown language: {language}"
            )
        
        try:
            result = subprocess.run(
                commands[language],
                capture_output=True,
                text=True,
                timeout=30,
                cwd=Path.cwd()
            )
            
            execution_time = time.time() - start_time
            
            if result.returncode == 0:
                # Try to extract JSON data
                output_data = self._extract_json(result.stdout)
                
                if output_data:
                    return ImplementationResult(
                        language=language,
                        domain=domain,
                        score=output_data.get('overall_score'),
                        grade=output_data.get('grade'),
                        probe_count=len(output_data.get('probe_results', [])),
                        execution_time=execution_time,
                        success=True,
                        raw_output=result.stdout,
                        error=None
                    )
                else:
                    # Fallback: parse human-readable output
                    score, grade = self._parse_human_output(result.stdout)
                    return ImplementationResult(
                        language=language,
                        domain=domain,
                        score=score,
                        grade=grade,
                        probe_count=self._count_probes_in_output(result.stdout),
                        execution_time=execution_time,
                        success=True,
                        raw_output=result.stdout,
                        error=None
                    )
            else:
                return ImplementationResult(
                    language=language,
                    domain=domain,
                    score=None,
                    grade=None,
                    probe_count=0,
                    execution_time=execution_time,
                    success=False,
                    raw_output=result.stdout,
                    error=result.stderr
                )
                
        except subprocess.TimeoutExpired:
            return ImplementationResult(
                language=language,
                domain=domain,
                score=None,
                grade=None,
                probe_count=0,
                execution_time=30,
                success=False,
                raw_output="",
                error="Timeout"
            )
        except Exception as e:
            return ImplementationResult(
                language=language,
                domain=domain,
                score=None,
                grade=None,
                probe_count=0,
                execution_time=time.time() - start_time,
                success=False,
                raw_output="",
                error=str(e)
            )
    
    def _extract_json(self, output: str) -> Optional[Dict[str, Any]]:
        """Extract JSON from output."""
        lines = output.strip().split('\n')
        for line in lines:
            line = line.strip()
            if line.startswith('{') and line.endswith('}'):
                try:
                    return json.loads(line)
                except json.JSONDecodeError:
                    continue
        return None
    
    def _parse_human_output(self, output: str) -> tuple[Optional[float], Optional[str]]:
        """Parse score and grade from human-readable output."""
        lines = output.split('\n')
        score = None
        grade = None
        
        for line in lines:
            # Look for score patterns
            if 'Score:' in line or 'score:' in line:
                try:
                    # Extract percentage
                    import re
                    score_match = re.search(r'(\d+(?:\.\d+)?)%', line)
                    if score_match:
                        score = float(score_match.group(1)) / 100.0
                except:
                    pass
            
            # Look for grade patterns
            if any(g in line for g in ['A+', 'A', 'B', 'C', 'D', 'E', 'F']):
                for g in ['A+', 'A', 'B', 'C', 'D', 'E', 'F']:
                    if g in line:
                        grade = g
                        break
        
        return score, grade
    
    def _count_probes_in_output(self, output: str) -> int:
        """Count probes mentioned in output."""
        probe_indicators = ['TLS', 'DNS', 'HTTPS', 'Security Headers', 'tls', 'dns', 'https', 'security_headers']
        count = 0
        for indicator in probe_indicators:
            if indicator in output:
                count += 1
        return min(count, 4)  # Cap at 4 main probes
    
    def validate_domain(self, domain: str, languages: List[str]) -> Dict[str, Any]:
        """Validate a domain across multiple languages."""
        print(f"🌐 Validating {domain}...")
        
        domain_results = {}
        for language in languages:
            print(f"  🔄 {language}...", end=' ')
            result = self.run_implementation(language, domain)
            domain_results[language] = result
            
            if result.success and result.score is not None:
                print(f"✅ {result.score:.2f} ({result.grade})")
            elif result.success:
                print(f"✅ (no score)")
            else:
                print(f"❌ {result.error}")
        
        # Store results
        self.results[domain] = domain_results
        
        # Analyze consistency
        successful_results = {lang: res for lang, res in domain_results.items() if res.success and res.score is not None}
        
        if len(successful_results) >= 2:
            scores = [res.score for res in successful_results.values()]
            score_variance = max(scores) - min(scores)
            
            probe_counts = [res.probe_count for res in successful_results.values()]
            probe_consistency = len(set(probe_counts)) == 1
            
            return {
                'domain': domain,
                'implementations_tested': len(domain_results),
                'successful_implementations': len(successful_results),
                'score_variance': score_variance,
                'score_consistent': score_variance <= 0.1,  # 10% tolerance
                'probe_consistency': probe_consistency,
                'results': domain_results
            }
        else:
            return {
                'domain': domain,
                'implementations_tested': len(domain_results),
                'successful_implementations': len(successful_results),
                'score_variance': None,
                'score_consistent': None,
                'probe_consistency': None,
                'results': domain_results
            }
    
    def run_full_validation(self, languages: List[str], domains: List[str]) -> Dict[str, Any]:
        """Run full cross-language validation."""
        print("🚀 DQIX Cross-Language Validation Suite")
        print("=" * 50)
        print(f"Languages: {', '.join(languages)}")
        print(f"Domains: {', '.join(domains)}")
        print()
        
        validation_results = []
        
        for domain in domains:
            domain_validation = self.validate_domain(domain, languages)
            validation_results.append(domain_validation)
        
        # Generate summary
        total_tests = sum(v['implementations_tested'] for v in validation_results)
        successful_tests = sum(v['successful_implementations'] for v in validation_results)
        consistent_scores = sum(1 for v in validation_results if v['score_consistent'] is True)
        consistent_probes = sum(1 for v in validation_results if v['probe_consistency'] is True)
        
        summary = {
            'total_implementations_tested': total_tests,
            'successful_implementations': successful_tests,
            'success_rate': successful_tests / total_tests if total_tests > 0 else 0,
            'score_consistency_rate': consistent_scores / len(domains),
            'probe_consistency_rate': consistent_probes / len(domains),
            'validation_results': validation_results
        }
        
        print("\n" + "=" * 50)
        print("📊 VALIDATION SUMMARY")
        print("=" * 50)
        print(f"Success rate: {summary['success_rate']:.1%}")
        print(f"Score consistency: {summary['score_consistency_rate']:.1%}")
        print(f"Probe consistency: {summary['probe_consistency_rate']:.1%}")
        
        if summary['score_consistency_rate'] >= 0.8 and summary['probe_consistency_rate'] >= 0.8:
            print("✅ Cross-language validation PASSED")
        else:
            print("❌ Cross-language validation FAILED")
        
        return summary
    
    def generate_report(self, output_file: str = "cross-language-validation-report.json"):
        """Generate detailed validation report."""
        report = {
            'metadata': {
                'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
                'validator_version': '2.0.0'
            },
            'results': {}
        }
        
        for domain, implementations in self.results.items():
            report['results'][domain] = {}
            for language, result in implementations.items():
                report['results'][domain][language] = {
                    'success': result.success,
                    'score': result.score,
                    'grade': result.grade,
                    'probe_count': result.probe_count,
                    'execution_time': result.execution_time,
                    'error': result.error
                }
        
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"📄 Detailed report saved to: {output_file}")

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="DQIX Cross-Language Validation")
    parser.add_argument("--languages", nargs="+", 
                       default=["go", "bash"],
                       choices=["python", "go", "rust", "haskell", "bash"],
                       help="Languages to validate")
    parser.add_argument("--domains", nargs="+",
                       default=["example.com", "google.com", "github.com"],
                       help="Domains to test")
    parser.add_argument("--output", default="cross-language-validation-report.json",
                       help="Output file for detailed report")
    
    args = parser.parse_args()
    
    validator = CrossLanguageValidator()
    summary = validator.run_full_validation(args.languages, args.domains)
    validator.generate_report(args.output)