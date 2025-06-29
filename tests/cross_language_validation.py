#!/usr/bin/env python3
"""
Cross-Language Validation Tests for DQIX
Ensures consistency across all language implementations
"""

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Dict

# Test domains
TEST_DOMAINS = [
    "example.com",
    "google.com",
    "github.com",
    "badssl.com"
]

# Expected probe weights
EXPECTED_WEIGHTS = {
    "tls": 0.35,
    "dns": 0.25,
    "https": 0.20,
    "security_headers": 0.20
}

# Expected score thresholds
EXPECTED_THRESHOLDS = {
    "excellent": 0.8,
    "good": 0.6,
    "fair": 0.4
}

# Language implementations
IMPLEMENTATIONS = {
    "python": {
        "path": "dqix-python",
        "command": ["python", "-m", "dqix", "scan"],
        "json_flag": "--output=json"
    },
    "bash": {
        "path": "dqix-cli",
        "command": ["./dqix-multi", "scan"],
        "json_flag": None  # Bash outputs JSON by default for consistency testing
    },
    "go": {
        "path": "dqix-go",
        "command": ["./dqix", "scan"],
        "json_flag": "--output=json"
    },
    "rust": {
        "path": "dqix-rust",
        "command": ["./target/release/dqix"],
        "json_flag": "--output=json"
    },
    "haskell": {
        "path": "dqix-haskell",
        "command": ["./dqix", "scan"],
        "json_flag": None  # Haskell doesn't have JSON output yet
    }
}

class CrossLanguageValidator:
    def __init__(self):
        self.base_dir = Path(__file__).parent.parent
        self.results = {}
        self.validation_errors = []

    def run_implementation(self, lang: str, domain: str) -> Dict:
        """Run a specific language implementation and capture output"""
        impl = IMPLEMENTATIONS[lang]
        path = self.base_dir / impl["path"]

        # Build command
        cmd = impl["command"] + [domain]
        if impl["json_flag"]:
            cmd.append(impl["json_flag"])

        # For implementations without JSON, we'll parse text output
        try:
            # Change to implementation directory
            original_dir = os.getcwd()
            os.chdir(path)

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30
            )

            os.chdir(original_dir)

            if result.returncode != 0:
                print(f"Error running {lang}: {result.stderr}")
                return None

            # Parse output based on language
            if lang in ["python", "go", "rust"] and impl["json_flag"]:
                try:
                    return json.loads(result.stdout)
                except json.JSONDecodeError:
                    # Extract JSON from mixed output
                    lines = result.stdout.split('\n')
                    for line in lines:
                        if line.strip().startswith('{'):
                            return json.loads(line)
            else:
                # Parse text output for basic info
                return self.parse_text_output(lang, result.stdout)

        except subprocess.TimeoutExpired:
            print(f"Timeout running {lang} implementation")
            return None
        except Exception as e:
            print(f"Error running {lang}: {e}")
            return None

    def parse_text_output(self, lang: str, output: str) -> Dict:
        """Parse text output to extract key metrics"""
        result = {
            "domain": None,
            "overall_score": None,
            "probe_results": [],
            "metadata": {"engine": f"{lang} DQIX"}
        }

        lines = output.split('\n')

        # Extract domain and overall score
        for line in lines:
            if "Analyzing:" in line or "Domain:" in line:
                result["domain"] = line.split()[-1]
            elif "Overall Score:" in line or "Security Score:" in line:
                # Extract percentage
                import re
                match = re.search(r'(\d+(?:\.\d+)?)\s*%', line)
                if match:
                    result["overall_score"] = float(match.group(1)) / 100.0

            # Extract probe scores (simplified)
            for probe in ["TLS", "DNS", "HTTPS", "Security Headers"]:
                if probe in line and "%" in line:
                    match = re.search(r'(\d+(?:\.\d+)?)\s*%', line)
                    if match:
                        probe_id = probe.lower().replace(" ", "_")
                        if probe == "Security Headers":
                            probe_id = "security_headers"
                        result["probe_results"].append({
                            "probe_id": probe_id,
                            "score": float(match.group(1)) / 100.0
                        })

        return result

    def validate_consistency(self, results: Dict[str, Dict], domain: str):
        """Validate consistency across implementations"""
        print(f"\n🔍 Validating consistency for {domain}")
        print("=" * 60)

        # Collect valid results
        valid_results = {
            lang: res for lang, res in results.items()
            if res and res.get("overall_score") is not None
        }

        if len(valid_results) < 2:
            print("⚠️  Not enough valid results for comparison")
            return

        # 1. Compare overall scores
        scores = {
            lang: res["overall_score"]
            for lang, res in valid_results.items()
        }

        print("\n📊 Overall Scores:")
        for lang, score in sorted(scores.items()):
            print(f"  {lang:10} {score*100:6.2f}%")

        # Check score variance (should be within 10%)
        score_values = list(scores.values())
        min_score = min(score_values)
        max_score = max(score_values)
        variance = (max_score - min_score) / max_score if max_score > 0 else 0

        if variance > 0.1:
            self.validation_errors.append(
                f"High score variance for {domain}: {variance*100:.1f}% "
                f"(min: {min_score*100:.1f}%, max: {max_score*100:.1f}%)"
            )
            print(f"\n❌ High score variance: {variance*100:.1f}%")
        else:
            print(f"\n✅ Score variance within tolerance: {variance*100:.1f}%")

        # 2. Compare probe scores
        print("\n🔍 Probe Score Comparison:")
        probe_scores = {}

        for lang, res in valid_results.items():
            if "probe_results" in res:
                for probe in res["probe_results"]:
                    probe_id = probe.get("probe_id", "")
                    score = probe.get("score", 0)

                    if probe_id not in probe_scores:
                        probe_scores[probe_id] = {}
                    probe_scores[probe_id][lang] = score

        # Display probe comparison
        for probe_id in sorted(probe_scores.keys()):
            print(f"\n  {probe_id}:")
            scores = probe_scores[probe_id]

            for lang, score in sorted(scores.items()):
                print(f"    {lang:10} {score*100:6.2f}%")

            # Check probe score variance
            probe_values = list(scores.values())
            if len(probe_values) > 1:
                min_probe = min(probe_values)
                max_probe = max(probe_values)
                probe_variance = (max_probe - min_probe) / max_probe if max_probe > 0 else 0

                if probe_variance > 0.15:
                    self.validation_errors.append(
                        f"High variance for {probe_id} on {domain}: "
                        f"{probe_variance*100:.1f}%"
                    )

    def run_validation(self):
        """Run full cross-language validation"""
        print("🚀 DQIX Cross-Language Validation Test Suite")
        print("=" * 60)

        # Check which implementations are available
        available_langs = []
        for lang, impl in IMPLEMENTATIONS.items():
            path = self.base_dir / impl["path"]
            if path.exists():
                # Check if binary exists
                if lang == "python":
                    available_langs.append(lang)
                else:
                    binary = path / impl["command"][0].lstrip("./")
                    if binary.exists() or (path / impl["command"][0]).exists():
                        available_langs.append(lang)

        print(f"\n📦 Available implementations: {', '.join(available_langs)}")

        if len(available_langs) < 2:
            print("\n⚠️  Need at least 2 implementations for comparison")
            return False

        # Test each domain
        for domain in TEST_DOMAINS:
            print(f"\n\n🌐 Testing domain: {domain}")
            print("-" * 40)

            domain_results = {}

            # Run each implementation
            for lang in available_langs:
                print(f"  Running {lang}...", end=" ", flush=True)
                result = self.run_implementation(lang, domain)

                if result:
                    domain_results[lang] = result
                    print("✅")
                else:
                    print("❌")

            # Validate consistency
            if len(domain_results) >= 2:
                self.validate_consistency(domain_results, domain)

        # Final report
        print("\n\n" + "=" * 60)
        print("📋 VALIDATION SUMMARY")
        print("=" * 60)

        if not self.validation_errors:
            print("\n✅ All implementations are consistent!")
            return True
        else:
            print(f"\n❌ Found {len(self.validation_errors)} validation errors:\n")
            for error in self.validation_errors:
                print(f"  • {error}")
            return False

    def generate_report(self):
        """Generate detailed validation report"""
        report_path = self.base_dir / "CROSS_LANGUAGE_VALIDATION_REPORT.md"

        with open(report_path, "w") as f:
            f.write("# DQIX Cross-Language Validation Report\n\n")
            f.write(f"Generated: {os.popen('date').read().strip()}\n\n")

            f.write("## Summary\n\n")
            if not self.validation_errors:
                f.write("✅ **All implementations passed consistency validation**\n\n")
            else:
                f.write(f"❌ **Found {len(self.validation_errors)} inconsistencies**\n\n")

            f.write("## Test Configuration\n\n")
            f.write("### Test Domains\n")
            for domain in TEST_DOMAINS:
                f.write(f"- {domain}\n")

            f.write("\n### Expected Probe Weights\n")
            for probe, weight in EXPECTED_WEIGHTS.items():
                f.write(f"- {probe}: {weight} ({weight*100}%)\n")

            f.write("\n### Score Thresholds\n")
            for level, threshold in EXPECTED_THRESHOLDS.items():
                f.write(f"- {level}: ≥{threshold} ({threshold*100}%)\n")

            if self.validation_errors:
                f.write("\n## Validation Errors\n\n")
                for i, error in enumerate(self.validation_errors, 1):
                    f.write(f"{i}. {error}\n")

            f.write("\n## Recommendations\n\n")
            f.write("1. Ensure all implementations use consistent probe weights\n")
            f.write("2. Standardize score calculation algorithms\n")
            f.write("3. Implement JSON output for all languages\n")
            f.write("4. Create shared test fixtures for validation\n")

        print(f"\n📄 Report saved to: {report_path}")

def main():
    validator = CrossLanguageValidator()
    success = validator.run_validation()
    validator.generate_report()

    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()
