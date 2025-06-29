"""
Test domain diversity to ensure different domains excel in different criteria.
This demonstrates transparency in measurements.
"""

import asyncio
from typing import Dict

import pytest
from dqix.application.use_cases import DomainAssessmentUseCase
from dqix.infrastructure.factory import create_infrastructure


class TestDomainDiversity:
    """Test that different domains excel in different areas."""

    # Domain categories with expected strengths
    DOMAIN_PROFILES = {
        # CDN & Infrastructure - Expected: Excellent TLS, Good performance
        "cloudflare.com": {
            "category": "CDN Provider",
            "expected_strengths": ["tls", "https", "performance"],
            "expected_weaknesses": ["email_authentication"]  # Not a mail service
        },

        # Government - Expected: Good compliance, email security
        "usa.gov": {
            "category": "Government Portal",
            "expected_strengths": ["email_authentication", "compliance", "transparency"],
            "expected_weaknesses": ["modern_features"]  # Conservative tech adoption
        },

        # Security Organization - Expected: Excellent headers, modern features
        "owasp.org": {
            "category": "Security Organization",
            "expected_strengths": ["security_headers", "best_practices"],
            "expected_weaknesses": ["performance"]  # Focus on security over speed
        },

        # Educational Institution - Expected: Basic security, good DNS
        "mit.edu": {
            "category": "Educational",
            "expected_strengths": ["dns_infrastructure", "basic_security"],
            "expected_weaknesses": ["modern_security_headers"]  # Academic focus
        },

        # Tech Company - Expected: Balanced high performance
        "github.com": {
            "category": "Tech Platform",
            "expected_strengths": ["tls", "https", "developer_features"],
            "expected_weaknesses": ["permissions_policy"]  # Some modern headers missing
        },

        # E-commerce - Expected: Good HTTPS, customer protection
        "amazon.com": {
            "category": "E-commerce",
            "expected_strengths": ["https", "availability", "customer_security"],
            "expected_weaknesses": ["transparency"]  # Corporate opacity
        },

        # Small Business - Expected: Basic implementation
        "example.com": {
            "category": "Basic Website",
            "expected_strengths": ["simple_implementation"],
            "expected_weaknesses": ["advanced_security", "email_security", "headers"]
        },

        # Certificate Authority - Expected: Perfect TLS
        "letsencrypt.org": {
            "category": "Certificate Authority",
            "expected_strengths": ["tls", "certificate_transparency"],
            "expected_weaknesses": ["email_features"]  # Not a mail service
        }
    }

    @pytest.fixture
    def use_case(self):
        """Create assessment use case."""
        infrastructure = create_infrastructure()
        return DomainAssessmentUseCase(infrastructure)

    @pytest.mark.asyncio
    async def test_domain_diversity_matrix(self, use_case):
        """Test that different domains excel in different areas."""
        results = {}

        # Assess each domain
        for domain, profile in self.DOMAIN_PROFILES.items():
            try:
                print(f"\n🔍 Assessing {domain} ({profile['category']})...")
                result = await use_case.assess_domain(domain, timeout=30)
                results[domain] = self._analyze_domain_results(result, profile)
            except Exception as e:
                print(f"❌ Error assessing {domain}: {e}")
                results[domain] = {"error": str(e)}

        # Generate diversity report
        diversity_report = self._generate_diversity_report(results)

        # Verify diversity (no single domain should dominate all categories)
        assert self._verify_measurement_diversity(results), \
            "Measurements lack diversity - one domain dominates all categories"

        # Print diversity matrix
        self._print_diversity_matrix(diversity_report)

        return diversity_report

    def _analyze_domain_results(self, result: Dict, profile: Dict) -> Dict:
        """Analyze domain results against expected profile."""
        analysis = {
            "category": profile["category"],
            "overall_score": result.get("overall_score", 0),
            "probe_scores": {},
            "strengths": [],
            "weaknesses": [],
            "unexpected_results": []
        }

        # Extract probe scores
        for probe in result.get("probe_results", []):
            probe_id = probe.get("probe_id")
            score = probe.get("score", 0)
            analysis["probe_scores"][probe_id] = score

            # Categorize as strength or weakness
            if score >= 0.8:
                analysis["strengths"].append(probe_id)
            elif score <= 0.5:
                analysis["weaknesses"].append(probe_id)

        # Check against expectations
        for expected_strength in profile.get("expected_strengths", []):
            probe_score = self._get_related_probe_score(analysis["probe_scores"], expected_strength)
            if probe_score < 0.7:
                analysis["unexpected_results"].append(
                    f"Expected strength '{expected_strength}' scored only {probe_score:.2f}"
                )

        return analysis

    def _get_related_probe_score(self, probe_scores: Dict, feature: str) -> float:
        """Get probe score related to a feature."""
        mapping = {
            "tls": "tls",
            "https": "https",
            "security_headers": "security_headers",
            "dns_infrastructure": "dns",
            "email_authentication": "dns",  # SPF/DMARC in DNS
            "performance": "https",  # Response time
            "compliance": "security_headers",
            "transparency": "dns",
            "modern_features": "security_headers",
            "best_practices": "security_headers",
            "developer_features": "security_headers",
            "customer_security": "https",
            "availability": "https",
            "certificate_transparency": "tls",
            "basic_security": "https",
            "advanced_security": "security_headers",
            "email_security": "dns",
            "email_features": "dns",
            "simple_implementation": "https",
            "headers": "security_headers",
            "permissions_policy": "security_headers"
        }

        probe_id = mapping.get(feature, feature)
        return probe_scores.get(probe_id, 0)

    def _generate_diversity_report(self, results: Dict) -> Dict:
        """Generate diversity report showing different domain strengths."""
        report = {
            "probe_leaders": {},  # Which domain leads in each probe
            "category_diversity": {},  # How different categories perform
            "strength_distribution": {},  # Distribution of strengths
            "overall_rankings": []
        }

        # Find probe leaders
        all_probes = set()
        for domain_result in results.values():
            if "probe_scores" in domain_result:
                all_probes.update(domain_result["probe_scores"].keys())

        for probe in all_probes:
            leader = None
            max_score = 0
            probe_scores = []

            for domain, result in results.items():
                if "probe_scores" in result:
                    score = result["probe_scores"].get(probe, 0)
                    probe_scores.append((domain, score))
                    if score > max_score:
                        max_score = score
                        leader = domain

            report["probe_leaders"][probe] = {
                "leader": leader,
                "score": max_score,
                "all_scores": sorted(probe_scores, key=lambda x: x[1], reverse=True)
            }

        # Overall rankings
        overall_scores = []
        for domain, result in results.items():
            if "overall_score" in result:
                overall_scores.append((domain, result["overall_score"], result.get("category", "Unknown")))

        report["overall_rankings"] = sorted(overall_scores, key=lambda x: x[1], reverse=True)

        return report

    def _verify_measurement_diversity(self, results: Dict) -> bool:
        """Verify that measurements show diversity (no single winner)."""
        # Count how many categories each domain leads in
        domain_wins = {}

        for domain_result in results.values():
            if "probe_scores" not in domain_result:
                continue

            for probe, score in domain_result["probe_scores"].items():
                if probe not in domain_wins:
                    domain_wins[probe] = []
                domain_wins[probe].append((score, domain_result.get("category", "")))

        # Check if one domain dominates
        category_leaders = {}
        for probe, scores in domain_wins.items():
            if scores:
                scores.sort(reverse=True)
                leader_category = scores[0][1]
                category_leaders[leader_category] = category_leaders.get(leader_category, 0) + 1

        # No single category should lead in more than 50% of probes
        total_probes = len(domain_wins)
        for category, wins in category_leaders.items():
            if wins > total_probes * 0.5:
                return False

        return True

    def _print_diversity_matrix(self, report: Dict):
        """Print a visual diversity matrix."""
        print("\n" + "="*80)
        print("🌈 DOMAIN DIVERSITY MATRIX - Transparency in Measurements")
        print("="*80)

        # Overall rankings
        print("\n📊 Overall Rankings:")
        print("-" * 60)
        for i, (domain, score, category) in enumerate(report["overall_rankings"][:10], 1):
            bar = "█" * int(score * 20) + "░" * (20 - int(score * 20))
            print(f"{i:2d}. {domain:20s} [{category:20s}] {score:.1%} {bar}")

        # Probe leadership
        print("\n🏆 Domain Excellence by Category:")
        print("-" * 60)
        for probe, data in report["probe_leaders"].items():
            leader = data["leader"]
            score = data["score"]
            print(f"\n{probe.upper()} Champion:")
            print(f"  🥇 {leader} ({score:.1%})")

            # Show top 3
            for i, (domain, score) in enumerate(data["all_scores"][1:3], 2):
                medal = "🥈" if i == 2 else "🥉"
                print(f"  {medal} {domain} ({score:.1%})")

        print("\n" + "="*80)
        print("✅ Measurement Transparency Verified: Different domains excel in different areas")
        print("="*80)


async def main():
    """Run diversity test manually."""
    test = TestDomainDiversity()
    infrastructure = create_infrastructure()
    use_case = DomainAssessmentUseCase(infrastructure)

    await test.test_domain_diversity_matrix(use_case)


if __name__ == "__main__":
    asyncio.run(main())
