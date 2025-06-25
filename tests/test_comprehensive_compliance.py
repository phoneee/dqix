"""Comprehensive compliance testing for DQIX Internet Governance Framework."""

import unittest
from unittest.mock import Mock, patch
import yaml

from dqix.core.academic_references import (
    ComplianceMetrics,
    calculate_compliance_metrics,
    generate_governance_report,
    InternetGovernanceLevels,
)


class TestComprehensiveCompliance(unittest.TestCase):
    """Test comprehensive compliance assessment functionality."""

    def setUp(self):
        """Set up test environment."""
        self.sample_probe_results = {
            "tls": 0.85,
            "dnssec": 0.78,
            "spf": 0.72,
            "dmarc": 0.80,
            "dkim": 0.75,
            "headers": 0.88,
            "privacy_policy": 0.70,
            "cookie_consent": 0.65,
            "gdpr": 0.60,
            "accessibility": 0.75,
            "whois": 0.85,
            "caa": 0.70,
            "dns_basic": 0.80,
            "mx": 0.75,
            "reputation": 0.90,
        }

    def test_scoring_weights_sum_to_one(self):
        """Test that scoring weights in each level sum to approximately 1.0."""
        # Load configuration from file
        try:
            with open("dqix/presets/all_levels.yaml", "r") as f:
                config = yaml.safe_load(f)
        except FileNotFoundError:
            self.skipTest("Configuration file not found")

        for level_name in ["level1", "level2", "level3"]:
            if level_name in config:
                probes = config[level_name]["probes"]
                total_weight = sum(probes.values())
                
                # Allow for small floating point variations
                self.assertAlmostEqual(
                    total_weight, 1.0, places=2,
                    msg=f"{level_name} weights sum to {total_weight}, expected ~1.0"
                )

    def test_compliance_categories_coverage(self):
        """Test that compliance categories cover all aspects properly."""
        metrics = calculate_compliance_metrics(self.sample_probe_results)
        
        # Verify all compliance areas are measured
        self.assertGreater(metrics.transport_security_score, 0.0)
        self.assertGreater(metrics.dns_security_score, 0.0)
        self.assertGreater(metrics.email_security_score, 0.0)
        self.assertGreater(metrics.web_security_score, 0.0)
        self.assertGreater(metrics.accessibility_score, 0.0)
        self.assertGreater(metrics.transparency_score, 0.0)

    def test_progressive_scoring_levels(self):
        """Test that higher levels require progressively higher scores."""
        levels = [
            InternetGovernanceLevels.BASIC,
            InternetGovernanceLevels.STANDARD,
            InternetGovernanceLevels.ADVANCED,
        ]
        
        # Verify progressive target scores
        for i in range(len(levels) - 1):
            self.assertLess(
                levels[i].target_score,
                levels[i + 1].target_score,
                f"Level {i} should have lower target than level {i + 1}"
            )

    def test_baseline_requirement_enforcement(self):
        """Test that baseline requirements are properly enforced."""
        # Test with failing baseline probes
        failing_baseline_results = {
            "tls": 0.3,      # Below baseline
            "dns_basic": 0.2, # Below baseline
            "spf": 0.4,      # Below baseline
            "other_probe": 0.9,  # High score but not baseline
        }
        
        metrics = calculate_compliance_metrics(failing_baseline_results)
        
        # Overall score should be affected by baseline failures
        self.assertLess(metrics.overall_compliance_score, 0.6)
        self.assertEqual(metrics.compliance_level, "needs_improvement")

    def test_excellence_bonus_scoring(self):
        """Test that excellence in all areas provides bonus scoring."""
        excellent_results = {k: 0.95 for k in self.sample_probe_results.keys()}
        
        metrics = calculate_compliance_metrics(excellent_results)
        
        # Should achieve excellent compliance level
        self.assertGreaterEqual(metrics.overall_compliance_score, 0.9)
        self.assertEqual(metrics.compliance_level, "excellent")

    def test_category_weight_balance(self):
        """Test that category weights are balanced appropriately."""
        # Test with results skewed toward one category
        security_heavy_results = {
            "tls": 0.95,
            "dnssec": 0.95,
            "headers": 0.95,
            "spf": 0.30,
            "dmarc": 0.30,
            "privacy_policy": 0.30,
            "accessibility": 0.30,
        }
        
        metrics = calculate_compliance_metrics(security_heavy_results)
        
        # Security should be high, but overall should be limited by other areas
        self.assertGreater(metrics.transport_security_score, 0.9)
        self.assertLess(metrics.overall_compliance_score, 0.8)

    def test_governance_report_completeness(self):
        """Test that governance reports include all required sections."""
        report = generate_governance_report(
            domain="example.com",
            score=0.82,
            probe_results=self.sample_probe_results,
            target_level=InternetGovernanceLevels.STANDARD,
        )
        
        # Verify all required sections are present
        required_sections = [
            "domain",
            "overall_score",
            "status",
            "assessment_level",
            "governance_compliance",
            "detailed_compliance",
            "recommendations",
            "framework",
        ]
        
        for section in required_sections:
            self.assertIn(section, report, f"Missing required section: {section}")

    def test_specific_recommendations_generation(self):
        """Test that specific recommendations are generated based on probe results."""
        # Test with specific low scores
        problematic_results = {
            "tls": 0.5,        # Should trigger TLS recommendation
            "dnssec": 0.3,     # Should trigger DNSSEC recommendation
            "dmarc": 0.2,      # Should trigger email auth recommendation
            "headers": 0.4,    # Should trigger headers recommendation
            "accessibility": 0.3, # Should trigger accessibility recommendation
        }
        
        report = generate_governance_report(
            domain="example.com",
            score=0.35,
            probe_results=problematic_results,
            target_level=InternetGovernanceLevels.STANDARD,
        )
        
        recommendations = report["recommendations"]
        missing_requirements = report["missing_requirements"]
        
        # Should have specific recommendations for each low-scoring area
        self.assertTrue(len(recommendations) >= 4)
        self.assertTrue(len(missing_requirements) >= 4)
        
        # Check for specific recommendation categories
        self.assertIn("Transport Security", missing_requirements)
        self.assertIn("DNS Security", missing_requirements)
        self.assertIn("Email Authentication", missing_requirements)

    def test_compliance_level_consistency(self):
        """Test that compliance levels are consistent across different scoring methods."""
        test_cases = [
            (0.95, "excellent"),
            (0.85, "good"),
            (0.70, "adequate"),
            (0.45, "needs_improvement"),
        ]
        
        for score, expected_level in test_cases:
            # Create probe results that would achieve this score
            uniform_results = {k: score for k in self.sample_probe_results.keys()}
            metrics = calculate_compliance_metrics(uniform_results)
            
            # The exact score might differ due to weighting, but level should be consistent
            if expected_level == "excellent":
                self.assertGreaterEqual(metrics.overall_compliance_score, 0.9)
            elif expected_level == "good":
                self.assertGreaterEqual(metrics.overall_compliance_score, 0.8)
            elif expected_level == "adequate":
                self.assertGreaterEqual(metrics.overall_compliance_score, 0.6)
            else:  # needs_improvement
                self.assertLess(metrics.overall_compliance_score, 0.6)

    def test_privacy_compliance_weighting(self):
        """Test that privacy compliance is properly weighted in overall score."""
        # Test with strong privacy but weak security
        privacy_strong_results = {
            "privacy_policy": 0.95,
            "cookie_consent": 0.95,
            "gdpr": 0.95,
            "tls": 0.30,
            "dnssec": 0.30,
            "headers": 0.30,
        }
        
        metrics = calculate_compliance_metrics(privacy_strong_results)
        
        # Privacy should be high
        self.assertGreater(metrics.gdpr_compliance_score, 0.9)
        self.assertTrue(metrics.privacy_policy_present)
        self.assertTrue(metrics.cookie_consent_present)
        
        # But overall should be limited by security weaknesses
        self.assertLess(metrics.overall_compliance_score, 0.7)

    def test_accessibility_compliance_levels(self):
        """Test WCAG compliance level assignment accuracy."""
        test_cases = [
            (0.95, "AA"),
            (0.85, "A"), 
            (0.60, "none"),
            (0.0, "none"),
        ]
        
        for accessibility_score, expected_level in test_cases:
            probe_results = {"accessibility": accessibility_score}
            metrics = calculate_compliance_metrics(probe_results)
            
            self.assertEqual(
                metrics.wcag_compliance_level, expected_level,
                f"Score {accessibility_score} should result in WCAG level {expected_level}"
            )

    def test_governance_transparency_scoring(self):
        """Test governance transparency scoring accuracy."""
        transparency_results = {
            "whois": 0.9,      # High transparency
            "caa": 0.8,        # Good accountability
            "reputation": 0.85, # Good reputation
            "tls": 0.8,        # Good for multistakeholder calc
            "dnssec": 0.7,     # DNS security
            "spf": 0.72,       # SPF for email security
            "dmarc": 0.78,     # DMARC for email security  
            "dkim": 0.75,      # DKIM for email security
            "headers": 0.8,    # Web security
        }
        
        metrics = calculate_compliance_metrics(transparency_results)
        
        # Verify governance scoring
        self.assertEqual(metrics.transparency_score, 0.9)
        self.assertEqual(metrics.accountability_score, 0.8)
        
        # Multistakeholder score should be average of security scores
        # It uses: transport_security (tls), dns_security (dnssec), 
        # email_security (avg of spf/dmarc/dkim), web_security (headers)
        expected_email_security = (0.72 + 0.78 + 0.75) / 3  # 0.75
        expected_multistakeholder = (0.8 + 0.7 + 0.75 + 0.8) / 4  # 0.7625
        
        self.assertAlmostEqual(
            metrics.multistakeholder_score, expected_multistakeholder, places=2
        )


class TestConfigurationValidation(unittest.TestCase):
    """Test configuration file validation and consistency."""

    def test_configuration_file_structure(self):
        """Test that configuration file has proper structure."""
        try:
            with open("dqix/presets/all_levels.yaml", "r") as f:
                config = yaml.safe_load(f)
        except FileNotFoundError:
            self.skipTest("Configuration file not found")

        # Verify required top-level sections
        required_sections = [
            "level1", "level2", "level3",
            "compliance_categories",
            "minimum_requirements",
            "scoring",
        ]

        for section in required_sections:
            self.assertIn(section, config, f"Missing required section: {section}")

    def test_compliance_categories_consistency(self):
        """Test that compliance categories are properly defined."""
        try:
            with open("dqix/presets/all_levels.yaml", "r") as f:
                config = yaml.safe_load(f)
        except FileNotFoundError:
            self.skipTest("Configuration file not found")

        if "compliance_categories" in config:
            categories = config["compliance_categories"]
            
            # Verify category weights sum to 1.0
            total_weight = sum(cat["weight"] for cat in categories.values())
            self.assertAlmostEqual(total_weight, 1.0, places=2)
            
            # Verify each category has required fields
            for cat_name, cat_config in categories.items():
                self.assertIn("weight", cat_config)
                self.assertIn("description", cat_config)
                self.assertIn("critical_probes", cat_config)
                self.assertIsInstance(cat_config["critical_probes"], list)


if __name__ == "__main__":
    unittest.main() 