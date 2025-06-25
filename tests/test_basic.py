"""Basic functionality tests for DQIX Internet Governance Framework."""

import pytest
import unittest
from unittest.mock import patch

from dqix.core.academic_references import (
    DomainQualityGovernance,
    GovernanceFramework,
    InternetGovernanceLevels,
    generate_governance_report,
    ComplianceMetrics,
    calculate_compliance_metrics,
)


def test_imports():
    """Test basic DQIX imports work."""
    # Test governance framework imports
    assert DomainQualityGovernance is not None
    assert GovernanceFramework is not None
    assert InternetGovernanceLevels is not None
    assert generate_governance_report is not None


def test_governance_frameworks():
    """Test governance framework definitions."""
    # Test governance framework enumeration
    assert GovernanceFramework.WCAG_2_2.value == "wcag-2.2"
    assert GovernanceFramework.NIST_CYBERSECURITY_FRAMEWORK.value == "nist-csf"
    assert GovernanceFramework.RFC_6797_HSTS.value == "rfc-6797-hsts"
    assert GovernanceFramework.MULTISTAKEHOLDER_APPROACH.value == "multistakeholder"
    assert GovernanceFramework.IGF_BEST_PRACTICES.value == "igf-practices"


def test_governance_references():
    """Test internet governance reference retrieval."""
    references = DomainQualityGovernance.get_governance_references()
    
    # Should have references for key frameworks
    assert GovernanceFramework.MULTISTAKEHOLDER_APPROACH in references
    assert GovernanceFramework.IGF_BEST_PRACTICES in references
    assert GovernanceFramework.WCAG_2_2 in references
    assert GovernanceFramework.RFC_6797_HSTS in references
    
    # Check Harvard Berkman Klein Center reference
    multistakeholder_ref = references[GovernanceFramework.MULTISTAKEHOLDER_APPROACH]
    assert "Harvard Berkman Klein Center" in multistakeholder_ref.organization
    assert "collaborative" in multistakeholder_ref.description.lower()
    
    # Check Internet Society reference  
    igf_ref = references[GovernanceFramework.IGF_BEST_PRACTICES]
    assert "Internet Society" in igf_ref.organization
    assert "governance" in igf_ref.description.lower()


def test_governance_levels():
    """Test internet governance quality levels."""
    # Test basic infrastructure level
    assert InternetGovernanceLevels.BASIC.name == "Basic Infrastructure"
    assert InternetGovernanceLevels.BASIC.target_score == 0.6
    assert "Transport security" in InternetGovernanceLevels.BASIC.focus_areas[0]
    
    # Test standard compliance level
    assert InternetGovernanceLevels.STANDARD.name == "Standard Compliance"
    assert InternetGovernanceLevels.STANDARD.target_score == 0.8
    assert len(InternetGovernanceLevels.STANDARD.focus_areas) >= 3
    
    # Test best practice implementation level
    assert InternetGovernanceLevels.ADVANCED.name == "Best Practice Implementation"
    assert InternetGovernanceLevels.ADVANCED.target_score == 0.9
    assert "governance" in InternetGovernanceLevels.ADVANCED.description.lower()


def test_governance_references_by_category():
    """Test governance reference filtering by category."""
    # Test web standards category
    web_refs = DomainQualityGovernance.get_references_by_category("web_standards")
    assert GovernanceFramework.WCAG_2_2 in web_refs
    
    # Test security category
    security_refs = DomainQualityGovernance.get_references_by_category("security")
    assert GovernanceFramework.NIST_CYBERSECURITY_FRAMEWORK in security_refs
    
    # Test internet standards category
    internet_refs = DomainQualityGovernance.get_references_by_category("internet_standards") 
    assert GovernanceFramework.RFC_6797_HSTS in internet_refs
    assert GovernanceFramework.RFC_4034_DNSSEC in internet_refs
    
    # Test governance category
    governance_refs = DomainQualityGovernance.get_references_by_category("governance")
    assert GovernanceFramework.MULTISTAKEHOLDER_APPROACH in governance_refs
    assert GovernanceFramework.IGF_BEST_PRACTICES in governance_refs


def test_simple_engine_creation():
    """Test simple assessment engine creation."""
    try:
        from dqix.core.engine import create_basic_engine
        engine = create_basic_engine()
        assert engine is not None
    except ImportError:
        # Engine may not be fully implemented yet
        pytest.skip("Engine implementation not available")


@pytest.mark.skipif(True, reason="CLI may require typer dependency")
def test_cli_imports():
    """Test CLI imports work (skipped if typer not available)."""
    try:
        from dqix.cli.main import app
        assert app is not None
    except ImportError:
        pytest.skip("CLI dependencies not available")


def test_governance_report_generation():
    """Test governance report generation."""
    # Generate sample report
    report = generate_governance_report(
        domain="example.com",
        score=0.75,
        probe_results={"tls": 0.8, "dns": 0.7, "email": 0.7},
        target_level=InternetGovernanceLevels.STANDARD,
    )
    
    # Verify report structure
    assert report["domain"] == "example.com"
    assert report["overall_score"] == 0.75
    assert report["status"] == "GOOD"
    assert "internet governance principles" in report["framework"]
    
    # Verify governance compliance metrics
    governance_compliance = report["governance_compliance"]
    assert "multistakeholder_principles" in governance_compliance
    assert "internet_standards_compliance" in governance_compliance
    assert "best_practices_implementation" in governance_compliance
    
    # Check compliance values based on score
    assert governance_compliance["multistakeholder_principles"] is True  # score >= 0.7
    assert governance_compliance["internet_standards_compliance"] is False  # score < 0.8
    assert governance_compliance["best_practices_implementation"] is False  # score < 0.9


class TestGovernanceFramework(unittest.TestCase):
    """Test internet governance framework functionality."""

    def test_governance_framework_enum(self):
        """Test governance framework enum values."""
        # Test web standards
        assert GovernanceFramework.WCAG_2_2.value == "wcag-2.2"
        assert GovernanceFramework.WCAG_2_1.value == "wcag-2.1"
        
        # Test security frameworks
        assert GovernanceFramework.NIST_CYBERSECURITY_FRAMEWORK.value == "nist-csf"
        assert GovernanceFramework.CIS_CONTROLS_V8.value == "cis-controls-v8"
        
        # Test internet standards
        assert GovernanceFramework.RFC_6797_HSTS.value == "rfc-6797-hsts"
        assert GovernanceFramework.RFC_4034_DNSSEC.value == "rfc-4034-dnssec"
        assert GovernanceFramework.RFC_7489_DMARC.value == "rfc-7489-dmarc"
        assert GovernanceFramework.RFC_6844_CAA.value == "rfc-6844-caa"
        
        # Test privacy standards
        assert GovernanceFramework.GDPR_COMPLIANCE.value == "gdpr-compliance"
        assert GovernanceFramework.PRIVACY_POLICY.value == "privacy-policy"
        
        # Test governance frameworks
        assert GovernanceFramework.MULTISTAKEHOLDER_APPROACH.value == "multistakeholder"
        assert GovernanceFramework.IGF_BEST_PRACTICES.value == "igf-practices"
        assert GovernanceFramework.NETMUNDIAL_PRINCIPLES.value == "netmundial"

    def test_governance_references(self):
        """Test governance reference retrieval."""
        references = DomainQualityGovernance.get_governance_references()
        
        # Test that we have references for key frameworks
        assert GovernanceFramework.WCAG_2_2 in references
        assert GovernanceFramework.NIST_CYBERSECURITY_FRAMEWORK in references
        assert GovernanceFramework.RFC_6797_HSTS in references
        assert GovernanceFramework.MULTISTAKEHOLDER_APPROACH in references
        
        # Test reference structure
        wcag_ref = references[GovernanceFramework.WCAG_2_2]
        assert wcag_ref.title == "Web Content Accessibility Guidelines (WCAG) 2.2"
        assert wcag_ref.organization == "World Wide Web Consortium (W3C)"
        assert "w3.org" in wcag_ref.url
        assert wcag_ref.version == "2.2"

    def test_references_by_category(self):
        """Test filtering references by category."""
        # Test web standards category
        web_refs = DomainQualityGovernance.get_references_by_category("web_standards")
        assert GovernanceFramework.WCAG_2_2 in web_refs
        assert GovernanceFramework.WCAG_2_1 in web_refs
        
        # Test security category
        security_refs = DomainQualityGovernance.get_references_by_category("security")
        assert GovernanceFramework.NIST_CYBERSECURITY_FRAMEWORK in security_refs
        assert GovernanceFramework.CIS_CONTROLS_V8 in security_refs
        
        # Test internet standards category
        internet_refs = DomainQualityGovernance.get_references_by_category("internet_standards")
        assert GovernanceFramework.RFC_6797_HSTS in internet_refs
        assert GovernanceFramework.RFC_4034_DNSSEC in internet_refs
        assert GovernanceFramework.RFC_7489_DMARC in internet_refs
        
        # Test privacy category
        privacy_refs = DomainQualityGovernance.get_references_by_category("privacy")
        assert GovernanceFramework.GDPR_COMPLIANCE in privacy_refs
        assert GovernanceFramework.PRIVACY_POLICY in privacy_refs
        
        # Test governance category
        governance_refs = DomainQualityGovernance.get_references_by_category("governance")
        assert GovernanceFramework.MULTISTAKEHOLDER_APPROACH in governance_refs
        assert GovernanceFramework.IGF_BEST_PRACTICES in governance_refs

    def test_quality_levels(self):
        """Test internet governance quality levels."""
        # Test Basic level
        basic = InternetGovernanceLevels.BASIC
        assert basic.name == "Basic Infrastructure"
        assert basic.target_score == 0.6
        assert "Transport security (TLS/HTTPS)" in basic.focus_areas
        assert "HTTPS enabled" in basic.compliance_requirements
        
        # Test Standard level
        standard = InternetGovernanceLevels.STANDARD
        assert standard.name == "Standard Compliance"
        assert standard.target_score == 0.8
        assert "DNS security (DNSSEC)" in standard.focus_areas
        assert "DNSSEC validation" in standard.compliance_requirements
        
        # Test Advanced level
        advanced = InternetGovernanceLevels.ADVANCED
        assert advanced.name == "Best Practice Implementation"
        assert advanced.target_score == 0.9
        assert "Accessibility compliance" in advanced.focus_areas
        assert "WCAG 2.2 accessibility compliance" in advanced.compliance_requirements


class TestComplianceMetrics(unittest.TestCase):
    """Test compliance metrics functionality."""

    def test_compliance_metrics_initialization(self):
        """Test ComplianceMetrics initialization."""
        metrics = ComplianceMetrics()
        
        # Test default values
        assert metrics.transport_security_score == 0.0
        assert metrics.dns_security_score == 0.0
        assert metrics.email_security_score == 0.0
        assert metrics.web_security_score == 0.0
        assert metrics.privacy_policy_present is False
        assert metrics.cookie_consent_present is False
        assert metrics.gdpr_compliance_score == 0.0
        assert metrics.wcag_compliance_level == "none"
        assert metrics.accessibility_score == 0.0
        assert metrics.transparency_score == 0.0
        assert metrics.accountability_score == 0.0
        assert metrics.multistakeholder_score == 0.0
        assert metrics.overall_compliance_score == 0.0
        assert metrics.compliance_level == "basic"

    def test_compliance_score_calculation(self):
        """Test overall compliance score calculation."""
        metrics = ComplianceMetrics()
        
        # Set high scores
        metrics.transport_security_score = 0.9
        metrics.dns_security_score = 0.8
        metrics.email_security_score = 0.7
        metrics.web_security_score = 0.8
        metrics.gdpr_compliance_score = 0.8
        metrics.accessibility_score = 0.9
        metrics.transparency_score = 0.7
        metrics.accountability_score = 0.8
        metrics.multistakeholder_score = 0.8
        
        overall_score = metrics.calculate_overall_compliance()
        
        # Verify score calculation
        expected_security = (0.9 + 0.8 + 0.7 + 0.8) / 4  # 0.8
        expected_privacy = 0.8
        expected_accessibility = 0.9
        expected_governance = (0.7 + 0.8 + 0.8) / 3  # 0.767
        expected_overall = (0.8 * 0.4) + (0.8 * 0.2) + (0.9 * 0.2) + (0.767 * 0.2)
        
        assert abs(overall_score - expected_overall) < 0.01
        assert metrics.overall_compliance_score == overall_score
        assert metrics.compliance_level == "good"  # >= 0.8

    def test_compliance_level_determination(self):
        """Test compliance level determination based on score."""
        metrics = ComplianceMetrics()
        
        # Test excellent level (>= 0.9)
        metrics.transport_security_score = 1.0
        metrics.dns_security_score = 1.0
        metrics.email_security_score = 1.0
        metrics.web_security_score = 1.0
        metrics.gdpr_compliance_score = 1.0
        metrics.accessibility_score = 1.0
        metrics.transparency_score = 1.0
        metrics.accountability_score = 1.0
        metrics.multistakeholder_score = 1.0
        
        metrics.calculate_overall_compliance()
        assert metrics.compliance_level == "excellent"
        
        # Test needs improvement level (< 0.6)
        metrics = ComplianceMetrics()
        metrics.transport_security_score = 0.3
        metrics.dns_security_score = 0.2
        metrics.email_security_score = 0.1
        metrics.web_security_score = 0.2
        metrics.gdpr_compliance_score = 0.1
        metrics.accessibility_score = 0.2
        metrics.transparency_score = 0.1
        metrics.accountability_score = 0.2
        metrics.multistakeholder_score = 0.2
        
        metrics.calculate_overall_compliance()
        assert metrics.compliance_level == "needs_improvement"

    def test_wcag_compliance_level_assignment(self):
        """Test WCAG compliance level assignment."""
        # Test AA level (>= 0.9)
        probe_results = {"accessibility": 0.95}
        metrics = calculate_compliance_metrics(probe_results)
        assert metrics.wcag_compliance_level == "AA"
        
        # Test A level (>= 0.7)
        probe_results = {"accessibility": 0.75}
        metrics = calculate_compliance_metrics(probe_results)
        assert metrics.wcag_compliance_level == "A"
        
        # Test none level (< 0.7)
        probe_results = {"accessibility": 0.5}
        metrics = calculate_compliance_metrics(probe_results)
        assert metrics.wcag_compliance_level == "none"

    def test_calculate_compliance_metrics_function(self):
        """Test calculate_compliance_metrics function."""
        probe_results = {
            "tls": 0.8,
            "dnssec": 0.7,
            "spf": 0.6,
            "dmarc": 0.8,
            "dkim": 0.7,
            "headers": 0.9,
            "privacy_policy": 0.8,
            "cookie_consent": 0.6,
            "gdpr": 0.7,
            "accessibility": 0.8,
            "whois": 0.9,
            "caa": 0.6,
        }
        
        metrics = calculate_compliance_metrics(probe_results)
        
        # Verify security scores
        assert metrics.transport_security_score == 0.8
        assert metrics.dns_security_score == 0.7
        assert metrics.email_security_score == (0.6 + 0.8 + 0.7) / 3  # 0.7
        assert metrics.web_security_score == 0.9
        
        # Verify privacy scores  
        assert metrics.privacy_policy_present is True  # > 0.5
        assert metrics.cookie_consent_present is True  # > 0.5
        assert metrics.gdpr_compliance_score == 0.7
        
        # Verify accessibility
        assert metrics.accessibility_score == 0.8
        assert metrics.wcag_compliance_level == "A"  # >= 0.7
        
        # Verify governance scores
        assert metrics.transparency_score == 0.9
        assert metrics.accountability_score == 0.6
        # multistakeholder_score is average of security scores
        expected_multistakeholder = (0.8 + 0.7 + 0.7 + 0.9) / 4  # 0.775
        assert abs(metrics.multistakeholder_score - expected_multistakeholder) < 0.01


class TestGovernanceReportGeneration(unittest.TestCase):
    """Test governance report generation functionality."""

    def test_governance_report_generation_basic(self):
        """Test basic governance report generation."""
        probe_results = {
            "tls": 0.8,
            "dns": 0.7,
            "email": 0.7,
            "headers": 0.6,
        }
        
        report = generate_governance_report(
            domain="example.com",
            score=0.75,
            probe_results=probe_results,
            target_level=InternetGovernanceLevels.STANDARD,
        )
        
        # Verify basic report structure
        assert report["domain"] == "example.com"
        assert report["overall_score"] == 0.75
        assert report["status"] == "GOOD"
        assert "internet governance principles" in report["framework"]
        
        # Verify assessment level
        assert report["assessment_level"]["name"] == "Standard Compliance"
        assert report["assessment_level"]["target_score"] == 0.8
        assert "compliance_requirements" in report["assessment_level"]
        
        # Verify governance compliance
        governance_compliance = report["governance_compliance"]
        assert governance_compliance["multistakeholder_principles"] is True  # >= 0.7
        assert governance_compliance["internet_standards_compliance"] is False  # < 0.8
        assert governance_compliance["best_practices_implementation"] is False  # < 0.9

    def test_governance_report_with_detailed_compliance(self):
        """Test governance report with detailed compliance metrics."""
        probe_results = {
            "tls": 0.9,
            "dnssec": 0.8,
            "spf": 0.7,
            "dmarc": 0.8,
            "dkim": 0.9,
            "headers": 0.9,
            "accessibility": 0.8,
            "whois": 0.9,
            "caa": 0.7,
        }
        
        report = generate_governance_report(
            domain="example.com",
            score=0.85,
            probe_results=probe_results,
            target_level=InternetGovernanceLevels.ADVANCED,
        )
        
        # Verify detailed compliance is included
        assert "detailed_compliance" in report
        detailed = report["detailed_compliance"]
        
        # Verify security metrics
        assert detailed["security"]["transport_security"] == 0.9
        assert detailed["security"]["dns_security"] == 0.8
        assert abs(detailed["security"]["email_security"] - 0.8) < 0.01  # (0.7+0.8+0.9)/3
        assert detailed["security"]["web_security"] == 0.9
        
        # Verify accessibility metrics
        assert detailed["accessibility"]["score"] == 0.8
        assert detailed["accessibility"]["wcag_level"] == "A"
        
        # Verify governance metrics
        assert detailed["governance"]["transparency"] == 0.9
        assert detailed["governance"]["accountability"] == 0.7
        
        # Verify overall compliance
        assert "overall_compliance" in detailed
        assert detailed["overall_compliance"]["score"] > 0.0
        assert detailed["overall_compliance"]["level"] in ["excellent", "good", "adequate", "needs_improvement"]

    def test_governance_report_recommendations(self):
        """Test governance report recommendation generation."""
        # Test low scores to trigger recommendations
        probe_results = {
            "tls": 0.5,  # Low TLS score
            "dnssec": 0.3,  # Low DNSSEC score
            "dmarc": 0.2,  # Low DMARC score
            "headers": 0.4,  # Low headers score
            "accessibility": 0.3,  # Low accessibility score
        }
        
        report = generate_governance_report(
            domain="example.com",
            score=0.4,
            probe_results=probe_results,
            target_level=InternetGovernanceLevels.STANDARD,
        )
        
        # Verify recommendations are generated
        assert "recommendations" in report
        assert "missing_requirements" in report
        recommendations = report["recommendations"]
        missing_requirements = report["missing_requirements"]
        
        # Should have multiple recommendations for low scores
        assert len(recommendations) > 1
        assert len(missing_requirements) > 0
        
        # Check for specific recommendations
        recommendation_text = " ".join(recommendations)
        assert "TLS" in recommendation_text or "transport" in recommendation_text.lower()
        assert "DNSSEC" in recommendation_text or "dns" in recommendation_text.lower()
        assert "DMARC" in recommendation_text or "email" in recommendation_text.lower()
        
        # Check missing requirements
        assert "Transport Security" in missing_requirements
        assert "DNS Security" in missing_requirements
        assert "Email Authentication" in missing_requirements

    def test_governance_report_excellent_score(self):
        """Test governance report for excellent scores."""
        probe_results = {
            "tls": 0.95,
            "dnssec": 0.92,
            "spf": 0.9,
            "dmarc": 0.93,
            "dkim": 0.9,
            "headers": 0.94,
            "accessibility": 0.91,
            "whois": 0.9,
            "caa": 0.88,
        }
        
        report = generate_governance_report(
            domain="example.com",
            score=0.92,
            probe_results=probe_results,
            target_level=InternetGovernanceLevels.ADVANCED,
        )
        
        # Should have excellent status
        assert report["status"] == "EXCELLENT"
        
        # Should have minimal recommendations
        recommendations = report["recommendations"]
        missing_requirements = report["missing_requirements"]
        
        # Should recommend maintenance rather than improvements
        assert len(missing_requirements) == 0
        assert any("maintain" in rec.lower() for rec in recommendations)


if __name__ == "__main__":
    unittest.main() 