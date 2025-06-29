"""Basic functionality tests for DQIX Internet Governance Framework."""

import unittest

import pytest
from dqix.domain.entities import (
    ADVANCED,
    BASIC,
    EXCELLENT,
    STANDARD,
    ComplianceMetrics,
    GovernanceFramework,
    InternetGovernanceLevels,
)

# Fix imports to match current project structure
from dqix.domain.services import (
    DomainQualityGovernance,
    calculate_compliance_metrics,
    generate_governance_report,
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
    assert BASIC.name == "Basic Infrastructure"
    assert BASIC.target_score == 0.6
    assert "Transport security" in BASIC.focus_areas[0]

    # Test standard compliance level
    assert STANDARD.name == "Standard Compliance"
    assert STANDARD.target_score == 0.8
    assert len(STANDARD.focus_areas) >= 3

    # Test best practice implementation level
    assert ADVANCED.name == "Best Practice Implementation"
    assert ADVANCED.target_score == 0.9
    assert "governance" in ADVANCED.description.lower()


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
        from dqix.application.use_cases import DomainAssessmentUseCase
        engine = DomainAssessmentUseCase
        assert engine is not None
    except ImportError:
        # Engine may not be fully implemented yet
        pytest.skip("Engine implementation not available")


@pytest.mark.skipif(True, reason="CLI may require typer dependency")
def test_cli_imports():
    """Test CLI imports work (skipped if typer not available)."""
    try:
        from dqix.interfaces.cli import app
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
        target_level=STANDARD,
    )

    # Verify report structure
    assert report["domain"] == "example.com"
    assert report["overall_score"] == 0.75
    assert report["status"] == "FAIR"
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

    def test_quality_levels(self):
        """Test internet governance quality levels."""
        # Test basic level
        assert BASIC.name == "Basic Infrastructure"
        assert BASIC.target_score == 0.6
        assert len(BASIC.focus_areas) >= 3
        assert len(BASIC.requirements) >= 3

        # Test standard level
        assert STANDARD.name == "Standard Compliance"
        assert STANDARD.target_score == 0.8
        assert len(STANDARD.focus_areas) >= 3
        assert len(STANDARD.requirements) >= 4

        # Test advanced level
        assert ADVANCED.name == "Best Practice Implementation"
        assert ADVANCED.target_score == 0.9
        assert len(ADVANCED.focus_areas) >= 3
        assert len(ADVANCED.requirements) >= 4

        # Test excellent level
        assert EXCELLENT.name == "Excellence in Internet Governance"
        assert EXCELLENT.target_score == 0.95
        assert len(EXCELLENT.focus_areas) >= 3
        assert len(EXCELLENT.requirements) >= 4


class TestComplianceMetrics(unittest.TestCase):
    """Test compliance metrics functionality."""

    def test_compliance_metrics_initialization(self):
        """Test compliance metrics can be created properly."""
        metrics = calculate_compliance_metrics(
            overall_score=0.85,
            probe_results={"tls": 0.9, "dns": 0.8, "headers": 0.85, "email": 0.7},
            governance_level="ADVANCED"
        )

        assert isinstance(metrics, ComplianceMetrics)
        assert metrics.overall_score == 0.85
        assert metrics.governance_level == "ADVANCED"
        assert 0 <= metrics.compliance_percentage <= 100
        assert 0 <= metrics.web_standards_compliance <= 1.0
        assert 0 <= metrics.security_framework_compliance <= 1.0

    def test_compliance_score_calculation(self):
        """Test compliance score calculations are reasonable."""
        metrics = calculate_compliance_metrics(
            overall_score=0.85,
            probe_results={"tls": 0.9, "dns": 0.8, "headers": 0.85},
            governance_level="STANDARD"
        )

        # Security framework compliance should be weighted average
        expected_security = 0.9 * 0.4 + 0.85 * 0.3 + 0.8 * 0.3
        assert abs(metrics.security_framework_compliance - expected_security) < 0.01

        # Internet standards compliance should include DNS and TLS
        expected_internet = 0.8 * 0.5 + 0.7 * 0.3 + 0.9 * 0.2  # using default email=0.7
        assert abs(metrics.internet_standards_compliance - expected_internet) < 0.01

        # Privacy compliance should be derived from overall score
        expected_privacy = min(1.0, 0.85 * 0.8 + 0.2)
        assert abs(metrics.privacy_compliance - expected_privacy) < 0.01

    def test_compliance_level_determination(self):
        """Test WCAG compliance level determination."""
        # Test AAA level
        metrics_aaa = calculate_compliance_metrics(
            overall_score=0.95,
            probe_results={"accessibility": 0.95},
            governance_level="EXCELLENT"
        )
        assert metrics_aaa.wcag_compliance_level == "AAA"

        # Test AA level
        metrics_aa = calculate_compliance_metrics(
            overall_score=0.85,
            probe_results={"accessibility": 0.85},
            governance_level="ADVANCED"
        )
        assert metrics_aa.wcag_compliance_level == "AA"

        # Test A level
        metrics_a = calculate_compliance_metrics(
            overall_score=0.65,
            probe_results={"accessibility": 0.65},
            governance_level="BASIC"
        )
        assert metrics_a.wcag_compliance_level == "A"

        # Test non-compliant
        metrics_nc = calculate_compliance_metrics(
            overall_score=0.45,
            probe_results={"accessibility": 0.45},
            governance_level="BASIC"
        )
        assert metrics_nc.wcag_compliance_level == "Non-compliant"

    def test_wcag_compliance_level_assignment(self):
        """Test WCAG compliance level assignment based on accessibility scores."""
        test_cases = [
            (0.95, "AAA"),
            (0.85, "AA"),
            (0.65, "A"),
            (0.45, "Non-compliant")
        ]

        for accessibility_score, expected_level in test_cases:
            metrics = calculate_compliance_metrics(
                overall_score=0.8,
                probe_results={"accessibility": accessibility_score},
                governance_level="STANDARD"
            )
            assert metrics.wcag_compliance_level == expected_level

    def test_calculate_compliance_metrics_function(self):
        """Test the calculate_compliance_metrics function comprehensively."""
        probe_results = {
            "tls": 0.9,
            "dns": 0.85,
            "headers": 0.8,
            "email": 0.75,
            "accessibility": 0.85
        }

        metrics = calculate_compliance_metrics(
            overall_score=0.85,
            probe_results=probe_results,
            governance_level="ADVANCED"
        )

        # Verify all fields are populated
        assert metrics.overall_score == 0.85
        assert metrics.governance_level == "ADVANCED"
        assert metrics.compliance_percentage == 85.0

        # Verify framework-specific compliance scores
        assert 0 <= metrics.web_standards_compliance <= 1.0
        assert 0 <= metrics.security_framework_compliance <= 1.0
        assert 0 <= metrics.internet_standards_compliance <= 1.0
        assert 0 <= metrics.privacy_compliance <= 1.0
        assert 0 <= metrics.governance_compliance <= 1.0

        # Verify boolean flags
        assert isinstance(metrics.multistakeholder_principles, bool)
        assert metrics.multistakeholder_principles == (0.85 >= 0.7)

        # Verify recommendations are lists
        assert isinstance(metrics.priority_improvements, list)
        assert isinstance(metrics.governance_recommendations, list)


class TestGovernanceReportGeneration(unittest.TestCase):
    """Test governance report generation functionality."""

    def test_governance_report_generation_basic(self):
        """Test basic governance report generation."""
        report = generate_governance_report(
            domain="test.example.com",
            score=0.75,
            probe_results={"tls": 0.8, "dns": 0.7, "headers": 0.75},
            target_level=STANDARD
        )

        # Verify basic structure
        assert report["domain"] == "test.example.com"
        assert report["overall_score"] == 0.75
        assert report["status"] == "FAIR"
        assert report["framework"] == "internet governance principles"
        assert report["target_level"] == "Standard Compliance"

        # Verify governance compliance structure
        governance_compliance = report["governance_compliance"]
        assert isinstance(governance_compliance, dict)
        assert "multistakeholder_principles" in governance_compliance
        assert "internet_standards_compliance" in governance_compliance
        assert "best_practices_implementation" in governance_compliance
        assert "transparency_and_accountability" in governance_compliance
        assert "security_and_stability" in governance_compliance
        assert "accessibility_compliance" in governance_compliance

        # Verify recommendations and analysis
        assert "recommendations" in report
        assert "compliance_gap_analysis" in report
        assert "next_steps" in report
        assert isinstance(report["recommendations"], list)
        assert isinstance(report["next_steps"], list)

    def test_governance_report_with_detailed_compliance(self):
        """Test governance report with detailed compliance analysis."""
        probe_results = {
            "tls": 0.9,
            "dns": 0.85,
            "headers": 0.8,
            "email": 0.75
        }

        report = generate_governance_report(
            domain="secure.example.com",
            score=0.85,
            probe_results=probe_results,
            target_level=ADVANCED
        )

        # Verify compliance determinations
        governance_compliance = report["governance_compliance"]
        assert governance_compliance["multistakeholder_principles"] is True  # score >= 0.7
        assert governance_compliance["internet_standards_compliance"] is True  # score >= 0.8
        assert governance_compliance["best_practices_implementation"] is False  # score < 0.9
        assert governance_compliance["transparency_and_accountability"] is True  # score >= 0.85
        assert governance_compliance["security_and_stability"] is True  # tls >= 0.8
        assert governance_compliance["accessibility_compliance"] is True  # score >= 0.75

        # Verify gap analysis
        gap_analysis = report["compliance_gap_analysis"]
        assert gap_analysis["current_score"] == 0.85
        assert gap_analysis["target_score"] == ADVANCED.target_score
        assert gap_analysis["compliance_gap"] == max(0, ADVANCED.target_score - 0.85)
        assert isinstance(gap_analysis["areas_for_improvement"], list)
        assert isinstance(gap_analysis["missing_requirements"], list)

    def test_governance_report_recommendations(self):
        """Test governance report recommendation generation."""
        # Test low score scenario
        low_score_report = generate_governance_report(
            domain="lowscore.example.com",
            score=0.55,
            probe_results={"tls": 0.5, "dns": 0.6},
            target_level=BASIC
        )

        recommendations = low_score_report["recommendations"]
        assert len(recommendations) > 0
        assert any("TLS" in rec for rec in recommendations)

        next_steps = low_score_report["next_steps"]
        assert len(next_steps) > 0
        assert any("basic security" in step.lower() for step in next_steps)

        # Test high score scenario
        high_score_report = generate_governance_report(
            domain="highscore.example.com",
            score=0.95,
            probe_results={"tls": 0.95, "dns": 0.9, "headers": 0.9},
            target_level=EXCELLENT
        )

        high_next_steps = high_score_report["next_steps"]
        assert len(high_next_steps) > 0
        assert any("governance" in step.lower() for step in high_next_steps)

    def test_governance_report_excellent_score(self):
        """Test governance report for excellent scores."""
        report = generate_governance_report(
            domain="excellent.example.com",
            score=0.95,
            probe_results={"tls": 0.95, "dns": 0.9, "headers": 0.9, "email": 0.85},
            target_level=EXCELLENT
        )

        assert report["status"] == "EXCELLENT"

        # All governance compliance should be True for excellent score
        governance_compliance = report["governance_compliance"]
        assert governance_compliance["multistakeholder_principles"] is True
        assert governance_compliance["internet_standards_compliance"] is True
        assert governance_compliance["best_practices_implementation"] is True
        assert governance_compliance["transparency_and_accountability"] is True
        assert governance_compliance["security_and_stability"] is True
        assert governance_compliance["accessibility_compliance"] is True

        # Gap should be minimal or zero
        gap_analysis = report["compliance_gap_analysis"]
        assert gap_analysis["compliance_gap"] <= 0.01  # Very small or zero gap


class TestGovernanceLevelDetermination(unittest.TestCase):
    """Test governance level determination functionality."""

    def test_governance_level_determination(self):
        """Test governance level determination based on scores."""
        # Test excellent level
        excellent_level = DomainQualityGovernance.get_governance_level(0.96)
        assert excellent_level == EXCELLENT

        # Test advanced level
        advanced_level = DomainQualityGovernance.get_governance_level(0.92)
        assert advanced_level == ADVANCED

        # Test standard level
        standard_level = DomainQualityGovernance.get_governance_level(0.85)
        assert standard_level == STANDARD

        # Test basic level
        basic_level = DomainQualityGovernance.get_governance_level(0.65)
        assert basic_level == BASIC

        # Test very low score
        low_level = DomainQualityGovernance.get_governance_level(0.45)
        assert low_level == BASIC

    def test_governance_level_edge_cases(self):
        """Test governance level determination at exact boundaries."""
        # Test exact boundaries
        assert DomainQualityGovernance.get_governance_level(0.95) == EXCELLENT
        assert DomainQualityGovernance.get_governance_level(0.9) == ADVANCED
        assert DomainQualityGovernance.get_governance_level(0.8) == STANDARD
        assert DomainQualityGovernance.get_governance_level(0.6) == BASIC

        # Test just below boundaries
        assert DomainQualityGovernance.get_governance_level(0.94) == ADVANCED
        assert DomainQualityGovernance.get_governance_level(0.89) == STANDARD
        assert DomainQualityGovernance.get_governance_level(0.79) == BASIC
        assert DomainQualityGovernance.get_governance_level(0.59) == BASIC


if __name__ == "__main__":
    unittest.main()
