"""
Comprehensive tests for DQIX Enhanced Governance and Detailed Reporting
"""

import unittest
from unittest.mock import Mock

import pytest

from dqix.application.use_cases import ComprehensiveAssessmentUseCase
from dqix.domain.entities import (
    ADVANCED,
    BASIC,
    EXCELLENT,
    STANDARD,
    ComplianceMetrics,
    ComprehensiveAssessmentResult,
    DetailedProbeResult,
    GovernanceFramework,
    ProbeCategory,
    ProbeResult,
)
from dqix.domain.services import (
    DomainQualityGovernance,
    calculate_compliance_metrics,
    generate_governance_report,
)
from dqix.interfaces.export import EnhancedReportGenerator, ExportManager


class TestComprehensiveAssessmentResult(unittest.TestCase):
    """Test comprehensive assessment result functionality."""

    def setUp(self):
        """Set up test data."""
        self.sample_probe_results = [
            DetailedProbeResult(
                probe_id="tls",
                domain="example.com",
                status="SUCCESS",
                score=0.85,
                message="TLS probe completed successfully",
                technical_details={
                    "protocol_version": "TLS 1.3",
                    "cipher_suite": "TLS_AES_256_GCM_SHA384",
                    "supports_tls_13": True,
                    "hsts_enabled": True
                },
                compliance_details={
                    "rfc_8446_tls13_compliance": True,
                    "rfc_6797_hsts_compliance": True,
                    "nist_compliance_level": "High"
                },
                governance_alignment={
                    GovernanceFramework.RFC_8446_TLS13: True,
                    GovernanceFramework.RFC_6797_HSTS: True,
                    GovernanceFramework.NIST_CYBERSECURITY_FRAMEWORK: True
                },
                recommendations=[
                    "Consider implementing certificate pinning",
                    "Enable OCSP stapling for better performance"
                ],
                critical_issues=[],
                best_practices=[
                    "Use automated certificate management",
                    "Monitor certificate expiration dates"
                ]
            ),
            DetailedProbeResult(
                probe_id="dns",
                domain="example.com",
                status="SUCCESS",
                score=0.75,
                message="DNS probe completed with warnings",
                technical_details={
                    "dnssec_enabled": False,
                    "ipv6_support": True,
                    "response_time_ms": 45,
                    "caa_records": [],
                    "dns_servers": ["8.8.8.8", "8.8.4.4"]
                },
                compliance_details={
                    "rfc_4034_dnssec_compliance": False,
                    "rfc_6844_caa_compliance": False,
                    "ipv6_readiness": True,
                    "dns_performance_compliance": True
                },
                governance_alignment={
                    GovernanceFramework.RFC_4034_DNSSEC: False,
                    GovernanceFramework.RFC_6844_CAA: False
                },
                recommendations=[
                    "Enable DNSSEC to prevent DNS spoofing attacks",
                    "Implement CAA records to control certificate issuance"
                ],
                critical_issues=[
                    "DNSSEC not enabled - vulnerable to DNS spoofing"
                ],
                best_practices=[
                    "Use multiple DNS providers for redundancy",
                    "Implement DNS monitoring and alerting"
                ]
            )
        ]

        self.sample_compliance_metrics = ComplianceMetrics(
            overall_score=0.8,
            governance_level="ADVANCED",
            compliance_percentage=80.0,
            web_standards_compliance=0.75,
            security_framework_compliance=0.85,
            internet_standards_compliance=0.7,
            privacy_compliance=0.8,
            governance_compliance=0.8,
            wcag_compliance_level="AA",
            nist_framework_alignment=0.85,
            rfc_standards_adherence=0.7,
            multistakeholder_principles=True,
            priority_improvements=[
                "Enable DNSSEC validation",
                "Implement CAA records"
            ],
            governance_recommendations=[
                "Adopt multistakeholder governance principles",
                "Participate in internet governance forums"
            ]
        )

    def test_comprehensive_assessment_result_creation(self):
        """Test creation of comprehensive assessment result."""
        result = ComprehensiveAssessmentResult(
            domain="example.com",
            overall_score=0.8,
            compliance_level="ADVANCED",
            probe_results=self.sample_probe_results,
            compliance_metrics=self.sample_compliance_metrics,
            governance_frameworks={},
            executive_summary="Test executive summary",
            technical_summary="Test technical summary",
            compliance_summary="Test compliance summary",
            immediate_actions=["Action 1", "Action 2"],
            medium_term_improvements=["Improvement 1"],
            long_term_strategy=["Strategy 1"]
        )

        assert result.domain == "example.com"
        assert result.overall_score == 0.8
        assert result.compliance_level == "ADVANCED"
        assert len(result.probe_results) == 2
        assert result.compliance_metrics is not None
        assert len(result.immediate_actions) == 2

    def test_detailed_probe_result_governance_alignment(self):
        """Test governance framework alignment in detailed probe results."""
        tls_probe = self.sample_probe_results[0]

        # Check TLS governance alignment
        assert tls_probe.governance_alignment[GovernanceFramework.RFC_8446_TLS13] is True
        assert tls_probe.governance_alignment[GovernanceFramework.RFC_6797_HSTS] is True
        assert tls_probe.governance_alignment[GovernanceFramework.NIST_CYBERSECURITY_FRAMEWORK] is True

        # Check DNS governance alignment
        dns_probe = self.sample_probe_results[1]
        assert dns_probe.governance_alignment[GovernanceFramework.RFC_4034_DNSSEC] is False
        assert dns_probe.governance_alignment[GovernanceFramework.RFC_6844_CAA] is False

    def test_compliance_metrics_calculations(self):
        """Test compliance metrics calculations."""
        metrics = self.sample_compliance_metrics

        assert metrics.overall_score == 0.8
        assert metrics.compliance_percentage == 80.0
        assert metrics.wcag_compliance_level == "AA"
        assert metrics.multistakeholder_principles is True
        assert len(metrics.priority_improvements) == 2
        assert len(metrics.governance_recommendations) == 2


class TestEnhancedReportGenerator(unittest.TestCase):
    """Test enhanced report generation functionality."""

    def setUp(self):
        """Set up test data."""
        self.report_generator = EnhancedReportGenerator()

        # Create sample assessment result
        self.sample_result = ComprehensiveAssessmentResult(
            domain="test.example.com",
            overall_score=0.85,
            compliance_level="ADVANCED",
            probe_results=[
                DetailedProbeResult(
                    probe_id="tls",
                    domain="test.example.com",
                    status="SUCCESS",
                    score=0.9,
                    message="TLS configuration excellent",
                    technical_details={
                        "protocol_version": "TLS 1.3",
                        "supports_tls_13": True,
                        "hsts_enabled": True
                    },
                    compliance_details={
                        "rfc_8446_tls13_compliance": True,
                        "nist_compliance_level": "High"
                    },
                    governance_alignment={
                        GovernanceFramework.RFC_8446_TLS13: True
                    },
                    recommendations=["Implement certificate pinning"],
                    critical_issues=[],
                    best_practices=["Use automated certificate management"]
                )
            ],
            compliance_metrics=ComplianceMetrics(
                overall_score=0.85,
                governance_level="ADVANCED",
                compliance_percentage=85.0,
                web_standards_compliance=0.8,
                security_framework_compliance=0.9,
                internet_standards_compliance=0.8,
                privacy_compliance=0.85,
                governance_compliance=0.85,
                wcag_compliance_level="AA",
                nist_framework_alignment=0.9,
                rfc_standards_adherence=0.8,
                multistakeholder_principles=True,
                priority_improvements=["Enhance accessibility"],
                governance_recommendations=["Participate in standards development"]
            ),
            governance_frameworks={},
            executive_summary="Excellent security posture with minor improvements needed",
            technical_summary="Strong TLS configuration with modern protocols",
            compliance_summary="High compliance with international standards",
            immediate_actions=["Review accessibility compliance"],
            medium_term_improvements=["Implement advanced monitoring"],
            long_term_strategy=["Become industry leader in security"]
        )

    def test_executive_report_generation(self):
        """Test executive report generation."""
        report_data = self.report_generator._generate_executive_report(self.sample_result)

        assert report_data["report_type"] == "executive_summary"
        assert report_data["domain"] == "test.example.com"
        assert report_data["overall_score"] == 0.85
        assert report_data["compliance_level"] == "ADVANCED"
        assert "executive_summary" in report_data
        assert "key_metrics" in report_data
        assert "strategic_recommendations" in report_data

        # Check key metrics
        key_metrics = report_data["key_metrics"]
        assert key_metrics["total_probes"] == 1
        assert key_metrics["successful_probes"] == 1
        assert "critical_issues" in key_metrics
        assert "immediate_actions_required" in key_metrics

    def test_technical_report_generation(self):
        """Test technical report generation."""
        report_data = self.report_generator._generate_technical_report(self.sample_result)

        assert report_data["report_type"] == "technical_analysis"
        assert report_data["domain"] == "test.example.com"
        assert "technical_summary" in report_data
        assert "probe_analysis" in report_data
        assert "infrastructure_analysis" in report_data
        assert "security_analysis" in report_data
        assert "performance_analysis" in report_data

        # Check probe analysis
        probe_analysis = report_data["probe_analysis"]
        assert len(probe_analysis) == 1

        tls_probe = probe_analysis[0]
        assert tls_probe["probe_id"] == "tls"
        assert tls_probe["score"] == 0.9
        assert tls_probe["status"] == "SUCCESS"
        assert "technical_details" in tls_probe
        assert "compliance_details" in tls_probe
        assert "governance_alignment" in tls_probe

    def test_compliance_report_generation(self):
        """Test compliance report generation."""
        report_data = self.report_generator._generate_compliance_report(self.sample_result)

        assert report_data["report_type"] == "compliance_assessment"
        assert report_data["domain"] == "test.example.com"
        assert "compliance_summary" in report_data
        assert "compliance_metrics" in report_data
        assert "governance_frameworks" in report_data
        assert "compliance_gaps" in report_data
        assert "regulatory_alignment" in report_data
        assert "certification_readiness" in report_data

        # Check compliance metrics
        compliance_metrics = report_data["compliance_metrics"]
        assert compliance_metrics["overall_score"] == 0.85
        assert compliance_metrics["governance_level"] == "ADVANCED"
        assert compliance_metrics["wcag_compliance_level"] == "AA"

    def test_comprehensive_report_generation(self):
        """Test comprehensive report generation."""
        report_data = self.report_generator._generate_comprehensive_report(self.sample_result)

        assert report_data["report_type"] == "comprehensive_assessment"
        assert "metadata" in report_data
        assert "executive_summary" in report_data
        assert "technical_analysis" in report_data
        assert "compliance_assessment" in report_data
        assert "governance_analysis" in report_data
        assert "detailed_findings" in report_data
        assert "actionable_recommendations" in report_data

        # Check metadata
        metadata = report_data["metadata"]
        assert metadata["domain"] == "test.example.com"
        assert "assessment_date" in metadata
        assert "report_version" in metadata

    def test_governance_report_generation(self):
        """Test governance report generation."""
        report_data = self.report_generator._generate_governance_report(self.sample_result)

        assert report_data["report_type"] == "internet_governance_analysis"
        assert report_data["domain"] == "test.example.com"
        assert "governance_maturity" in report_data
        assert "standards_compliance" in report_data
        assert "framework_alignment" in report_data
        assert "governance_recommendations" in report_data

        # Check governance maturity
        governance_maturity = report_data["governance_maturity"]
        assert governance_maturity["current_level"] == "ADVANCED"
        assert "target_level" in governance_maturity
        assert governance_maturity["maturity_score"] == 0.85

    def test_html_report_formatting(self):
        """Test HTML report formatting."""
        report_data = self.report_generator._generate_executive_report(self.sample_result)
        html_content = self.report_generator._format_html_report(report_data, "executive")

        assert "<!DOCTYPE html>" in html_content
        assert "DQIX Internet Observability Platform" in html_content
        assert "test.example.com" in html_content
        assert "Executive Summary" in html_content
        assert "report-container" in html_content

        # Check for CSS styling
        assert "<style>" in html_content
        assert "font-family" in html_content

    def test_json_report_formatting(self):
        """Test JSON report formatting."""
        report_data = self.report_generator._generate_executive_report(self.sample_result)
        json_content = self.report_generator._format_json_report(report_data)

        import json
        parsed_json = json.loads(json_content)

        assert parsed_json["report_type"] == "executive_summary"
        assert parsed_json["domain"] == "test.example.com"
        assert parsed_json["overall_score"] == 0.85

    def test_csv_report_formatting(self):
        """Test CSV report formatting."""
        report_data = self.report_generator._generate_technical_report(self.sample_result)
        csv_content = self.report_generator._format_csv_report(report_data)

        assert "Metric,Value" in csv_content
        assert "Domain,test.example.com" in csv_content
        assert "Report Type,technical_analysis" in csv_content
        assert "Probe ID,Score,Status,Critical Issues" in csv_content

    def test_markdown_report_formatting(self):
        """Test Markdown report formatting."""
        report_data = self.report_generator._generate_executive_report(self.sample_result)
        md_content = self.report_generator._format_markdown_report(report_data, "executive")

        assert "# DQIX Executive Summary" in md_content
        assert "**Domain:** test.example.com" in md_content
        assert "## Executive Summary" in md_content
        assert "### Key Metrics" in md_content

    def test_grade_calculation(self):
        """Test grade calculation from scores."""
        assert self.report_generator._calculate_grade(0.95) == "A+"
        assert self.report_generator._calculate_grade(0.9) == "A"
        assert self.report_generator._calculate_grade(0.85) == "A-"
        assert self.report_generator._calculate_grade(0.8) == "B+"
        assert self.report_generator._calculate_grade(0.75) == "B"
        assert self.report_generator._calculate_grade(0.7) == "B-"
        assert self.report_generator._calculate_grade(0.65) == "C+"
        assert self.report_generator._calculate_grade(0.6) == "C"
        assert self.report_generator._calculate_grade(0.55) == "C-"
        assert self.report_generator._calculate_grade(0.5) == "D"
        assert self.report_generator._calculate_grade(0.4) == "F"

    def test_infrastructure_analysis(self):
        """Test infrastructure analysis."""
        analysis = self.report_generator._analyze_infrastructure(self.sample_result.probe_results)

        assert "dns_infrastructure" in analysis
        assert "tls_infrastructure" in analysis
        assert "overall_health" in analysis

        # Should have TLS infrastructure data
        tls_infra = analysis["tls_infrastructure"]
        assert tls_infra["protocol_version"] == "TLS 1.3"
        assert tls_infra["tls13_support"] is True
        assert tls_infra["hsts_enabled"] is True

    def test_security_analysis(self):
        """Test security analysis."""
        analysis = self.report_generator._analyze_security(self.sample_result.probe_results)

        assert "security_score" in analysis
        assert "critical_vulnerabilities" in analysis
        assert "security_headers" in analysis
        assert "encryption_strength" in analysis

        # Should have good security score
        assert analysis["security_score"] > 0.8
        assert analysis["encryption_strength"] == "excellent"  # TLS 1.3

    def test_performance_analysis(self):
        """Test performance analysis."""
        analysis = self.report_generator._analyze_performance(self.sample_result.probe_results)

        assert "dns_response_time" in analysis
        assert "tls_handshake_performance" in analysis
        assert "overall_performance" in analysis

        # Should detect TLS 1.3 performance
        assert analysis["tls_handshake_performance"] == "excellent"


class TestExportManager(unittest.TestCase):
    """Test export manager functionality."""

    def setUp(self):
        """Set up test data."""
        self.export_manager = ExportManager()

        # Create minimal assessment result for testing
        self.sample_result = ComprehensiveAssessmentResult(
            domain="export.test.com",
            overall_score=0.75,
            compliance_level="STANDARD",
            probe_results=[],
            compliance_metrics=None,
            governance_frameworks={},
            executive_summary="Test export functionality",
            technical_summary="",
            compliance_summary="",
            immediate_actions=[],
            medium_term_improvements=[],
            long_term_strategy=[]
        )

    def test_export_assessment_html(self):
        """Test exporting assessment as HTML."""
        result = self.export_manager.export_assessment(
            self.sample_result,
            format_type="html",
            template="executive"
        )

        assert "<!DOCTYPE html>" in result
        assert "export.test.com" in result
        assert "DQIX Internet Observability Platform" in result

    def test_export_assessment_json(self):
        """Test exporting assessment as JSON."""
        result = self.export_manager.export_assessment(
            self.sample_result,
            format_type="json",
            template="executive"
        )

        import json
        parsed = json.loads(result)
        assert parsed["domain"] == "export.test.com"
        assert parsed["overall_score"] == 0.75

    def test_export_assessment_csv(self):
        """Test exporting assessment as CSV."""
        result = self.export_manager.export_assessment(
            self.sample_result,
            format_type="csv",
            template="technical"
        )

        assert "Metric,Value" in result
        assert "export.test.com" in result

    def test_export_assessment_markdown(self):
        """Test exporting assessment as Markdown."""
        result = self.export_manager.export_assessment(
            self.sample_result,
            format_type="markdown",
            template="executive"
        )

        assert "# DQIX Executive Summary" in result
        assert "export.test.com" in result

    def test_export_with_file_output(self):
        """Test exporting assessment to file."""
        import os
        import tempfile

        with tempfile.NamedTemporaryFile(mode='w', suffix='.html', delete=False) as temp_file:
            temp_path = temp_file.name

        try:
            result = self.export_manager.export_assessment(
                self.sample_result,
                format_type="html",
                template="executive",
                output_path=temp_path
            )

            # Check that file was created
            assert os.path.exists(temp_path)

            # Check file contents
            with open(temp_path, encoding='utf-8') as f:
                file_content = f.read()

            assert file_content == result
            assert "export.test.com" in file_content

        finally:
            # Clean up
            if os.path.exists(temp_path):
                os.unlink(temp_path)


class TestComprehensiveAssessmentUseCase(unittest.TestCase):
    """Test comprehensive assessment use case."""

    def setUp(self):
        """Set up test mocks."""
        self.mock_probe_executor = Mock()
        self.mock_assessment_service = Mock()

        # Create use case instance
        self.use_case = ComprehensiveAssessmentUseCase(
            self.mock_probe_executor,
            self.mock_assessment_service
        )

        # Mock probe results
        self.mock_probe_results = [
            ProbeResult(
                probe_id="tls",
                domain="test.com",
                score=0.9,
                category=ProbeCategory.SECURITY,
                details={
                    "protocol_version": "TLS 1.3",
                    "supports_tls_13": True,
                    "hsts_enabled": True
                }
            ),
            ProbeResult(
                probe_id="dns",
                domain="test.com",
                score=0.7,
                category=ProbeCategory.SECURITY,
                details={
                    "dnssec_enabled": False,
                    "ipv6_support": True,
                    "response_time": 50
                }
            )
        ]

    @pytest.mark.asyncio
    async def test_execute_comprehensive_assessment(self):
        """Test executing comprehensive assessment."""
        # Mock the probe executor
        self.mock_probe_executor.execute_all.return_value = self.mock_probe_results

        # Mock the scoring service
        self.use_case.scoring_service = Mock()
        self.use_case.scoring_service.calculate_overall_score.return_value = 0.8

        # Execute assessment
        result = await self.use_case.execute_comprehensive_assessment(
            domain_name="test.com",
            config=Mock(),
            report_template="comprehensive"
        )

        # Verify result
        assert isinstance(result, ComprehensiveAssessmentResult)
        assert result.domain == "test.com"
        assert result.overall_score == 0.8
        assert result.compliance_level == "Advanced Implementation"
        assert len(result.probe_results) == 2
        assert result.compliance_metrics is not None
        assert result.executive_summary != ""
        assert result.technical_summary != ""
        assert len(result.immediate_actions) >= 0

    def test_create_detailed_probe_result(self):
        """Test creating detailed probe result."""
        probe_result = self.mock_probe_results[0]  # TLS probe

        detailed_result = self.use_case._create_detailed_probe_result(
            probe_result, "test.com"
        )

        assert isinstance(detailed_result, DetailedProbeResult)
        assert detailed_result.probe_id == "tls"
        assert detailed_result.domain == "test.com"
        assert detailed_result.score == 0.9
        assert detailed_result.status == "SUCCESS"
        assert len(detailed_result.technical_details) > 0
        assert len(detailed_result.compliance_details) > 0
        assert len(detailed_result.governance_alignment) > 0

    def test_extract_technical_details_tls(self):
        """Test extracting technical details for TLS probe."""
        tls_probe = self.mock_probe_results[0]

        technical_details = self.use_case._extract_technical_details(tls_probe)

        assert technical_details["protocol_version"] == "TLS 1.3"
        assert technical_details["supports_tls_13"] is True
        assert technical_details["hsts_enabled"] is True
        assert "cipher_suite" in technical_details
        assert "certificate_chain_length" in technical_details

    def test_extract_technical_details_dns(self):
        """Test extracting technical details for DNS probe."""
        dns_probe = self.mock_probe_results[1]

        technical_details = self.use_case._extract_technical_details(dns_probe)

        assert technical_details["dnssec_enabled"] is False
        assert technical_details["ipv6_support"] is True
        assert technical_details["response_time_ms"] == 50
        assert "caa_records" in technical_details
        assert "dns_servers" in technical_details

    def test_extract_compliance_details(self):
        """Test extracting compliance details."""
        tls_probe = self.mock_probe_results[0]

        compliance_details = self.use_case._extract_compliance_details(tls_probe)

        assert compliance_details["rfc_8446_tls13_compliance"] is True
        assert compliance_details["rfc_6797_hsts_compliance"] is True
        assert compliance_details["pci_dss_compliance"] is True  # score >= 0.8
        assert compliance_details["nist_compliance_level"] == "High"  # score >= 0.9

    def test_determine_governance_alignment(self):
        """Test determining governance framework alignment."""
        tls_probe = self.mock_probe_results[0]

        governance_alignment = self.use_case._determine_governance_alignment(tls_probe)

        assert governance_alignment[GovernanceFramework.RFC_8446_TLS13] is True
        assert governance_alignment[GovernanceFramework.RFC_6797_HSTS] is True
        assert governance_alignment[GovernanceFramework.NIST_CYBERSECURITY_FRAMEWORK] is True

    def test_generate_probe_recommendations(self):
        """Test generating probe recommendations."""
        # Test with low score to trigger recommendations
        low_score_probe = ProbeResult(
            probe_id="tls",
            domain="test.com",
            score=0.5,  # Low score
            category=ProbeCategory.SECURITY,
            details={}
        )

        recommendations = self.use_case._generate_probe_recommendations(low_score_probe)

        assert len(recommendations) > 0
        assert any("TLS 1.3" in rec for rec in recommendations)
        assert any("HSTS" in rec for rec in recommendations)

    def test_identify_critical_issues(self):
        """Test identifying critical issues."""
        # Test with low score and missing security features
        critical_probe = ProbeResult(
            probe_id="tls",
            domain="test.com",
            score=0.3,  # Very low score
            category=ProbeCategory.SECURITY,
            details={
                "hsts_enabled": False,
                "protocol_version": "TLS 1.0"
            }
        )

        critical_issues = self.use_case._identify_critical_issues(critical_probe)

        assert len(critical_issues) > 0
        assert any("HSTS" in issue for issue in critical_issues)
        assert any("TLS 1.0" in issue for issue in critical_issues)

    def test_generate_best_practices(self):
        """Test generating best practices."""
        tls_probe = self.mock_probe_results[0]

        best_practices = self.use_case._generate_best_practices(tls_probe)

        assert len(best_practices) > 0
        assert any("certificate" in practice.lower() for practice in best_practices)
        assert any("automated" in practice.lower() for practice in best_practices)


class TestIntegrationGovernanceReporting(unittest.TestCase):
    """Integration tests for governance reporting functionality."""

    def test_end_to_end_governance_report_generation(self):
        """Test end-to-end governance report generation."""
        # Create realistic test data
        probe_results = {
            "tls": 0.9,
            "dns": 0.7,
            "headers": 0.8,
            "email": 0.75
        }

        # Generate governance report
        report = generate_governance_report(
            domain="integration.test.com",
            score=0.8,
            probe_results=probe_results,
            target_level=ADVANCED
        )

        # Verify report structure
        assert report["domain"] == "integration.test.com"
        assert report["overall_score"] == 0.8
        assert report["status"] == "GOOD"
        assert "governance_compliance" in report
        assert "recommendations" in report
        assert "compliance_gap_analysis" in report
        assert "next_steps" in report

        # Verify governance compliance
        governance_compliance = report["governance_compliance"]
        assert governance_compliance["multistakeholder_principles"] is True
        assert governance_compliance["internet_standards_compliance"] is True
        assert governance_compliance["security_and_stability"] is True

    def test_compliance_metrics_integration(self):
        """Test compliance metrics integration."""
        # Calculate compliance metrics
        metrics = calculate_compliance_metrics(
            overall_score=0.85,
            probe_results={
                "tls": 0.9,
                "dns": 0.8,
                "headers": 0.85,
                "email": 0.75,
                "accessibility": 0.8
            },
            governance_level="ADVANCED"
        )

        # Verify comprehensive metrics
        assert metrics.overall_score == 0.85
        assert metrics.governance_level == "ADVANCED"
        assert metrics.compliance_percentage == 85.0
        assert metrics.wcag_compliance_level == "AA"
        assert metrics.multistakeholder_principles is True
        assert len(metrics.priority_improvements) >= 0
        assert len(metrics.governance_recommendations) >= 0

        # Verify framework-specific compliance
        assert 0 <= metrics.web_standards_compliance <= 1.0
        assert 0 <= metrics.security_framework_compliance <= 1.0
        assert 0 <= metrics.internet_standards_compliance <= 1.0
        assert 0 <= metrics.privacy_compliance <= 1.0
        assert 0 <= metrics.governance_compliance <= 1.0

    def test_governance_framework_references(self):
        """Test governance framework references."""
        references = DomainQualityGovernance.get_governance_references()

        # Verify comprehensive framework coverage
        assert len(references) >= 10

        # Check specific frameworks
        assert GovernanceFramework.WCAG_2_2 in references
        assert GovernanceFramework.NIST_CYBERSECURITY_FRAMEWORK in references
        assert GovernanceFramework.RFC_8446_TLS13 in references
        assert GovernanceFramework.MULTISTAKEHOLDER_APPROACH in references

        # Verify reference structure
        wcag_ref = references[GovernanceFramework.WCAG_2_2]
        assert wcag_ref.title == "Web Content Accessibility Guidelines (WCAG) 2.2"
        assert wcag_ref.organization == "World Wide Web Consortium (W3C)"
        assert wcag_ref.category == "web_standards"
        assert len(wcag_ref.implementation_notes) > 0

    def test_governance_level_determination(self):
        """Test governance level determination."""
        # Test all governance levels
        assert DomainQualityGovernance.get_governance_level(0.96) == EXCELLENT
        assert DomainQualityGovernance.get_governance_level(0.92) == ADVANCED
        assert DomainQualityGovernance.get_governance_level(0.85) == STANDARD
        assert DomainQualityGovernance.get_governance_level(0.65) == BASIC
        assert DomainQualityGovernance.get_governance_level(0.45) == BASIC


if __name__ == "__main__":
    unittest.main()
