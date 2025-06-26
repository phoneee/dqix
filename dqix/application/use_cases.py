"""Application Use Cases - Business workflows."""

import asyncio
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from ..domain.entities import (
    AssessmentResult,
    ComplianceLevel,
    ComplianceMetrics,
    ComprehensiveAssessmentResult,
    DetailedProbeResult,
    Domain,
    GovernanceFramework,
    ProbeConfig,
    ProbeResult,
)
from ..domain.repositories import AssessmentRepository
from ..domain.services import (
    AssessmentService,
    DomainQualityGovernance,
    ScoringService,
    calculate_compliance_metrics,
)
from ..infrastructure.probes import ProbeExecutor, ProbeRegistry


@dataclass
class AssessDomainCommand:
    """Command to assess a single domain."""
    domain_name: str
    probe_config: ProbeConfig


@dataclass
class AssessDomainsCommand:
    """Command to assess multiple domains."""
    domain_names: list[str]
    probe_config: ProbeConfig


class DomainAssessmentUseCase:
    """Simplified use case for domain assessment with modern interface."""

    def __init__(self, infrastructure):
        self.infrastructure = infrastructure
        self.probe_executor = infrastructure.get_probe_executor()
        self.probe_registry = infrastructure.get_probe_registry()

    async def assess_domain(self, domain_name: str, timeout: int = 10, comprehensive: bool = False) -> dict[str, Any]:
        """Assess a single domain and return results as dictionary."""
        try:
            domain = Domain(name=domain_name)
            config = ProbeConfig(timeout=timeout)

            # Execute probes
            probe_results = await self.probe_executor.execute_all(domain, config)

            # Calculate overall score
            total_score = sum(result.score for result in probe_results)
            overall_score = total_score / len(probe_results) if probe_results else 0.0

            # Determine compliance level
            if overall_score >= 0.8:
                compliance_level = ComplianceLevel.ADVANCED
            elif overall_score >= 0.6:
                compliance_level = ComplianceLevel.STANDARD
            elif overall_score >= 0.4:
                compliance_level = ComplianceLevel.BASIC
            else:
                compliance_level = ComplianceLevel.BASIC

            # Convert probe results to dictionaries
            probe_results_dict = []
            category_scores = {}

            for result in probe_results:
                probe_dict = {
                    "probe_id": result.probe_id,
                    "domain": result.domain,
                    "score": result.score,
                    "category": result.category.value,
                    "is_successful": result.is_successful,
                    "error": result.error,
                    "technical_details": result.details
                }
                probe_results_dict.append(probe_dict)

                # Calculate category scores
                category = result.category.value
                if category not in category_scores:
                    category_scores[category] = []
                category_scores[category].append(result.score)

            # Average category scores
            for category in category_scores:
                scores = category_scores[category]
                category_scores[category] = sum(scores) / len(scores) if scores else 0.0

            return {
                "domain": domain_name,
                "timestamp": datetime.now().isoformat(),
                "overall_score": overall_score,
                "compliance_level": compliance_level.value,
                "probe_results": probe_results_dict,
                "category_scores": category_scores,
                "assessment_metadata": {
                    "timeout": timeout,
                    "comprehensive": comprehensive,
                    "total_probes": len(probe_results),
                    "successful_probes": len([r for r in probe_results if r.is_successful])
                }
            }

        except Exception as e:
            return {
                "domain": domain_name,
                "timestamp": datetime.now().isoformat(),
                "overall_score": 0.0,
                "compliance_level": "error",
                "error": str(e),
                "probe_results": [],
                "category_scores": {}
            }


class AssessDomainUseCase:
    """Use case for assessing a single domain."""

    def __init__(self, probe_executor: ProbeExecutor, probe_registry: ProbeRegistry):
        self.probe_executor = probe_executor
        self.probe_registry = probe_registry

    async def execute(self, domain: Domain, config: ProbeConfig) -> AssessmentResult:
        """Execute domain assessment."""
        list(self.probe_registry.get_all_probes().values())

        # Execute probes using the executor's execute_all method
        probe_results = await self.probe_executor.execute_all(domain, config)

        # Calculate overall score
        total_score = sum(result.score for result in probe_results)
        overall_score = total_score / len(probe_results) if probe_results else 0.0

        # Determine compliance level
        if overall_score >= 0.8:
            compliance_level = ComplianceLevel.ADVANCED
        elif overall_score >= 0.6:
            compliance_level = ComplianceLevel.STANDARD
        elif overall_score >= 0.4:
            compliance_level = ComplianceLevel.BASIC
        else:
            compliance_level = ComplianceLevel.BASIC

        return AssessmentResult(
            domain=domain,
            overall_score=overall_score,
            compliance_level=compliance_level,
            probe_results=probe_results,
            timestamp=datetime.now().isoformat()
        )


class BulkAssessDomainsUseCase:
    """Use case for assessing multiple domains."""

    def __init__(self, probe_executor: ProbeExecutor, probe_registry: ProbeRegistry):
        self.probe_executor = probe_executor
        self.probe_registry = probe_registry

    async def execute(self, domains: list[Domain], config: ProbeConfig) -> list[AssessmentResult]:
        """Execute bulk domain assessment."""
        results = []

        # Use semaphore to limit concurrent assessments
        semaphore = asyncio.Semaphore(5)  # Max 5 concurrent assessments

        async def assess_single_domain(domain: Domain) -> AssessmentResult:
            async with semaphore:
                assess_use_case = AssessDomainUseCase(self.probe_executor, self.probe_registry)
                return await assess_use_case.execute(domain, config)

        # Create tasks for all domains
        tasks = [assess_single_domain(domain) for domain in domains]

        # Execute all tasks concurrently
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Filter out exceptions and return successful results
        successful_results = []
        for result in results:
            if isinstance(result, AssessmentResult):
                successful_results.append(result)
            else:
                # Log error or handle exception
                print(f"Assessment failed: {result}")

        return successful_results


class GetAssessmentHistoryUseCase:
    """Use case for retrieving assessment history."""

    def __init__(self, assessment_repo: AssessmentRepository):
        self.assessment_repo = assessment_repo

    async def execute(self, domain_name: str) -> list[AssessmentResult]:
        """Get assessment history for domain."""
        domain = Domain(name=domain_name)
        return await self.assessment_repo.find_all_by_domain(domain)


class ComprehensiveAssessmentUseCase:
    """Enhanced use case for comprehensive domain assessment with detailed governance reporting."""

    def __init__(self, probe_executor: ProbeExecutor, assessment_service: AssessmentService):
        self.probe_executor = probe_executor
        self.assessment_service = assessment_service
        self.governance_service = DomainQualityGovernance()
        self.scoring_service = ScoringService()

    async def execute_comprehensive_assessment(
        self,
        domain_name: str,
        config: ProbeConfig,
        report_template: str = "comprehensive"
    ) -> ComprehensiveAssessmentResult:
        """Execute comprehensive assessment with detailed governance analysis."""

        # Validate domain
        domain = Domain(domain_name)
        if not domain.is_valid():
            raise ValueError(f"Invalid domain: {domain_name}")

        # Execute all probes
        probe_results = await self.probe_executor.execute_all(domain, config)

        # Calculate overall score
        overall_score = self.scoring_service.calculate_overall_score(probe_results)

        # Determine compliance level
        governance_level = self.governance_service.get_governance_level(overall_score)

        # Create detailed probe results
        detailed_probes = []
        for probe_result in probe_results:
            detailed_probe = self._create_detailed_probe_result(probe_result, domain_name)
            detailed_probes.append(detailed_probe)

        # Calculate comprehensive compliance metrics
        probe_scores = {probe.probe_id: probe.score for probe in probe_results}
        compliance_metrics = calculate_compliance_metrics(
            overall_score=overall_score,
            probe_results=probe_scores,
            governance_level=governance_level.name
        )

        # Generate governance frameworks mapping
        governance_frameworks = self.governance_service.get_governance_references()

        # Generate summaries
        executive_summary = self._generate_executive_summary(
            domain_name, overall_score, governance_level, detailed_probes
        )
        technical_summary = self._generate_technical_summary(detailed_probes)
        compliance_summary = self._generate_compliance_summary(compliance_metrics)

        # Generate recommendations
        immediate_actions = self._generate_immediate_actions(detailed_probes, overall_score)
        medium_term_improvements = self._generate_medium_term_improvements(
            compliance_metrics, governance_level
        )
        long_term_strategy = self._generate_long_term_strategy(
            overall_score, governance_level
        )

        return ComprehensiveAssessmentResult(
            domain=domain_name,
            overall_score=overall_score,
            compliance_level=governance_level.name,
            probe_results=detailed_probes,
            compliance_metrics=compliance_metrics,
            governance_frameworks=governance_frameworks,
            executive_summary=executive_summary,
            technical_summary=technical_summary,
            compliance_summary=compliance_summary,
            immediate_actions=immediate_actions,
            medium_term_improvements=medium_term_improvements,
            long_term_strategy=long_term_strategy,
            report_template=report_template
        )

    def _create_detailed_probe_result(
        self,
        probe_result: ProbeResult,
        domain_name: str
    ) -> DetailedProbeResult:
        """Create detailed probe result with comprehensive analysis."""

        # Generate technical details based on probe type
        technical_details = self._extract_technical_details(probe_result)

        # Generate compliance details
        compliance_details = self._extract_compliance_details(probe_result)

        # Determine governance framework alignment
        governance_alignment = self._determine_governance_alignment(probe_result)

        # Generate recommendations
        recommendations = self._generate_probe_recommendations(probe_result)

        # Identify critical issues
        critical_issues = self._identify_critical_issues(probe_result)

        # Generate best practices
        best_practices = self._generate_best_practices(probe_result)

        return DetailedProbeResult(
            probe_id=probe_result.probe_id,
            domain=domain_name,
            status="SUCCESS" if probe_result.is_successful else "FAILED",
            score=probe_result.score,
            message=f"Probe {probe_result.probe_id} completed with score {probe_result.score:.2f}",
            technical_details=technical_details,
            compliance_details=compliance_details,
            governance_alignment=governance_alignment,
            recommendations=recommendations,
            critical_issues=critical_issues,
            best_practices=best_practices
        )

    def _extract_technical_details(self, probe_result: ProbeResult) -> dict[str, Any]:
        """Extract technical details based on probe type."""
        details = probe_result.details.copy()

        if probe_result.probe_id == "tls":
            return {
                "protocol_version": details.get("protocol_version", "Unknown"),
                "cipher_suite": details.get("cipher_suite", "Unknown"),
                "certificate_chain_length": details.get("cert_chain_length", 0),
                "certificate_validity_days": details.get("cert_validity_days", 0),
                "supports_tls_13": details.get("supports_tls_13", False),
                "hsts_enabled": details.get("hsts_enabled", False),
                "certificate_authority": details.get("cert_authority", "Unknown"),
                "key_size": details.get("key_size", 0),
                "signature_algorithm": details.get("signature_algorithm", "Unknown")
            }
        elif probe_result.probe_id == "dns":
            return {
                "dnssec_enabled": details.get("dnssec_enabled", False),
                "dns_servers": details.get("dns_servers", []),
                "response_time_ms": details.get("response_time", 0),
                "ipv6_support": details.get("ipv6_support", False),
                "caa_records": details.get("caa_records", []),
                "mx_records": details.get("mx_records", []),
                "txt_records": details.get("txt_records", []),
                "ns_records": details.get("ns_records", [])
            }
        elif probe_result.probe_id == "headers":
            return {
                "security_headers": details.get("security_headers", {}),
                "missing_headers": details.get("missing_headers", []),
                "hsts_policy": details.get("hsts_policy", {}),
                "csp_policy": details.get("csp_policy", {}),
                "x_frame_options": details.get("x_frame_options", ""),
                "x_content_type_options": details.get("x_content_type_options", ""),
                "referrer_policy": details.get("referrer_policy", ""),
                "permissions_policy": details.get("permissions_policy", {})
            }
        else:
            return details

    def _extract_compliance_details(self, probe_result: ProbeResult) -> dict[str, Any]:
        """Extract compliance-specific details."""
        compliance = {}

        if probe_result.probe_id == "tls":
            compliance.update({
                "rfc_8446_tls13_compliance": probe_result.details.get("supports_tls_13", False),
                "rfc_6797_hsts_compliance": probe_result.details.get("hsts_enabled", False),
                "certificate_transparency_compliance": probe_result.details.get("ct_logs", False),
                "pci_dss_compliance": probe_result.score >= 0.8,
                "nist_compliance_level": "High" if probe_result.score >= 0.9 else "Medium" if probe_result.score >= 0.7 else "Low"
            })
        elif probe_result.probe_id == "dns":
            compliance.update({
                "rfc_4034_dnssec_compliance": probe_result.details.get("dnssec_enabled", False),
                "rfc_6844_caa_compliance": len(probe_result.details.get("caa_records", [])) > 0,
                "ipv6_readiness": probe_result.details.get("ipv6_support", False),
                "dns_performance_compliance": probe_result.details.get("response_time", 1000) < 100
            })
        elif probe_result.probe_id == "headers":
            compliance.update({
                "owasp_compliance": probe_result.score >= 0.8,
                "csp_compliance": "csp_policy" in probe_result.details,
                "hsts_compliance": probe_result.details.get("hsts_policy", {}).get("enabled", False),
                "clickjacking_protection": "x_frame_options" in probe_result.details.get("security_headers", {}),
                "content_sniffing_protection": "x_content_type_options" in probe_result.details.get("security_headers", {})
            })

        return compliance

    def _determine_governance_alignment(
        self,
        probe_result: ProbeResult
    ) -> dict[GovernanceFramework, bool]:
        """Determine alignment with governance frameworks."""
        alignment = {}

        if probe_result.probe_id == "tls":
            alignment.update({
                GovernanceFramework.RFC_8446_TLS13: probe_result.details.get("supports_tls_13", False),
                GovernanceFramework.RFC_6797_HSTS: probe_result.details.get("hsts_enabled", False),
                GovernanceFramework.NIST_CYBERSECURITY_FRAMEWORK: probe_result.score >= 0.8
            })
        elif probe_result.probe_id == "dns":
            alignment.update({
                GovernanceFramework.RFC_4034_DNSSEC: probe_result.details.get("dnssec_enabled", False),
                GovernanceFramework.RFC_6844_CAA: len(probe_result.details.get("caa_records", [])) > 0
            })
        elif probe_result.probe_id == "headers":
            alignment.update({
                GovernanceFramework.NIST_CYBERSECURITY_FRAMEWORK: probe_result.score >= 0.8,
                GovernanceFramework.CIS_CONTROLS_V8: probe_result.score >= 0.7
            })

        return alignment

    def _generate_probe_recommendations(self, probe_result: ProbeResult) -> list[str]:
        """Generate probe-specific recommendations."""
        recommendations = []

        if probe_result.score < 0.7:
            if probe_result.probe_id == "tls":
                recommendations.extend([
                    "Upgrade to TLS 1.3 for improved security and performance",
                    "Enable HTTP Strict Transport Security (HSTS)",
                    "Use strong cipher suites and disable weak algorithms",
                    "Implement certificate transparency logging"
                ])
            elif probe_result.probe_id == "dns":
                recommendations.extend([
                    "Enable DNSSEC to prevent DNS spoofing attacks",
                    "Implement CAA records to control certificate issuance",
                    "Add IPv6 support for future-proofing",
                    "Optimize DNS response times"
                ])
            elif probe_result.probe_id == "headers":
                recommendations.extend([
                    "Implement Content Security Policy (CSP)",
                    "Add X-Frame-Options header to prevent clickjacking",
                    "Enable X-Content-Type-Options header",
                    "Configure Referrer-Policy header"
                ])

        return recommendations

    def _identify_critical_issues(self, probe_result: ProbeResult) -> list[str]:
        """Identify critical security issues."""
        critical_issues = []

        if probe_result.score < 0.5:
            if probe_result.probe_id == "tls":
                if not probe_result.details.get("hsts_enabled", False):
                    critical_issues.append("HSTS not enabled - vulnerable to downgrade attacks")
                if probe_result.details.get("protocol_version", "").startswith("TLS 1.0"):
                    critical_issues.append("Using deprecated TLS 1.0 - upgrade immediately")
            elif probe_result.probe_id == "headers":
                if "x_frame_options" not in probe_result.details.get("security_headers", {}):
                    critical_issues.append("No clickjacking protection - add X-Frame-Options header")
                if not probe_result.details.get("csp_policy"):
                    critical_issues.append("No Content Security Policy - vulnerable to XSS attacks")

        return critical_issues

    def _generate_best_practices(self, probe_result: ProbeResult) -> list[str]:
        """Generate best practices for the probe."""
        best_practices = []

        if probe_result.probe_id == "tls":
            best_practices.extend([
                "Use automated certificate management (e.g., Let's Encrypt)",
                "Implement certificate pinning for critical applications",
                "Monitor certificate expiration dates",
                "Use OCSP stapling for better performance"
            ])
        elif probe_result.probe_id == "dns":
            best_practices.extend([
                "Use multiple DNS providers for redundancy",
                "Implement DNS monitoring and alerting",
                "Regularly audit DNS configurations",
                "Use geographic DNS distribution"
            ])
        elif probe_result.probe_id == "headers":
            best_practices.extend([
                "Regularly review and update security policies",
                "Use security header scanners in CI/CD pipeline",
                "Implement security headers gradually with monitoring",
                "Document security header configurations"
            ])

        return best_practices

    def _generate_executive_summary(
        self,
        domain_name: str,
        overall_score: float,
        governance_level: Any,
        detailed_probes: list[DetailedProbeResult]
    ) -> str:
        """Generate executive summary for the assessment."""

        grade = "A+" if overall_score >= 0.95 else "A" if overall_score >= 0.9 else "B" if overall_score >= 0.8 else "C" if overall_score >= 0.7 else "D"

        critical_issues_count = sum(len(probe.critical_issues) for probe in detailed_probes)

        summary = f"""
Executive Summary - Internet Security Assessment for {domain_name}

Overall Security Grade: {grade} ({overall_score:.1%})
Governance Compliance Level: {governance_level.name}

Key Findings:
• Overall security score of {overall_score:.1%} places this domain in the {governance_level.name} category
• {critical_issues_count} critical security issues identified requiring immediate attention
• {len([p for p in detailed_probes if p.score >= 0.8])} out of {len(detailed_probes)} security areas meet industry standards

Strategic Recommendations:
• Focus on addressing critical security vulnerabilities first
• Implement governance framework alignment for {governance_level.name} level
• Establish continuous monitoring and improvement processes
• Consider advancing to the next governance maturity level

This assessment follows international standards including NIST Cybersecurity Framework,
OWASP guidelines, and relevant Internet Engineering Task Force (IETF) RFCs.
        """.strip()

        return summary

    def _generate_technical_summary(self, detailed_probes: list[DetailedProbeResult]) -> str:
        """Generate technical summary of findings."""

        tls_probe = next((p for p in detailed_probes if p.probe_id == "tls"), None)
        dns_probe = next((p for p in detailed_probes if p.probe_id == "dns"), None)
        headers_probe = next((p for p in detailed_probes if p.probe_id == "headers"), None)

        summary = "Technical Assessment Summary\n\n"

        if tls_probe:
            tls_details = tls_probe.technical_details
            summary += f"""TLS/SSL Configuration:
• Protocol Version: {tls_details.get('protocol_version', 'Unknown')}
• Cipher Suite: {tls_details.get('cipher_suite', 'Unknown')}
• Certificate Authority: {tls_details.get('certificate_authority', 'Unknown')}
• HSTS Enabled: {'Yes' if tls_details.get('hsts_enabled') else 'No'}
• TLS 1.3 Support: {'Yes' if tls_details.get('supports_tls_13') else 'No'}

"""

        if dns_probe:
            dns_details = dns_probe.technical_details
            summary += f"""DNS Configuration:
• DNSSEC Enabled: {'Yes' if dns_details.get('dnssec_enabled') else 'No'}
• IPv6 Support: {'Yes' if dns_details.get('ipv6_support') else 'No'}
• CAA Records: {len(dns_details.get('caa_records', []))} configured
• Response Time: {dns_details.get('response_time_ms', 0)}ms
• DNS Servers: {len(dns_details.get('dns_servers', []))} configured

"""

        if headers_probe:
            headers_details = headers_probe.technical_details
            summary += f"""Security Headers:
• Security Headers Present: {len(headers_details.get('security_headers', {}))}
• Missing Headers: {len(headers_details.get('missing_headers', []))}
• CSP Policy: {'Configured' if headers_details.get('csp_policy') else 'Not configured'}
• HSTS Policy: {'Configured' if headers_details.get('hsts_policy') else 'Not configured'}
• X-Frame-Options: {headers_details.get('x_frame_options', 'Not set')}

"""

        return summary.strip()

    def _generate_compliance_summary(self, compliance_metrics: ComplianceMetrics) -> str:
        """Generate compliance summary."""

        summary = f"""Compliance Assessment Summary

Overall Compliance: {compliance_metrics.compliance_percentage:.1f}%
Governance Level: {compliance_metrics.governance_level}
WCAG Accessibility Level: {compliance_metrics.wcag_compliance_level}

Framework Compliance Scores:
• Web Standards Compliance: {compliance_metrics.web_standards_compliance:.1%}
• Security Framework Compliance: {compliance_metrics.security_framework_compliance:.1%}
• Internet Standards Compliance: {compliance_metrics.internet_standards_compliance:.1%}
• Privacy Compliance: {compliance_metrics.privacy_compliance:.1%}
• Governance Compliance: {compliance_metrics.governance_compliance:.1%}

Standards Alignment:
• NIST Framework Alignment: {compliance_metrics.nist_framework_alignment:.1%}
• RFC Standards Adherence: {compliance_metrics.rfc_standards_adherence:.1%}
• Multistakeholder Principles: {'Adopted' if compliance_metrics.multistakeholder_principles else 'Not adopted'}

Priority Areas for Improvement:
{chr(10).join('• ' + item for item in compliance_metrics.priority_improvements)}

Governance Recommendations:
{chr(10).join('• ' + item for item in compliance_metrics.governance_recommendations)}
        """.strip()

        return summary

    def _generate_immediate_actions(
        self,
        detailed_probes: list[DetailedProbeResult],
        overall_score: float
    ) -> list[str]:
        """Generate immediate action items."""
        actions = []

        # Collect all critical issues
        for probe in detailed_probes:
            actions.extend(probe.critical_issues)

        # Add score-based immediate actions
        if overall_score < 0.6:
            actions.extend([
                "Conduct comprehensive security audit",
                "Implement basic security measures immediately",
                "Establish security incident response plan"
            ])

        # Remove duplicates and limit to most critical
        unique_actions = list(dict.fromkeys(actions))
        return unique_actions[:10]  # Top 10 most critical

    def _generate_medium_term_improvements(
        self,
        compliance_metrics: ComplianceMetrics,
        governance_level: Any
    ) -> list[str]:
        """Generate medium-term improvement recommendations."""
        improvements = []

        if compliance_metrics.security_framework_compliance < 0.8:
            improvements.extend([
                "Implement comprehensive security framework (NIST/CIS)",
                "Establish security monitoring and alerting",
                "Conduct regular security assessments"
            ])

        if compliance_metrics.internet_standards_compliance < 0.8:
            improvements.extend([
                "Achieve full RFC standards compliance",
                "Implement email security standards (SPF/DMARC/DKIM)",
                "Enable IPv6 support across infrastructure"
            ])

        if governance_level.target_score > compliance_metrics.overall_score:
            improvements.extend([
                f"Work towards {governance_level.name} compliance level",
                "Establish governance processes and documentation",
                "Implement compliance monitoring and reporting"
            ])

        return improvements

    def _generate_long_term_strategy(
        self,
        overall_score: float,
        governance_level: Any
    ) -> list[str]:
        """Generate long-term strategic recommendations."""
        strategy = []

        if overall_score < 0.9:
            strategy.extend([
                "Develop comprehensive internet governance strategy",
                "Participate in industry standards development",
                "Establish center of excellence for internet security"
            ])

        strategy.extend([
            "Contribute to open source security projects",
            "Share best practices with industry community",
            "Mentor other organizations in internet governance",
            "Participate in multistakeholder internet governance forums",
            "Develop thought leadership in internet security"
        ])

        return strategy
