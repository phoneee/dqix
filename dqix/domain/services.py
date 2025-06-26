"""
DQIX Domain Services - Enhanced with Comprehensive Internet Governance
"""

from typing import Any

from .entities import (
    ADVANCED,
    BASIC,
    EXCELLENT,
    STANDARD,
    AssessmentResult,
    ComplianceLevel,
    ComplianceMetrics,
    Domain,
    GovernanceFramework,
    GovernanceReference,
    InternetGovernanceLevels,
    ProbeResult,
)


class ScoringService:
    """Service for calculating domain quality scores."""

    def calculate_overall_score(self, probe_results: list[ProbeResult]) -> float:
        """Calculate weighted overall score from probe results."""
        if not probe_results:
            return 0.0

        successful_results = [r for r in probe_results if r.is_successful]
        if not successful_results:
            return 0.0

        total_score = sum(result.score for result in successful_results)
        return total_score / len(successful_results)

    def determine_compliance_level(self, overall_score: float) -> ComplianceLevel:
        """Determine compliance level based on overall score."""
        if overall_score >= 0.9:
            return ComplianceLevel.ADVANCED
        elif overall_score >= 0.7:
            return ComplianceLevel.STANDARD
        else:
            return ComplianceLevel.BASIC


class DomainValidationService:
    """Service for domain validation."""

    def validate_domain(self, domain: Domain) -> bool:
        """Validate domain format and constraints."""
        return domain.is_valid()

    def sanitize_domain_name(self, raw_domain: str) -> str:
        """Clean and sanitize domain name."""
        domain = raw_domain.strip().lower()
        # Remove protocol if present
        if domain.startswith(('http://', 'https://')):
            domain = domain.split('//', 1)[1]
        # Remove path if present
        if '/' in domain:
            domain = domain.split('/', 1)[0]
        return domain


class AssessmentService:
    """Service for creating domain assessments."""

    def __init__(
        self,
        scoring_service: ScoringService,
        validation_service: DomainValidationService
    ):
        self.scoring_service = scoring_service
        self.validation_service = validation_service

    def create_assessment(
        self,
        domain: Domain,
        probe_results: list[ProbeResult],
        timestamp: str
    ) -> AssessmentResult:
        """Create complete assessment from probe results."""
        overall_score = self.scoring_service.calculate_overall_score(probe_results)
        compliance_level = self.scoring_service.determine_compliance_level(overall_score)

        return AssessmentResult(
            domain=domain,
            overall_score=overall_score,
            probe_results=probe_results,
            compliance_level=compliance_level,
            timestamp=timestamp
        )


class DomainQualityGovernance:
    """Service for internet governance framework management and compliance assessment."""

    @staticmethod
    def get_governance_references() -> dict[GovernanceFramework, GovernanceReference]:
        """Get comprehensive governance framework references."""
        return {
            # Web Standards
            GovernanceFramework.WCAG_2_2: GovernanceReference(
                title="Web Content Accessibility Guidelines (WCAG) 2.2",
                organization="World Wide Web Consortium (W3C)",
                url="https://www.w3.org/WAI/WCAG22/",
                version="2.2",
                category="web_standards",
                description="International standard for web accessibility, ensuring content is perceivable, operable, understandable, and robust for all users including those with disabilities.",
                compliance_level="AA",
                implementation_notes=[
                    "Implement semantic HTML structure",
                    "Provide alternative text for images",
                    "Ensure keyboard navigation support",
                    "Maintain sufficient color contrast ratios"
                ]
            ),

            GovernanceFramework.WCAG_2_1: GovernanceReference(
                title="Web Content Accessibility Guidelines (WCAG) 2.1",
                organization="World Wide Web Consortium (W3C)",
                url="https://www.w3.org/WAI/WCAG21/",
                version="2.1",
                category="web_standards",
                description="Previous version of WCAG with fundamental accessibility principles.",
                compliance_level="AA",
                implementation_notes=[
                    "Foundation for WCAG 2.2 compliance",
                    "Focus on mobile accessibility improvements"
                ]
            ),

            # Security Frameworks
            GovernanceFramework.NIST_CYBERSECURITY_FRAMEWORK: GovernanceReference(
                title="NIST Cybersecurity Framework",
                organization="National Institute of Standards and Technology (NIST)",
                url="https://www.nist.gov/cyberframework",
                version="1.1",
                category="security",
                description="Comprehensive framework for managing cybersecurity risk through Identify, Protect, Detect, Respond, and Recover functions.",
                compliance_level="Core",
                implementation_notes=[
                    "Identify assets and vulnerabilities",
                    "Implement protective measures",
                    "Deploy detection capabilities",
                    "Establish response procedures",
                    "Plan recovery strategies"
                ]
            ),

            GovernanceFramework.CIS_CONTROLS_V8: GovernanceReference(
                title="CIS Controls Version 8",
                organization="Center for Internet Security (CIS)",
                url="https://www.cisecurity.org/controls/",
                version="8.0",
                category="security",
                description="Prioritized set of actions for cyber defense that provide specific ways to stop today's most pervasive and dangerous attacks.",
                compliance_level="Implementation Group 1",
                implementation_notes=[
                    "Inventory and control of enterprise assets",
                    "Secure configuration of enterprise assets",
                    "Data protection and access control"
                ]
            ),

            # Internet Standards (RFCs)
            GovernanceFramework.RFC_6797_HSTS: GovernanceReference(
                title="HTTP Strict Transport Security (HSTS)",
                organization="Internet Engineering Task Force (IETF)",
                url="https://tools.ietf.org/html/rfc6797",
                version="RFC 6797",
                category="internet_standards",
                description="Security policy mechanism that helps protect websites against man-in-the-middle attacks such as protocol downgrade attacks and cookie hijacking.",
                compliance_level="MUST",
                implementation_notes=[
                    "Set Strict-Transport-Security header",
                    "Include subdomains in policy",
                    "Consider HSTS preload list inclusion"
                ]
            ),

            GovernanceFramework.RFC_4034_DNSSEC: GovernanceReference(
                title="DNS Security Extensions (DNSSEC)",
                organization="Internet Engineering Task Force (IETF)",
                url="https://tools.ietf.org/html/rfc4034",
                version="RFC 4034",
                category="internet_standards",
                description="Suite of IETF specifications for securing DNS information provided by the Domain Name System.",
                compliance_level="RECOMMENDED",
                implementation_notes=[
                    "Enable DNSSEC signing for zone",
                    "Publish DS records in parent zone",
                    "Monitor DNSSEC validation"
                ]
            ),

            GovernanceFramework.RFC_7489_DMARC: GovernanceReference(
                title="Domain-based Message Authentication, Reporting, and Conformance (DMARC)",
                organization="Internet Engineering Task Force (IETF)",
                url="https://tools.ietf.org/html/rfc7489",
                version="RFC 7489",
                category="internet_standards",
                description="Email authentication protocol that uses SPF and DKIM to determine the authenticity of email messages.",
                compliance_level="RECOMMENDED",
                implementation_notes=[
                    "Implement SPF and DKIM first",
                    "Start with p=none policy",
                    "Monitor aggregate reports",
                    "Gradually enforce with p=quarantine or p=reject"
                ]
            ),

            GovernanceFramework.RFC_6844_CAA: GovernanceReference(
                title="DNS Certification Authority Authorization (CAA) Resource Record",
                organization="Internet Engineering Task Force (IETF)",
                url="https://tools.ietf.org/html/rfc6844",
                version="RFC 6844",
                category="internet_standards",
                description="DNS resource record type that allows domain owners to specify which certificate authorities are allowed to issue certificates for their domain.",
                compliance_level="RECOMMENDED",
                implementation_notes=[
                    "Publish CAA records for domain",
                    "Specify authorized certificate authorities",
                    "Include iodef property for incident reporting"
                ]
            ),

            GovernanceFramework.RFC_8446_TLS13: GovernanceReference(
                title="The Transport Layer Security (TLS) Protocol Version 1.3",
                organization="Internet Engineering Task Force (IETF)",
                url="https://tools.ietf.org/html/rfc8446",
                version="RFC 8446",
                category="internet_standards",
                description="Latest version of TLS providing improved security and performance over previous versions.",
                compliance_level="RECOMMENDED",
                implementation_notes=[
                    "Enable TLS 1.3 support",
                    "Disable older TLS versions",
                    "Use strong cipher suites",
                    "Implement proper certificate validation"
                ]
            ),

            # Privacy Standards
            GovernanceFramework.GDPR_COMPLIANCE: GovernanceReference(
                title="General Data Protection Regulation (GDPR)",
                organization="European Union",
                url="https://gdpr-info.eu/",
                version="2018/679",
                category="privacy",
                description="Comprehensive data protection regulation that governs how personal data is collected, processed, and stored.",
                compliance_level="MANDATORY",
                implementation_notes=[
                    "Implement privacy by design",
                    "Provide clear privacy notices",
                    "Enable data subject rights",
                    "Conduct data protection impact assessments"
                ]
            ),

            GovernanceFramework.PRIVACY_POLICY: GovernanceReference(
                title="Privacy Policy Best Practices",
                organization="Various Standards Bodies",
                url="https://www.privacypolicies.com/blog/privacy-policy-best-practices/",
                version="2024",
                category="privacy",
                description="Best practices for creating comprehensive and compliant privacy policies.",
                compliance_level="RECOMMENDED",
                implementation_notes=[
                    "Use clear, plain language",
                    "Specify data collection practices",
                    "Explain data usage and sharing",
                    "Provide contact information"
                ]
            ),

            # Internet Governance
            GovernanceFramework.MULTISTAKEHOLDER_APPROACH: GovernanceReference(
                title="Multistakeholder Approach to Internet Governance",
                organization="Harvard Berkman Klein Center for Internet & Society",
                url="https://cyber.harvard.edu/research/internetgovernance",
                version="2024",
                category="governance",
                description="Collaborative governance model involving governments, private sector, civil society, and technical community in internet policy decisions.",
                compliance_level="PRINCIPLE",
                implementation_notes=[
                    "Engage diverse stakeholders",
                    "Ensure transparent processes",
                    "Build consensus-based decisions",
                    "Maintain accountability mechanisms"
                ]
            ),

            GovernanceFramework.IGF_BEST_PRACTICES: GovernanceReference(
                title="Internet Governance Forum (IGF) Best Practices",
                organization="Internet Society (ISOC)",
                url="https://www.internetsociety.org/issues/internet-governance/",
                version="2024",
                category="governance",
                description="Best practices for internet governance derived from global Internet Governance Forum discussions and outcomes.",
                compliance_level="GUIDELINE",
                implementation_notes=[
                    "Promote open internet principles",
                    "Support capacity building",
                    "Foster international cooperation",
                    "Encourage innovation and access"
                ]
            ),

            GovernanceFramework.NETMUNDIAL_PRINCIPLES: GovernanceReference(
                title="NETmundial Multistakeholder Statement",
                organization="NETmundial Initiative",
                url="https://netmundial.br/netmundial-multistakeholder-statement/",
                version="2014",
                category="governance",
                description="Global consensus on internet governance principles emphasizing human rights, open standards, and distributed governance.",
                compliance_level="PRINCIPLE",
                implementation_notes=[
                    "Respect human rights online",
                    "Promote open standards",
                    "Ensure security and stability",
                    "Enable innovation and economic growth"
                ]
            )
        }

    @staticmethod
    def get_references_by_category(category: str) -> dict[GovernanceFramework, GovernanceReference]:
        """Get governance references filtered by category."""
        all_references = DomainQualityGovernance.get_governance_references()
        return {
            framework: reference
            for framework, reference in all_references.items()
            if reference.category == category
        }

    @staticmethod
    def get_governance_level(score: float) -> InternetGovernanceLevels:
        """Determine governance level based on score."""
        if score >= EXCELLENT.target_score:
            return EXCELLENT
        elif score >= ADVANCED.target_score:
            return ADVANCED
        elif score >= STANDARD.target_score:
            return STANDARD
        else:
            return BASIC

def generate_governance_report(
    domain: str,
    score: float,
    probe_results: dict[str, float],
    target_level: InternetGovernanceLevels
) -> dict[str, Any]:
    """Generate comprehensive governance compliance report."""

    # Determine compliance status
    if score >= 0.9:
        status = "EXCELLENT"
    elif score >= 0.8:
        status = "GOOD"
    elif score >= 0.7:
        status = "FAIR"
    else:
        status = "NEEDS_IMPROVEMENT"

    # Calculate governance compliance metrics
    governance_compliance = {
        "multistakeholder_principles": score >= 0.7,
        "internet_standards_compliance": score >= 0.8,
        "best_practices_implementation": score >= 0.9,
        "transparency_and_accountability": score >= 0.85,
        "security_and_stability": probe_results.get("tls", 0) >= 0.8,
        "accessibility_compliance": score >= 0.75
    }

    return {
        "domain": domain,
        "overall_score": score,
        "status": status,
        "framework": "internet governance principles",
        "governance_compliance": governance_compliance,
        "target_level": target_level.name,
        "recommendations": _generate_governance_recommendations(score, probe_results, target_level),
        "compliance_gap_analysis": _analyze_compliance_gaps(score, target_level),
        "next_steps": _generate_next_steps(score, target_level)
    }

def calculate_compliance_metrics(
    overall_score: float,
    probe_results: dict[str, float],
    governance_level: str
) -> ComplianceMetrics:
    """Calculate detailed compliance metrics."""

    # Framework-specific compliance calculations
    web_standards_compliance = min(1.0, (probe_results.get("accessibility", 0.7) + 0.3))
    security_framework_compliance = (
        probe_results.get("tls", 0) * 0.4 +
        probe_results.get("headers", 0) * 0.3 +
        probe_results.get("dns", 0) * 0.3
    )
    internet_standards_compliance = (
        probe_results.get("dns", 0) * 0.5 +
        probe_results.get("email", 0.7) * 0.3 +
        probe_results.get("tls", 0) * 0.2
    )
    privacy_compliance = min(1.0, overall_score * 0.8 + 0.2)
    governance_compliance = overall_score

    # Determine WCAG compliance level
    accessibility_score = probe_results.get("accessibility", 0.7)
    if accessibility_score >= 0.9:
        wcag_level = "AAA"
    elif accessibility_score >= 0.8:
        wcag_level = "AA"
    elif accessibility_score >= 0.6:
        wcag_level = "A"
    else:
        wcag_level = "Non-compliant"

    # Generate recommendations
    priority_improvements = []
    governance_recommendations = []

    if security_framework_compliance < 0.8:
        priority_improvements.append("Implement comprehensive security headers")
        priority_improvements.append("Upgrade TLS configuration")

    if internet_standards_compliance < 0.8:
        priority_improvements.append("Enable DNSSEC validation")
        priority_improvements.append("Implement email security (SPF/DMARC)")

    if overall_score < 0.9:
        governance_recommendations.append("Adopt multistakeholder governance principles")
        governance_recommendations.append("Participate in internet governance forums")

    return ComplianceMetrics(
        overall_score=overall_score,
        governance_level=governance_level,
        compliance_percentage=overall_score * 100,
        web_standards_compliance=web_standards_compliance,
        security_framework_compliance=security_framework_compliance,
        internet_standards_compliance=internet_standards_compliance,
        privacy_compliance=privacy_compliance,
        governance_compliance=governance_compliance,
        wcag_compliance_level=wcag_level,
        nist_framework_alignment=security_framework_compliance,
        rfc_standards_adherence=internet_standards_compliance,
        multistakeholder_principles=overall_score >= 0.7,
        priority_improvements=priority_improvements,
        governance_recommendations=governance_recommendations
    )

def _generate_governance_recommendations(
    score: float,
    probe_results: dict[str, float],
    target_level: InternetGovernanceLevels
) -> list[str]:
    """Generate governance-specific recommendations."""
    recommendations = []

    if score < target_level.target_score:
        recommendations.append(f"Improve overall score to reach {target_level.name} level")

    if probe_results.get("tls", 0) < 0.8:
        recommendations.append("Upgrade TLS configuration to meet security standards")

    if probe_results.get("dns", 0) < 0.8:
        recommendations.append("Implement DNSSEC for DNS security")

    if score < 0.9:
        recommendations.append("Adopt internet governance best practices")
        recommendations.append("Engage in multistakeholder processes")

    return recommendations

def _analyze_compliance_gaps(score: float, target_level: InternetGovernanceLevels) -> dict[str, Any]:
    """Analyze gaps between current and target compliance levels."""
    gap = target_level.target_score - score

    return {
        "current_score": score,
        "target_score": target_level.target_score,
        "compliance_gap": max(0, gap),
        "gap_percentage": max(0, gap * 100),
        "areas_for_improvement": target_level.focus_areas,
        "missing_requirements": target_level.requirements if gap > 0 else []
    }

def _generate_next_steps(score: float, target_level: InternetGovernanceLevels) -> list[str]:
    """Generate actionable next steps for compliance improvement."""
    next_steps = []

    if score < 0.6:
        next_steps.extend([
            "Implement basic security measures (TLS, HTTPS)",
            "Configure essential security headers",
            "Ensure DNS functionality and security"
        ])
    elif score < 0.8:
        next_steps.extend([
            "Implement advanced security headers",
            "Enable email security (SPF/DMARC)",
            "Deploy DNSSEC validation"
        ])
    elif score < 0.9:
        next_steps.extend([
            "Implement CAA records",
            "Ensure privacy policy compliance",
            "Meet accessibility guidelines (WCAG)"
        ])
    else:
        next_steps.extend([
            "Participate in internet governance initiatives",
            "Contribute to open source projects",
            "Share best practices with community"
        ])

    return next_steps
