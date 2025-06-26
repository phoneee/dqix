"""
DQIX Domain Entities - Enhanced for Comprehensive Internet Observability
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any


class ProbeCategory(Enum):
    """Categories of domain quality checks."""
    SECURITY = "security"
    PERFORMANCE = "performance"
    ACCESSIBILITY = "accessibility"
    COMPLIANCE = "compliance"


class ComplianceLevel(Enum):
    """Domain compliance levels."""
    BASIC = "basic"
    STANDARD = "standard"
    ADVANCED = "advanced"


@dataclass(frozen=True)
class Domain:
    """A domain to be assessed."""
    name: str

    @property
    def clean_name(self) -> str:
        """Get domain name without trailing dot."""
        return self.name.rstrip('.')

    def is_valid(self) -> bool:
        """Check if domain format is valid."""
        import re
        if not 1 <= len(self.name) <= 253:
            return False
        return bool(re.match(r'^[a-zA-Z0-9.-]+$', self.name))


@dataclass
class ProbeResult:
    """Result of a single probe check."""
    probe_id: str
    domain: str
    score: float  # 0.0 to 1.0
    category: ProbeCategory
    details: dict[str, Any]
    error: str | None = None

    @property
    def is_successful(self) -> bool:
        """Check if probe completed successfully."""
        return self.error is None


@dataclass
class AssessmentResult:
    """Complete domain quality assessment."""
    domain: Domain
    overall_score: float
    probe_results: list[ProbeResult]
    compliance_level: ComplianceLevel
    timestamp: str

    @property
    def successful_probes(self) -> list[ProbeResult]:
        """Get only successful probe results."""
        return [r for r in self.probe_results if r.is_successful]

    @property
    def failed_probes(self) -> list[ProbeResult]:
        """Get only failed probe results."""
        return [r for r in self.probe_results if not r.is_successful]


@dataclass
class ProbeConfig:
    """Configuration for probe execution."""
    timeout: int = 30
    retry_count: int = 3
    cache_enabled: bool = True
    max_concurrent: int = 10


@dataclass(frozen=True)
class GovernanceReference:
    """Reference to internet governance standards and frameworks."""
    title: str
    organization: str
    url: str
    version: str
    category: str
    description: str
    compliance_level: str
    implementation_notes: list[str] = field(default_factory=list)


class GovernanceFramework(Enum):
    """Internet governance and compliance frameworks."""
    # Web Standards
    WCAG_2_2 = "wcag-2.2"
    WCAG_2_1 = "wcag-2.1"

    # Security Frameworks
    NIST_CYBERSECURITY_FRAMEWORK = "nist-csf"
    CIS_CONTROLS_V8 = "cis-controls-v8"

    # Internet Standards (RFCs)
    RFC_6797_HSTS = "rfc-6797-hsts"
    RFC_4034_DNSSEC = "rfc-4034-dnssec"
    RFC_7489_DMARC = "rfc-7489-dmarc"
    RFC_6844_CAA = "rfc-6844-caa"
    RFC_8446_TLS13 = "rfc-8446-tls13"

    # Privacy Standards
    GDPR_COMPLIANCE = "gdpr-compliance"
    PRIVACY_POLICY = "privacy-policy"

    # Internet Governance
    MULTISTAKEHOLDER_APPROACH = "multistakeholder"
    IGF_BEST_PRACTICES = "igf-practices"
    NETMUNDIAL_PRINCIPLES = "netmundial"


@dataclass(frozen=True)
class InternetGovernanceLevels:
    """Internet governance compliance levels with detailed requirements."""
    name: str
    target_score: float
    description: str
    focus_areas: list[str]
    requirements: list[str] = field(default_factory=list)
    governance_frameworks: list[GovernanceFramework] = field(default_factory=list)


# Define governance levels
BASIC = InternetGovernanceLevels(
    name="Basic Infrastructure",
    target_score=0.6,
    description="Essential security and connectivity requirements",
    focus_areas=[
        "Transport security (TLS/SSL)",
        "Basic DNS functionality",
        "HTTP security headers",
        "Domain ownership verification"
    ],
    requirements=[
        "Valid TLS certificate",
        "HTTPS redirect implementation",
        "Basic security headers (HSTS, X-Frame-Options)",
        "DNS resolution working"
    ],
    governance_frameworks=[
        GovernanceFramework.RFC_6797_HSTS,
        GovernanceFramework.RFC_8446_TLS13
    ]
)

STANDARD = InternetGovernanceLevels(
    name="Standard Compliance",
    target_score=0.8,
    description="Industry standard compliance and best practices",
    focus_areas=[
        "Advanced security headers",
        "Email security (SPF/DMARC)",
        "DNS security (DNSSEC)",
        "Content Security Policy"
    ],
    requirements=[
        "All Basic requirements met",
        "CSP implementation",
        "SPF/DMARC email security",
        "DNSSEC validation",
        "Security header completeness"
    ],
    governance_frameworks=[
        GovernanceFramework.NIST_CYBERSECURITY_FRAMEWORK,
        GovernanceFramework.RFC_4034_DNSSEC,
        GovernanceFramework.RFC_7489_DMARC
    ]
)

ADVANCED = InternetGovernanceLevels(
    name="Best Practice Implementation",
    target_score=0.9,
    description="Advanced security and governance implementation",
    focus_areas=[
        "Certificate Authority Authorization",
        "Advanced threat protection",
        "Privacy compliance",
        "Accessibility standards"
    ],
    requirements=[
        "All Standard requirements met",
        "CAA records implemented",
        "Privacy policy compliance",
        "Accessibility guidelines (WCAG)",
        "Advanced security monitoring"
    ],
    governance_frameworks=[
        GovernanceFramework.RFC_6844_CAA,
        GovernanceFramework.WCAG_2_2,
        GovernanceFramework.GDPR_COMPLIANCE
    ]
)

EXCELLENT = InternetGovernanceLevels(
    name="Excellence in Internet Governance",
    target_score=0.95,
    description="Exemplary implementation of internet governance principles",
    focus_areas=[
        "Multistakeholder governance",
        "Transparency and accountability",
        "Innovation and openness",
        "Global internet governance participation"
    ],
    requirements=[
        "All Advanced requirements met",
        "Transparency reporting",
        "Community engagement",
        "Open source contributions",
        "Internet governance participation"
    ],
    governance_frameworks=[
        GovernanceFramework.MULTISTAKEHOLDER_APPROACH,
        GovernanceFramework.IGF_BEST_PRACTICES,
        GovernanceFramework.NETMUNDIAL_PRINCIPLES
    ]
)

@dataclass(frozen=True)
class ComplianceMetrics:
    """Detailed compliance metrics for governance assessment."""
    overall_score: float
    governance_level: str
    compliance_percentage: float

    # Framework-specific compliance
    web_standards_compliance: float
    security_framework_compliance: float
    internet_standards_compliance: float
    privacy_compliance: float
    governance_compliance: float

    # Detailed breakdown
    wcag_compliance_level: str
    nist_framework_alignment: float
    rfc_standards_adherence: float
    multistakeholder_principles: bool

    # Recommendations
    priority_improvements: list[str] = field(default_factory=list)
    governance_recommendations: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class DetailedProbeResult:
    """Enhanced probe result with comprehensive details."""
    probe_id: str
    domain: str
    status: str
    score: float
    message: str

    # Detailed technical information
    technical_details: dict[str, Any] = field(default_factory=dict)
    compliance_details: dict[str, Any] = field(default_factory=dict)
    governance_alignment: dict[GovernanceFramework, bool] = field(default_factory=dict)

    # Recommendations and improvements
    recommendations: list[str] = field(default_factory=list)
    critical_issues: list[str] = field(default_factory=list)
    best_practices: list[str] = field(default_factory=list)

    # Metadata
    timestamp: datetime = field(default_factory=datetime.now)
    probe_version: str = "2.0.0"


@dataclass(frozen=True)
class ComprehensiveAssessmentResult:
    """Comprehensive assessment result with full governance analysis."""
    domain: str
    overall_score: float
    compliance_level: str

    # Detailed probe results
    probe_results: list[DetailedProbeResult] = field(default_factory=list)

    # Governance analysis
    compliance_metrics: ComplianceMetrics | None = None
    governance_frameworks: dict[GovernanceFramework, GovernanceReference] = field(default_factory=dict)

    # Detailed reporting
    executive_summary: str = ""
    technical_summary: str = ""
    compliance_summary: str = ""

    # Recommendations
    immediate_actions: list[str] = field(default_factory=list)
    medium_term_improvements: list[str] = field(default_factory=list)
    long_term_strategy: list[str] = field(default_factory=list)

    # Metadata
    assessment_timestamp: datetime = field(default_factory=datetime.now)
    assessment_version: str = "2.0.0"
    report_template: str = "comprehensive"
