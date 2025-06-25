"""Domain Services - Core business logic."""

from abc import ABC, abstractmethod
from typing import List, Protocol

from .entities import AssessmentResult, ComplianceLevel, Domain, ProbeResult


class ScoringService:
    """Service for calculating domain quality scores."""
    
    def calculate_overall_score(self, probe_results: List[ProbeResult]) -> float:
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
        probe_results: List[ProbeResult],
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